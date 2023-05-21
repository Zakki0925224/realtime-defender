use std::{fs::read, path::PathBuf};

use elf::{endian::LittleEndian, ElfBytes};
use file_format::FileFormat;
use regex::Regex;

use crate::definitions::Definition;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnalyzedLevel {
    None,
    Heuristic,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiskType {
    None,
    DangerHash(Definition),
    IncludeSuspiciousStrings(Vec<String>),
    HasVulnerableScanf,
}

pub struct Analyzer {
    sha256_definitions: Vec<Definition>,
    file_bytes: Vec<u8>,
    analyzed_level: AnalyzedLevel,
    analyzing_filepath: PathBuf,
    file_format: FileFormat,
    sha256_hash: String,
}

impl Analyzer {
    pub fn new(sha256_definitions: Vec<Definition>) -> Self {
        return Self {
            sha256_definitions,
            file_bytes: Vec::new(),
            analyzed_level: AnalyzedLevel::None,
            analyzing_filepath: PathBuf::new(),
            file_format: FileFormat::default(),
            sha256_hash: String::new(),
        };
    }

    pub fn analyzed_level(&self) -> AnalyzedLevel {
        return self.analyzed_level;
    }

    pub fn set_analyzing_filepath(&mut self, filepath: PathBuf) {
        self.analyzing_filepath = filepath;
        self.analyzed_level = AnalyzedLevel::None;
    }

    pub fn analyzing_filepath(&self) -> &PathBuf {
        return &self.analyzing_filepath;
    }

    pub fn file_format(&self) -> &FileFormat {
        return &self.file_format;
    }

    pub fn analyze_heuristic(&mut self) -> Result<LiskType, ()> {
        let filepath = &self.analyzing_filepath;

        info!("Analyzing heuristically: \"{}\"...", filepath.display());

        self.file_format = match FileFormat::from_file(filepath) {
            Ok(f) => f,
            Err(_) => return Err(()),
        };

        self.file_bytes = read(&self.analyzing_filepath).expect("Failed to read file");
        let byte_slice = self.file_bytes.as_slice();
        self.sha256_hash = sha256::digest(byte_slice);

        self.analyzed_level = AnalyzedLevel::Heuristic;
        let mut result = LiskType::None;

        // compare hash with definition
        if let Some(def) = self
            .sha256_definitions
            .iter()
            .find(|p| p.hash == self.sha256_hash)
        {
            result = LiskType::DangerHash(def.clone());
            return Ok(result);
        }

        // check suspicious strings (support URL or IP address only)
        let strings = self.get_readable_strings();
        let mut suspicious_strings = Vec::new();

        let url_pattern =
            Regex::new(r"^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$").unwrap();
        let ip_pattern = Regex::new(r"^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$").unwrap();

        for s in strings {
            if url_pattern.is_match(&s) || ip_pattern.is_match(&s) {
                suspicious_strings.push(s);
            }
        }

        if suspicious_strings.len() > 0 {
            result = LiskType::IncludeSuspiciousStrings(suspicious_strings);
        }

        return Ok(result);
    }

    pub fn analyze_static(&mut self) -> Result<LiskType, ()> {
        let filepath = &self.analyzing_filepath;

        info!("Analyzing statically: \"{}\"...", filepath.display());

        match self.file_format {
            FileFormat::ExecutableAndLinkableFormat => (),
            _ => unimplemented!("Support ELF file only"),
        }

        let mut result = LiskType::None;

        // analyze ELF file
        let byte_slice = self.file_bytes.as_slice();
        let elf = match ElfBytes::<LittleEndian>::minimal_parse(byte_slice) {
            Ok(elf) => elf,
            Err(_) => {
                warn!("Failed to parse ELF file");
                return Err(());
            }
        };

        let text_shdr = match elf.section_header_by_name(".text").unwrap() {
            Some(shdr) => shdr,
            None => return Ok(result),
        };
        let text_shdr_offset = text_shdr.sh_offset;
        let text_shdr_addr = text_shdr.sh_addr;

        // find __isoc99_scanf symbol
        let (symtab, strtab) = elf.symbol_table().unwrap().unwrap();
        let scanf_sym = match symtab.iter().find(|s| {
            let sym_name = match strtab.get(s.st_name as usize) {
                Ok(name) => name,
                Err(_) => return false,
            };

            return sym_name == "__isoc99_scanf";
        }) {
            Some(s) => s,
            _ => return Ok(result),
        };
        let scanf_addr = scanf_sym.st_value;

        // find main symbol
        let main_sym = match symtab.iter().find(|s| {
            let sym_name = match strtab.get(s.st_name as usize) {
                Ok(name) => name,
                Err(_) => return false,
            };

            return sym_name == "main";
        }) {
            Some(s) => s,
            _ => return Ok(result),
        };
        let start_main_addr = main_sym.st_value;
        let main_size = main_sym.st_size;

        let read_offset = start_main_addr - text_shdr_addr + text_shdr_offset;

        // read binary
        for i in read_offset..read_offset + main_size {
            let b = self.file_bytes[i as usize];
            let b_slice = &self.file_bytes[i as usize + 1..i as usize + 5];

            if b != 0xe8 {
                continue;
            }

            let offset_addr = u32::from_le_bytes(b_slice.try_into().unwrap()) as u64;

            // found scanf caller
            if scanf_addr == start_main_addr + 5 + offset_addr + i - read_offset {
                let mut j = i - 7;

                while j >= read_offset {
                    // find lea instrcution
                    // ex) 4016c3:  48 8d 05 3a c9 08 00    lea    0x8c93a(%rip),%rax
                    let b_slice = &self.file_bytes[j as usize..j as usize + 7];
                    j -= 1;

                    // 64bit prefix
                    if b_slice[0] != 0x48 {
                        continue;
                    }

                    // lea opcode
                    if b_slice[1] != 0x8d {
                        continue;
                    }

                    // address is offset
                    if b_slice[2] != 0x05 {
                        continue;
                    }

                    // offset addr
                    let format_arg_offset =
                        u32::from_le_bytes(b_slice[3..7].try_into().unwrap()) as u64;
                    let target_str_offset = format_arg_offset + 8 + j;

                    let target_str = &self.file_bytes
                        [target_str_offset as usize..target_str_offset as usize + 3];

                    // found "%s"
                    if target_str[0] == '%' as u8
                        && target_str[1] == 's' as u8
                        && target_str[2] == 0
                    {
                        result = LiskType::HasVulnerableScanf;
                        break;
                    }
                }
            }
        }

        // read main function
        self.analyzed_level = AnalyzedLevel::Static;

        return Ok(result);
    }

    fn get_readable_strings(&self) -> Vec<String> {
        let mut strings: Vec<String> = self
            .file_bytes
            .split(|x| *x == 0)
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect();

        // remove empty strings
        strings.retain(|x| !x.is_empty());

        // remove strings of 3 chars or less
        strings.retain(|x| x.len() > 3);

        return strings;
    }
}
