use std::{fs::read, path::PathBuf};

use elf::{endian::AnyEndian, ElfBytes};
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

    pub fn sha256_hash(&self) -> &str {
        return &self.sha256_hash;
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

    pub fn analyze_static(&mut self) {
        let filepath = &self.analyzing_filepath;

        info!("Analyzing statically: \"{}\"...", filepath.display());

        match self.file_format {
            FileFormat::ExecutableAndLinkableFormat => (),
            _ => unimplemented!("Support ELF file only"),
        }

        // analyze ELF file
        let byte_slice = self.file_bytes.as_slice();
        let elf = match ElfBytes::<AnyEndian>::minimal_parse(byte_slice) {
            Ok(elf) => elf,
            Err(_) => {
                warn!("Failed to parse ELF file");
                return;
            }
        };

        self.analyzed_level = AnalyzedLevel::Static;
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
