use std::{fs::read, path::PathBuf};

use elf::{endian::AnyEndian, ElfBytes};
use file_format::FileFormat;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnalyzedLevel {
    None,
    Heuristic,
    Static,
}

pub struct Analyzer {
    file_bytes: Vec<u8>,
    analyzed_level: AnalyzedLevel,
    analyzing_filepath: PathBuf,
    file_format: FileFormat,
    sha256_hash: String,
}

impl Analyzer {
    pub fn new() -> Self {
        return Self {
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

    pub fn analyze_heuristic(&mut self) {
        let filepath = &self.analyzing_filepath;

        info!("Analyzing heuristically: \"{}\"...", filepath.display());

        self.file_format = match FileFormat::from_file(filepath) {
            Ok(f) => f,
            Err(err) => {
                warn!("{}", err);
                return;
            }
        };

        self.file_bytes = read(&self.analyzing_filepath).expect("Failed to read file");
        let byte_slice = self.file_bytes.as_slice();
        self.sha256_hash = sha256::digest(byte_slice);

        self.analyzed_level = AnalyzedLevel::Heuristic;
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
}
