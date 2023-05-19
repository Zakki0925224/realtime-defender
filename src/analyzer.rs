use std::{fs::read, path::PathBuf};

use file_format::FileFormat;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnalyzedLevel {
    None,
    Heuristic,
    Static,
}

pub struct Analyzer {
    analyzed_level: AnalyzedLevel,
    analyzing_filepath: PathBuf,
    file_format: FileFormat,
    sha256_hash: String,
}

impl Analyzer {
    pub fn new() -> Self {
        return Self {
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

        let bytes = read(filepath).unwrap();
        let byte_slice = bytes.as_slice();
        self.sha256_hash = sha256::digest(byte_slice);

        self.analyzed_level = AnalyzedLevel::Heuristic;
    }

    pub fn analyze_static(&mut self) {
        let filepath = &self.analyzing_filepath;

        info!("Analyzing statically: \"{}\"...", filepath.display());

        self.analyzed_level = AnalyzedLevel::Static;
    }
}
