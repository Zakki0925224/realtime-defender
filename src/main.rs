#[macro_use]
extern crate log;
extern crate env_logger;

mod analyzer;
mod definitions;

use file_format::FileFormat;
use inotify::{EventMask, Inotify, WatchMask};
use serde::__private::de;
use std::{
    env,
    fs::remove_file,
    path::{Path, PathBuf},
    process::exit,
};

use crate::{
    analyzer::{AnalyzedLevel, Analyzer},
    definitions::Definitions,
};

fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Invalid arguments");
        exit(1);
    }

    // initialize inotify
    let mut inotify = Inotify::init().expect("Failed to initialize inotify");
    let dir = PathBuf::from(&args[1]);

    inotify
        .add_watch(
            dir,
            WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MODIFY
                | WatchMask::MOVED_TO
                | WatchMask::ATTRIB,
        )
        .expect("Failed to add watch");

    // parse sha256 definitions
    let json = include_str!("../sha256_definitions.json");
    let definitions: Definitions = serde_json::from_str(json).unwrap();
    let definitions = definitions.definitions;
    println!("Loaded {} definitions", definitions.len());

    // initialize analyzer
    let mut analyzer = Analyzer::new();

    // start watching
    println!("Watching at \"{}\"...", args[1]);

    let mut buffer = [0; 4096];

    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("Failed to read events");

        for event in events {
            info!("{:?}", event);

            if let None = event.name {
                continue;
            }

            let filepath = Path::new(&args[1]).join(event.name.unwrap().to_str().unwrap());
            analyzer.set_analyzing_filepath(filepath);

            if event.mask.contains(EventMask::MODIFY) || event.mask.contains(EventMask::MOVED_TO) {
                analyzer.analyze_heuristic();
            }

            if analyzer.analyzed_level() == AnalyzedLevel::Heuristic {
                // remove this file
                if let Some(def) = definitions
                    .iter()
                    .find(|def| def.hash == analyzer.sha256_hash())
                {
                    warn!(
                        "Detected malware file \"{}\" is \"{}\",  removing...",
                        analyzer.analyzing_filepath().display(),
                        &def.title
                    );

                    match remove_file(analyzer.analyzing_filepath()) {
                        Ok(_) => info!("Successfully removed file"),
                        Err(err) => error!("Failed to remove file: {}", err),
                    }
                } else {
                    // support ELF file only
                    if *analyzer.file_format() == FileFormat::ExecutableAndLinkableFormat {
                        analyzer.analyze_static();
                    }
                }
            }
        }
    }
}
