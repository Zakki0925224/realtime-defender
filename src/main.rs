#[macro_use]
extern crate log;
extern crate env_logger;

mod analyzer;
mod definitions;

use inotify::{EventMask, Inotify, WatchMask};
use std::{
    env,
    fs::remove_file,
    path::{Path, PathBuf},
    process::exit,
};

use crate::{analyzer::*, definitions::Definitions};

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
    let mut analyzer = Analyzer::new(definitions);

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
                let lisk_type = match analyzer.analyze_heuristic() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                info!("Lisk type: {:?}", lisk_type);

                match lisk_type {
                    LiskType::DangerHash(def) => {
                        warn!(
                            "Detected malware file: \"{}\" is \"{}\",  removing...",
                            analyzer.analyzing_filepath().display(),
                            def.title
                        );

                        match remove_file(analyzer.analyzing_filepath()) {
                            Ok(_) => info!("Successfully to remove file!"),
                            Err(err) => error!("Failed to remove file: {}", err),
                        }

                        continue;
                    }
                    LiskType::IncludeSuspiciousStrings(strings) => {
                        warn!("Suspicious strings was found: {:?}", strings);
                    }
                    _ => (),
                }

                // support ELF file only
                let lisk_type = match analyzer.analyze_static() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                match lisk_type {
                    LiskType::None => continue,
                    LiskType::HasVulnerableScanf => {
                        warn!("Vulnerable scanf code was found!")
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}
