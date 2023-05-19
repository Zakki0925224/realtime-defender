#[macro_use]
extern crate log;
extern crate env_logger;

use inotify::{Inotify, WatchMask};
use std::{env, path::PathBuf, process::exit};

fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Invalid arguments");
        exit(1);
    }

    let mut inotify = Inotify::init().expect("Failed to initialize inotify");
    let dir = PathBuf::from(&args[1]);

    inotify
        .add_watch(
            dir,
            WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MODIFY
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::ATTRIB
                | WatchMask::OPEN,
        )
        .expect("Failed to add watch");

    println!("Watching at \"{}\"...", args[1]);

    let mut buffer = [0; 4096];

    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("Failed to read events");

        for event in events {
            info!("{:?}", event);
        }
    }
}
