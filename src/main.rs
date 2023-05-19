use std::{env, path::PathBuf, process::exit};

use inotify::{Inotify, WatchMask};

fn main() {
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
                | WatchMask::ATTRIB,
        )
        .expect("Failed to add watch");

    println!("Watching...");

    let mut buffer = [0; 4096];

    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("Failed to read events");

        for event in events {
            println!("{:?}", event);
        }
    }
}
