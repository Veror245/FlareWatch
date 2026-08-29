use engine::{
    aho::{self, AhoCorasick},
    tcp_server,
};
use std::{io, sync::Arc};
const PATTERNS: &str = include_str!("../../aho_patterns.txt");

fn main() -> io::Result<()> {
    println!("Hello, world!");

    let mut ac = aho::AhoCorasick::default();
    load_patterns(&mut ac);
    ac.create_failure_links();

    let ac = Arc::new(ac);

    tcp_server::server_main(ac)?;

    Ok(())
}

fn load_patterns(ac: &mut AhoCorasick) {
    let mut count = 0;
    for line in PATTERNS.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Split on |, last part si id
        if let Some((pattern, id_str)) = line.split_once(',') {
            let pattern = pattern.trim();
            let id: usize = id_str.trim().parse().expect("valid pattern ID");
            if !pattern.is_empty() {
                ac.add(pattern.as_bytes(), id);
                count += 1;
            }
        } else {
            eprintln!("Skipping malformed pattern line: {line}");
        }
    }
    println!("Loaded {} patterns", count);
}
