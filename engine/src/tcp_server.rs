use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use crate::aho::AhoCorasick;
use std::collections::HashSet;

use std::time;

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
enum ThreatType {
    SQLI,
    XSS,
    PathTraversal,
    CommandInjection,
    SensitiveAccess,
    SSRF,
    LDAPInjection,
    XXE,
    HTTPAnomaly,
    HTTPEvent,
    Unknown,
}

fn build_id_to_threat_table() -> [ThreatType; 212] {
    let mut table = [ThreatType::Unknown; 212];

    // Fill ranges
    for id in 0..=36 {
        table[id] = ThreatType::SQLI;
    }
    for id in 37..=65 {
        table[id] = ThreatType::XSS;
    }
    for id in 66..=93 {
        table[id] = ThreatType::PathTraversal;
    }
    for id in 94..=127 {
        table[id] = ThreatType::CommandInjection;
    }
    for id in 128..=152 {
        table[id] = ThreatType::SensitiveAccess;
    }
    for id in 153..=179 {
        table[id] = ThreatType::SSRF;
    }
    for id in 180..=188 {
        table[id] = ThreatType::LDAPInjection;
    }
    for id in 189..=197 {
        table[id] = ThreatType::XXE;
    }
    for id in 198..=207 {
        table[id] = ThreatType::HTTPAnomaly;
    }
    for id in 208..=211 {
        table[id] = ThreatType::HTTPEvent;
    }

    table
}

pub fn server_main(ac: Arc<AhoCorasick>) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4000")?;
    println!("Server is listening on {:?}", listener.local_addr()?);

    let mut downstream = TcpStream::connect("127.0.0.1:4002")?;
    println!("Server is writing to {:?}", downstream.local_addr()?);

    let threat_table = build_id_to_threat_table();

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let addr = stream.peer_addr()?;
            println!("Client {addr} connected");
            let ac = Arc::clone(&ac);
            let t1 = time::Instant::now();
            let (processed, threats) =
                handle_client(&mut stream, ac, threat_table, &mut downstream);
            let elapsed = t1.elapsed().as_secs_f64();
            println!("logs/sec: {:?}", processed as f64 / elapsed);
            println!("Total Threats: {}", threats);

            println!("disconnected from {addr}");
        } else {
            println!("Error");
        }
    }

    Ok(())
}

fn handle_client(
    stream: &mut TcpStream,
    ac: Arc<AhoCorasick>,
    threat_table: [ThreatType; 212],
    downstream: &mut TcpStream,
) -> (u32, u32) {
    let mut lenbuf = [0u8; 4];
    let mut reqlen;
    let mut processed: u32 = 0;
    let mut threats_count: u32 = 0;

    let mut payload: Vec<u8> = vec![0u8];

    loop {
        if let Ok(()) = stream.read_exact(&mut lenbuf) {
            reqlen = u32::from_be_bytes(lenbuf);
            let mut reqbuf: Vec<u8> = vec![0u8; reqlen as usize];
            if stream.read_exact(&mut reqbuf).is_ok() {
                processed += 1;
                let msg_type = reqbuf[0];
                let iplen = reqbuf[1];
                let ip = &reqbuf[2..(iplen + 2) as usize];
                let msgst = (2 + iplen) as usize;
                let msglen = &reqbuf[msgst..msgst + 2];
                let msglen = u16::from_be_bytes(msglen.try_into().unwrap());
                let msg = &reqbuf[(msgst + 2) as usize..(msglen + 2 + msgst as u16) as usize];
                let matches = ac.search(msg);

                if matches
                    .iter()
                    .any(|&id| threat_table[id] != ThreatType::Unknown)
                {
                    threats_count += 1;
                    let threats: HashSet<ThreatType> = matches
                        .iter()
                        .map(|&id| threat_table[id])
                        .filter(|&t| t != ThreatType::Unknown)
                        .collect();
                    if let Some(th) = threats.iter().next() {
                        let threat_code: u8 = match *th {
                            ThreatType::SQLI => 0,
                            ThreatType::XSS => 1,
                            ThreatType::PathTraversal => 2,
                            ThreatType::CommandInjection => 3,
                            ThreatType::SensitiveAccess => 4,
                            ThreatType::SSRF => 5,
                            ThreatType::LDAPInjection => 6,
                            ThreatType::XXE => 7,
                            ThreatType::HTTPAnomaly => 8,
                            _ => 255,
                        };
                        payload.push(threat_code);
                    }
                    payload.push(iplen);
                    payload.extend_from_slice(ip);
                    payload.extend_from_slice(&(msglen.to_be_bytes()));
                    payload.extend_from_slice(msg);

                    let total_len = payload.len();
                } else {
                }
            } else {
                eprintln!("Error at reading msg bytes");
                break;
            }
        } else {
            eprintln!("Error parsing req length");
            break;
        }
    }

    (processed, threats_count)
}
