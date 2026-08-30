use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use crate::{aho::AhoCorasick, index::ThreatIndex};
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

pub fn server_main(ac: Arc<AhoCorasick>, index: Arc<Mutex<ThreatIndex>>) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4000")?;
    println!("Server is listening on {:?}", listener.local_addr()?);

    let threat_table = build_id_to_threat_table();
    //let mut index = ThreatIndex::default();

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let addr = stream.peer_addr()?;
            println!("Client {addr} connected");
            let ac = Arc::clone(&ac);
            let index = Arc::clone(&index);
            //           let pindex = Arc::clone(&index);
            handle_client(&mut stream, ac, threat_table, index)?;
            println!("disconnected from {addr}");
            // let idx = pindex.lock().unwrap();
            // let res = idx.search_by_token("Sqli");
            // println!("{:?}", res.join("\n"));
            // println!("Threat Index");
            // for (i, log) in idx.logs.iter().enumerate() {
            //     println!("[{}] {}", i, log);
            // }
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
    index: Arc<Mutex<ThreatIndex>>,
) -> io::Result<()> {
    let mut lenbuf = [0u8; 4];
    let mut reqlen;
    let mut processed: u64 = 0;
    let mut threats_count: u64 = 0;
    let mut t1 = time::Instant::now();
    let tottime = time::Instant::now();

    let mut downstream_backend = match TcpStream::connect("127.0.0.1:4002") {
        Ok(stream) => {
            println!("Server is writing to backend {:?}", stream.local_addr()?);
            Some(stream)
        }
        Err(_) => {
            eprintln!("failure to connect to backend server");
            None
        }
    };

    let mut downstream_analysis = match TcpStream::connect("127.0.0.1:4001") {
        Ok(stream) => {
            println!("Server is writing to analysus {:?}", stream.local_addr()?);
            Some(stream)
        }
        Err(_) => {
            eprintln!("failure to connect to analysis server");
            None
        }
    };

    loop {
        if let Ok(()) = stream.read_exact(&mut lenbuf) {
            reqlen = u32::from_be_bytes(lenbuf);
            let mut reqbuf: Vec<u8> = vec![0u8; reqlen as usize];
            if stream.read_exact(&mut reqbuf).is_ok() {
                processed += 1;
                let msg_type = reqbuf[0];
                if msg_type == 5 {
                    let msglen = &reqbuf[1..=2];
                    let msglen = u16::from_be_bytes(msglen.try_into().unwrap());
                    let msg = &reqbuf[3..(3 + msglen) as usize];
                    let mut results = Vec::new();
                    let term: String = String::from_utf8_lossy(msg).into();
                    if let Ok(idx) = index.lock() {
                        results = idx.search_by_token(&term);
                    } else {
                        eprintln!("failed to lock index");
                    }
                    let payloadlen = results.len() + 1;
                    let mut frame = Vec::with_capacity(payloadlen);
                    frame.extend_from_slice(&(payloadlen as u32).to_be_bytes());
                    frame.push(5);
                    frame.extend_from_slice(&(results.join("\n").into_bytes()));

                    if let Some(stream) = downstream_backend.as_mut() {
                        if let Err(e) = stream.write_all(&frame) {
                            eprintln!("Error sending search results: {}", e);
                            break;
                        }
                    } else {
                        eprintln!("Not connected to bakckend");
                    }
                    continue;
                }
                let iplen = reqbuf[1];
                let ip = &reqbuf[2..(iplen + 2) as usize];
                let msgst = (2 + iplen) as usize;
                let msglen = &reqbuf[msgst..msgst + 2];
                let msglen = u16::from_be_bytes(msglen.try_into().unwrap());
                let msg = &reqbuf[(msgst + 2) as usize..(msglen + 2 + msgst as u16) as usize];
                let matches = ac.search(msg);
                let mut payload: Vec<u8> = Vec::new();
                let mut threat_code: u8 = 9;

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
                        threat_code = match *th {
                            ThreatType::SQLI => 0,
                            ThreatType::XSS => 1,
                            ThreatType::PathTraversal => 2,
                            ThreatType::CommandInjection => 3,
                            ThreatType::SensitiveAccess => 4,
                            ThreatType::SSRF => 5,
                            ThreatType::LDAPInjection => 6,
                            ThreatType::XXE => 7,
                            ThreatType::HTTPAnomaly => 8,
                            ThreatType::HTTPEvent => 9,
                            _ => 255,
                        };
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            .to_string();
                        let logstr = format!(
                            "[{:?}] [{:?}] {} {}",
                            timestamp,
                            th,
                            String::from_utf8_lossy(ip),
                            String::from_utf8_lossy(msg)
                        );
                        if let Ok(mut idx) = index.lock() {
                            idx.add_threat(logstr);
                        } else {
                            eprintln!("Failed to lock threat index");
                        }
                        if threat_code != 9 {
                            payload.push(threat_code);
                        } else {
                            let eventtype = matches[0] - 208;
                            payload.push(eventtype as u8);
                        }
                    }
                    payload.push(iplen);
                    payload.extend_from_slice(ip);
                    payload.extend_from_slice(&(msglen.to_be_bytes()));
                    payload.extend_from_slice(msg);

                    let total_len = payload.len() + 1;
                    let mut frame = Vec::with_capacity(total_len);
                    frame.extend_from_slice(&(total_len as u32).to_be_bytes());
                    if threat_code != 9 {
                        frame.push(1);
                    } else {
                        frame.push(4);
                    }
                    frame.extend_from_slice(&payload);

                    if threat_code != 9 {
                        if let Some(stream) = downstream_backend.as_mut() {
                            if let Err(e) = stream.write_all(&frame) {
                                eprintln!("Client Error: {e}");
                                break;
                            }
                        } else {
                            eprintln!("Not connected to backend");
                            break;
                        }
                        if let Some(stream) = downstream_analysis.as_mut() {
                            if let Err(e) = stream.write_all(&frame) {
                                eprintln!("Client Error: {e}");
                                break;
                            }
                        } else {
                            eprintln!("Not connected to analysis server");
                            break;
                        }
                    } else {
                        if let Some(stream) = downstream_analysis.as_mut() {
                            if let Err(e) = stream.write_all(&frame) {
                                eprintln!("Client Error: {e}");
                                break;
                            }
                        } else {
                            eprintln!("Not connected to analysis server");
                            break;
                        }
                    }
                } else {
                    payload.push(iplen);
                    payload.extend_from_slice(ip);
                    payload.extend_from_slice(&(msglen.to_be_bytes()));
                    payload.extend_from_slice(msg);

                    let total_len = payload.len() + 1;
                    let mut frame = Vec::with_capacity(total_len);
                    frame.extend_from_slice(&(total_len as u32).to_be_bytes());
                    frame.push(2);
                    frame.extend_from_slice(&payload);

                    if let Some(stream) = downstream_backend.as_mut() {
                        if let Err(e) = stream.write_all(&frame) {
                            eprintln!("Client Error: {e}");
                            break;
                        }
                    } else {
                        eprintln!("Not connected to backend");
                        break;
                    }
                }
                let elapsed = t1.elapsed().as_secs_f64();
                let totelapsed = tottime.elapsed().as_secs_f64();
                if elapsed >= 2.00 {
                    t1 = time::Instant::now();
                    let logsec = (processed as f64 / totelapsed) as u32;
                    println!("logs/sec: {:?}", logsec);
                    println!("Total Threats: {}", threats_count);
                    let mut payload = Vec::new();

                    payload.extend_from_slice(&(processed.to_be_bytes()));
                    payload.extend_from_slice(&(threats_count.to_be_bytes()));
                    payload.extend_from_slice(&(logsec.to_be_bytes()));

                    let totalen = payload.len() + 1;
                    let mut frame = Vec::with_capacity(totalen);

                    frame.extend_from_slice(&((totalen as u32).to_be_bytes()));
                    frame.push(3);
                    frame.extend_from_slice(&payload);

                    if let Some(stream) = downstream_backend.as_mut() {
                        if let Err(e) = stream.write_all(&frame) {
                            eprintln!("Client Error: {e}");
                            break;
                        }
                    } else {
                        eprintln!("Not connected to backend");
                        break;
                    }
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

    Ok(())
}
