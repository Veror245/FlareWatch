use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::time;
use std::{
    io::{Read, Write},
    sync::Arc,
    sync::Mutex,
};

const PATTERNS: &str = include_str!("../aho_patterns.txt");

fn main() -> io::Result<()> {
    let mut ac = AhoCorasick::default();
    load_patterns(&mut ac);
    ac.create_failure_links();

    let ac = Arc::new(ac);
    let index = Arc::new(Mutex::new(ThreatIndex::default()));

    server_main(ac, Arc::clone(&index))?;

    Ok(())
}

fn load_patterns(ac: &mut AhoCorasick) {
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
            }
        } else {
            eprintln!("Skipping malformed pattern line: {line}");
        }
    }
}

#[derive(Debug)]
struct Node {
    next: [i32; 256],
    fail: usize,
    outputs: Vec<usize>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            next: [-1; 256],
            fail: 0,
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct AhoCorasick {
    nodes: Vec<Node>,
}

impl Default for AhoCorasick {
    fn default() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
}

impl AhoCorasick {
    pub fn add(&mut self, bytes: &[u8], pattern_id: usize) {
        let mut curr = 0;

        for &byte in bytes {
            let next = self.nodes[curr].next[byte as usize];
            if next == -1 {
                let new_node = self.nodes.len();
                self.nodes.push(Node::default());

                self.nodes[curr].next[byte as usize] = new_node as i32;
                curr = new_node;
            } else {
                curr = next as usize;
            }
        }

        self.nodes[curr].outputs.push(pattern_id);
    }

    pub fn print(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            println!("Node {i}:");

            for (byte, &child) in node.next.iter().enumerate() {
                if child != -1 {
                    println!("  '{}' ({byte}) -> Node {child}", byte as u8 as char);
                }
            }

            println!("  outputs: {:?}", node.outputs);
        }
    }

    pub fn create_failure_links(&mut self) {
        let mut queue = VecDeque::new();
        for i in 0..256 {
            let child = self.nodes[0].next[i];
            if child != -1 {
                self.nodes[child as usize].fail = 0;
                queue.push_back(child);
            }
        }

        while let Some(curr) = queue.pop_front() {
            for byte in 0..256 {
                let child = self.nodes[curr as usize].next[byte];
                if child == -1 {
                    continue;
                }

                let mut fail = self.nodes[curr as usize].fail;
                while fail != 0 && self.nodes[fail].next[byte] == -1 {
                    fail = self.nodes[fail].fail;
                }

                if self.nodes[fail].next[byte] != -1 {
                    fail = self.nodes[fail].next[byte] as usize;
                } else {
                    fail = 0;
                }

                self.nodes[child as usize].fail = fail;

                //merges outputs from failutes
                let fail_outputs = self.nodes[fail].outputs.clone();
                self.nodes[child as usize].outputs.extend(fail_outputs);

                queue.push_back(child);
            }
        }
    }

    pub fn search(&self, pattern: &[u8]) -> Vec<usize> {
        let mut curr: usize = 0;
        let mut patterns = Vec::new();
        for &bytes in pattern {
            let bytes = bytes as usize;
            while curr != 0 && self.nodes[curr].next[bytes] == -1 {
                curr = self.nodes[curr].fail;
            }

            if self.nodes[curr].next[bytes] != -1 {
                curr = self.nodes[curr].next[bytes] as usize;
            } else {
                curr = 0;
            }

            patterns.extend(self.nodes[curr].outputs.iter().copied());
        }

        patterns
    }
}

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
    let listener = TcpListener::bind("0.0.0.0:4000")?;
    println!("Server is listening on {:?}", listener.local_addr()?);

    let threat_table = build_id_to_threat_table();

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let addr = stream.peer_addr()?;
            println!("Client {addr} connected");
            let ac = Arc::clone(&ac);
            let index = Arc::clone(&index);

            std::thread::spawn(move || {
                if let Err(e) = handle_client(&mut stream, ac, threat_table, index) {
                    eprintln!("Error handling client {addr}: {e}");
                }
                println!("disconnected from {addr}");
            });
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
    let analysis_host = std::env::var("ANALYSIS_HOST").unwrap_or("127.0.0.1".into());
    let backend_host = std::env::var("BACKEND_HOST").unwrap_or("127.0.0.1".into());

    let analysis_addr = format!("{}:4001", analysis_host);
    let backend_addr = format!("{}:4002", backend_host);
    let mut downstream_backend = match TcpStream::connect(&analysis_addr) {
        Ok(stream) => {
            println!("Server is writing to backend {:?}", stream.local_addr()?);
            Some(stream)
        }
        Err(_) => {
            eprintln!("failure to connect to backend server");
            None
        }
    };

    let mut downstream_analysis = match TcpStream::connect(&backend_addr) {
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
                    let result_bytes = results.join("\n").into_bytes();
                    let payloadlen = result_bytes.len() + 1;
                    let mut frame = Vec::with_capacity(payloadlen + 4);
                    frame.extend_from_slice(&(payloadlen as u32).to_be_bytes());
                    frame.push(5);
                    frame.extend_from_slice(&result_bytes);

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
                            let event_id =
                                matches.iter().copied().find(|&id| id >= 208 && id <= 211);
                            let eventtype = event_id.map(|id| id - 208).unwrap_or(255);
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

#[derive(Default)]
pub struct ThreatIndex {
    pub logs: Vec<String>,
    index: HashMap<String, Vec<usize>>,
}

impl ThreatIndex {
    fn tokenize(log: &str) -> HashSet<String> {
        let mut tokens = HashSet::new();
        for word in log.split_whitespace() {
            let lower = word.to_lowercase();

            // Always store the full word if it contains at least one alphanumeric character.
            if lower.chars().any(|c| c.is_alphanumeric()) {
                tokens.insert(lower.clone());
            }

            // Split on any non-alphanumeric character and add meaningful sub-tokens.
            for sub in lower.split(|c: char| !c.is_alphanumeric()) {
                if !sub.is_empty() && sub.chars().any(|c| c.is_alphanumeric()) {
                    tokens.insert(sub.to_string());
                }
            }
        }
        tokens
    }

    pub fn add_threat(&mut self, log: String) {
        let idx = self.logs.len();
        self.logs.push(log.clone());

        // Tokenize and index
        for token in ThreatIndex::tokenize(&log) {
            self.index.entry(token).or_default().push(idx); //or default is mnmore ididmatic,
            //so use that
        }
    }

    pub fn search_by_token(&self, term: &str) -> Vec<String> {
        let term = term.to_lowercase();
        self.index
            .get(&term)
            .map(|indices| indices.iter().map(|&i| self.logs[i].clone()).collect())
            .unwrap_or_default()
    }
}
