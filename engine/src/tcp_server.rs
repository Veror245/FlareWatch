use std::{
    io::{self, Read},
    net::TcpListener,
};

use super::aho;

pub fn server_main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4000")?;
    println!("Server is listening on {:?}", listener.local_addr()?);

    let mut buffer = [0u8; 1024];
    let mut lenbuf = [0u8; 4];
    let mut reqlen;
    let mut tempbuf: Vec<u8> = Vec::new();

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let addr = stream.peer_addr()?;
            println!("Client {addr} connected");

            loop {
                if let Ok(()) = stream.read_exact(&mut lenbuf) {
                    reqlen = u32::from_be_bytes(lenbuf);
                    let mut reqbuf: Vec<u8> = vec![0u8; reqlen as usize];
                    if stream.read_exact(&mut reqbuf).is_ok() {
                        let msg_type = reqbuf[0];
                        let iplen = reqbuf[1];
                        let ip = &reqbuf[2..(iplen + 2) as usize];
                        let msgst = (2 + iplen) as usize;
                        let msglen = &reqbuf[msgst..msgst + 2];
                        let msglen = u16::from_be_bytes(msglen.try_into().unwrap());
                        let msg =
                            &reqbuf[(msgst + 2) as usize..(msglen + 2 + msgst as u16) as usize];
                        println!(
                            "reqlen: {}, msg_type: {}, ip: {:?}, msg: {:?}",
                            reqlen,
                            msg_type,
                            std::str::from_utf8(ip),
                            std::str::from_utf8(msg)
                        );
                        let patterns = aho::AhoCorasick::search(&self, msg);
                    } else {
                        eprintln!("Error at reading msg bytes");
                        break;
                    }
                } else {
                    eprintln!("Error parsing req length");
                    break;
                }
            }
            println!("disconnected from {addr}");
        } else {
            println!("Error");
        }
    }

    Ok(())
}
