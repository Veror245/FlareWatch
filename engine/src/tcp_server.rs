use std::{
    io::{self, Read},
    net::TcpListener,
};

pub fn server_main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4000")?;
    println!("Server is listening on {:?}", listener.local_addr()?);

    let mut buffer = [0u8; 1024];

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let addr = stream.peer_addr()?;
            println!("Client {addr} connected");

            loop {
                let n = stream.read(&mut buffer)?;
                println!("size of message: {}", n);

                if n == 0 {
                    break;
                }

                let msg = String::from_utf8_lossy(&buffer[..n]);
                println!("{addr}: {msg}");
            }

            println!("disconnected from {addr}");
        } else {
            println!("Error");
        }
    }

    Ok(())
}
