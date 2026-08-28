use std::{
    io::{self, Write},
    net::TcpStream,
};

pub fn client_main(msg: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:4002")?;
    println!("Connected to server: {}", stream.peer_addr()?);

    // let mut buf = [0u8; 1024];

    //let msg = String::from("Hello Stream !");

    stream.write_all(msg.as_bytes())?;

    Ok(())
}
