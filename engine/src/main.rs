use engine::{aho, tcp_client, tcp_server};
use std::io;

fn main() -> io::Result<()> {
    println!("Hello, world!");

    let msg = "Hello Stream";

    let mut cora = aho::AhoCorasick::default();
    cora.add("aa".as_bytes(), 1);
    cora.add("ba".as_bytes(), 2);
    cora.add("cba".as_bytes(), 3);
    cora.add("her".as_bytes(), 4);

    // println!("{:#?}", cora);
    cora.print();
    println!("------------------------------------------");

    cora.create_failure_links();
    cora.print();

    println!("{:#?}", cora.search("cbaa".as_bytes()));

    tcp_client::client_main(msg)?;
    tcp_server::server_main()?;

    Ok(())
}
