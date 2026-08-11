//! End-to-end DNS over a real UDP socket: intercept and static precedence.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use hematite_dns::resolve::{DnsConfig, StaticRecord};
use hematite_dns::wire::{parse_query, TYPE_A};
use hematite_dns::DnsServer;
use hematite_kernel::matcher::DomainGlob;

fn query_packet(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

/// Extract the first A record's IPv4 from a response (naive: last 4 bytes of
/// a single-A answer).
fn first_a(resp: &[u8]) -> Option<Ipv4Addr> {
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }
    let octets = &resp[resp.len() - 4..];
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

#[tokio::test(flavor = "multi_thread")]
async fn intercept_and_static_over_udp() {
    let mut records = HashMap::new();
    records.insert("db.internal.corp".to_string(), StaticRecord::A(Ipv4Addr::new(10, 0, 0, 9)));
    let config = DnsConfig {
        proxy_ip: Ipv4Addr::new(172, 20, 0, 2),
        passthrough: vec![DomainGlob::parse("*.internal.corp").unwrap()],
        records,
        ttl: 60,
    };
    // Upstream resolver unused here (no passthrough query is issued).
    let server = Arc::new(DnsServer::new(config, "127.0.0.1:9".parse().unwrap()));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    tokio::spawn(server.serve_udp(socket));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server_addr).await.unwrap();

    // Intercepted name → proxy_ip.
    client.send(&query_packet(1, "anything.example", TYPE_A)).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = client.recv(&mut buf).await.unwrap();
    let resp = &buf[..n];
    assert_eq!(parse_query(&query_packet(1, "anything.example", TYPE_A)).unwrap().id, 1);
    assert_eq!(first_a(resp), Some(Ipv4Addr::new(172, 20, 0, 2)));

    // Static record inside the passthrough zone → static wins.
    client.send(&query_packet(2, "db.internal.corp", TYPE_A)).await.unwrap();
    let n = client.recv(&mut buf).await.unwrap();
    assert_eq!(first_a(&buf[..n]), Some(Ipv4Addr::new(10, 0, 0, 9)));
}
