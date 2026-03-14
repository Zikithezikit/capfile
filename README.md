# Capfile

[![Rust](https://github.com/Zikithezikit/capfile/actions/workflows/rust.yml/badge.svg)](https://github.com/Zikithezikit/capfile/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/capfile.svg)](https://crates.io/crates/capfile)
[![docs.rs](https://docs.rs/capfile/badge.svg)](https://docs.rs/capfile)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A pure Rust crate for reading and writing pcap/pcapng capture files with zero-copy parsing and built-in packet dissection.

## Features

- **Zero-copy parsing**: Efficiently parse large capture files without unnecessary memory allocation
- **Both formats**: Full support for legacy PCAP and modern PCAPNG formats
- **Packet dissection**: Built-in dissection for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and DNS
- **Write support**: Create new PCAP and PCAPNG capture files
- **Memory-mapped I/O**: Fast reading using memory mapping

## Quick Start

### Reading a PCAP file

```rust
use capfile::PcapReader;

let mut reader = PcapReader::open("capture.pcap")?;

while let Some(pkt) = reader.next_packet()? {
    println!("{} bytes at {}", pkt.len(), pkt.timestamp_ns());
}
```

### Reading from bytes (no_std/WASM)

```rust
use capfile::PcapReader;
use std::io::Cursor;

let data = include_bytes!("capture.pcap");
let mut reader = PcapReader::from_reader(Cursor::new(data))?;

while let Some(pkt) = reader.next_packet()? {
    // Process packet
}
```

### Reading a PCAPNG file

```rust
use capfile::PcapngReader;
use capfile::format::pcapng::Block;

let mut reader = PcapngReader::open("capture.pcapng")?;

// Get interface information
for (i, iface) in reader.interfaces().iter().enumerate() {
    println!("Interface {}: link_type={}, snap_len={}", i, iface.link_type, iface.snap_len);
}

// Iterate over blocks
while let Some(block) = reader.next_block()? {
    match block {
        Block::EnhancedPacket(epb) => {
            println!("Packet: {} bytes on interface {}", epb.captured_length, epb.interface_id);
        }
        Block::InterfaceStatistics(stats) => {
            println!("Stats: {} packets received", stats.packets_received);
        }
        _ => {}
    }
}
```

### Packet Dissection

```rust
use capfile::{PcapReader, dissect::{Ethernet, Ipv4, Tcp}};

let mut reader = PcapReader::open("capture.pcap")?;

if let Some(pkt) = reader.next_packet()? {
    // Dissect Ethernet
    let eth = Ethernet::new(pkt.data())?;
    println!("{} -> {}", eth.src(), eth.dst());

    // Dissect IPv4
    let ip = Ipv4::new(eth.payload())?;
    println!("{} -> {}", ip.src_str(), ip.dst_str());

    // Dissect TCP
    if let Ok(tcp) = Tcp::new(ip.payload()) {
        println!("{} -> {}", tcp.src_port(), tcp.dst_port());
    }
}
```

### Writing a PCAP file

```rust
use capfile::PcapWriter;

let mut writer = PcapWriter::create("output.pcap", 1)?; // Ethernet (link_type = 1)

// Write a packet (data, timestamp in ns, captured length)
writer.write_packet(b"packet data", 1_000_000_000, 14)?;
```

### Writing a PCAPNG file

```rust
use capfile::PcapngWriter;

let mut writer = PcapngWriter::create("output.pcapng")?;

// Add an interface (returns interface ID)
let iface_id = writer.write_interface(1, 65535)?; // Ethernet, snap_len = 65535

// Write a packet
writer.write_packet(iface_id, b"packet data", 1_000_000_000, 14, 14)?;
```

## Feature Flags

- `std` (default): Enables file system access. Without this feature, you can only parse from in-memory byte slices.

## Requirements

- Rust 1.80 or later

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
