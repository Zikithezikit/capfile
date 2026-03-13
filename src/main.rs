//! Capfile CLI tool

use std::env;
use std::process::exit;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Capfile - Pure Rust pcap/pcapng library");
        println!("");
        println!("Usage: capfile <command> [options]");
        println!("");
        println!("Commands:");
        println!("  info <file>    - Display file info (magic, version, link type)");
        println!("  list <file>    - List packets in capture file");
        println!("");
        println!("Examples:");
        println!("  capfile info capture.pcap");
        println!("  capfile list capture.pcapng");
        exit(1);
    }

    let cmd = &args[1];

    match cmd.as_str() {
        "info" => {
            if args.len() < 3 {
                eprintln!("Error: missing file argument");
                exit(1);
            }
            info_file(&args[2]);
        }
        "list" => {
            if args.len() < 3 {
                eprintln!("Error: missing file argument");
                exit(1);
            }
            list_packets(&args[2]);
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            exit(1);
        }
    }
}

fn info_file(path: &str) {
    use std::fs::File;
    use std::io::Read;

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            exit(1);
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Error reading file: {}", e);
        exit(1);
    }

    // Try to detect format
    if buffer.len() >= 4 {
        let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        match magic {
            0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 => {
                println!("Format: PCAP");
                if let Ok(reader) = capfile::PcapReader::from_reader(std::io::Cursor::new(&buffer))
                {
                    println!("Link type: {}", reader.link_type());
                }
            }
            0x0a0d0d0a => {
                println!("Format: PCAPNG");
                if let Ok(reader) =
                    capfile::PcapngReader::from_reader(std::io::Cursor::new(&buffer))
                {
                    println!("Interfaces: {}", reader.interfaces().len());
                    for (i, iface) in reader.interfaces().iter().enumerate() {
                        println!(
                            "  Interface {}: link_type={}, snap_len={}",
                            i, iface.link_type, iface.snap_len
                        );
                    }
                }
            }
            _ => {
                println!("Unknown format");
            }
        }
    }
}

fn list_packets(path: &str) {
    use std::fs::File;
    use std::io::Read;

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            exit(1);
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Error reading file: {}", e);
        exit(1);
    }

    if buffer.len() >= 4 {
        let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        match magic {
            0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 => {
                // PCAP
                if let Ok(mut reader) =
                    capfile::PcapReader::from_reader(std::io::Cursor::new(&buffer))
                {
                    let mut count = 0;
                    while let Ok(Some(packet)) = reader.next_packet() {
                        count += 1;
                        println!(
                            "{}: {} bytes at {} ns",
                            count,
                            packet.len(),
                            packet.timestamp_ns()
                        );
                    }
                    println!("Total packets: {}", count);
                }
            }
            0x0a0d0d0a => {
                // PCAPNG
                if let Ok(mut reader) =
                    capfile::PcapngReader::from_reader(std::io::Cursor::new(&buffer))
                {
                    use capfile::format::pcapng::Block;

                    let mut count = 0;
                    while let Ok(Some(block)) = reader.next_block() {
                        if let Block::EnhancedPacket(epb) = block {
                            count += 1;
                            let ts =
                                ((epb.timestamp_high as u64) << 32) | (epb.timestamp_low as u64);
                            println!("{}: {} bytes at {} ns", count, epb.captured_length, ts);
                        }
                    }
                    println!("Total packets: {}", count);
                }
            }
            _ => {
                eprintln!("Unknown format");
            }
        }
    }
}
