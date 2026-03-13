//! Fuzz target for PCAP parsing

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse as PCAP
    if data.len() >= 24 {
        if let Ok(reader) = capfile::PcapReader::from_reader(Cursor::new(data)) {
            // Try to read packets
            let mut reader = reader;
            let mut count = 0;
            while count < 100 {
                match reader.next_packet() {
                    Ok(Some(_)) => count += 1,
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
});
