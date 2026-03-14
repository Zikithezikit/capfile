//! Fuzz target for PCAPNG parsing

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse as PCAPNG
    if data.len() >= 12 {
        if let Ok(reader) = capfile::PcapngReader::from_reader(Cursor::new(data)) {
            // Try to read blocks
            let mut reader = reader;
            let mut count = 0;
            while count < 100 {
                match reader.next_block() {
                    Ok(Some(_)) => count += 1,
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
});
