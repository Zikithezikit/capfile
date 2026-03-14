#!/usr/bin/env python3
"""Generate test pcap fixtures for capfile testing."""

import struct

def create_simple_pcap(filename):
    """Create a simple pcap file with one TCP packet."""
    # PCAP global header (24 bytes)
    magic = 0xa1b2c3d4  # pcap magic
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # Ethernet
    
    header = struct.pack('<IHHiIII',
        magic, version_major, version_minor, thiszone,
        sigfigs, snaplen, network)
    
    # Packet: Ethernet + IPv4 + TCP
    # Ethernet header (14 bytes)
    eth_dst = b'\x00\x11\x22\x33\x44\x55'
    eth_src = b'\x66\x77\x88\x99\xaa\xbb'
    eth_type = b'\x08\x00'  # IPv4
    
    # IPv4 header (20 bytes)
    ipv4_ver_ihl = 0x45  # version=4, IHL=5
    ipv4_tos = 0
    ipv4_total_len = 40  # 20 + 20
    ipv4_id = 1
    ipv4_flags_offset = 0x4000  # Don't fragment
    ipv4_ttl = 64
    ipv4_proto = 6  # TCP
    ipv4_checksum = 0
    ipv4_src = b'\xc0\xa8\x01\x01'  # 192.168.1.1
    ipv4_dst = b'\xc0\xa8\x01\x02'  # 192.168.1.2
    
    # TCP header (20 bytes)
    tcp_src_port = 80
    tcp_dst_port = 443
    tcp_seq = 0
    tcp_ack = 0
    tcp_data_offset = 5  # 20 bytes
    tcp_flags = 0x02  # SYN
    tcp_window = 0
    tcp_checksum = 0
    tcp_urgent = 0
    
    packet = (eth_dst + eth_src + eth_type +
              struct.pack('!BBHHHBBH', ipv4_ver_ihl, ipv4_tos, ipv4_total_len, 
                         ipv4_id, ipv4_flags_offset, ipv4_ttl, ipv4_proto, ipv4_checksum) +
              ipv4_src + ipv4_dst +
              struct.pack('!HHIIBBHHH', tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack,
                         tcp_data_offset << 4, tcp_flags, tcp_window, tcp_checksum, tcp_urgent))
    
    # Packet header (16 bytes)
    ts_sec = 0
    ts_usec = 0
    incl_len = len(packet)
    orig_len = len(packet)
    
    packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
    
    with open(filename, 'wb') as f:
        f.write(header)
        f.write(packet_header)
        f.write(packet)
    
    print(f"Created {filename}: {len(header) + len(packet_header) + len(packet)} bytes")

def create_simple_pcapng(filename):
    """Create a simple pcapng file with one Enhanced Packet Block."""
    blocks = bytearray()
    
    # Section Header Block (28 bytes)
    shb_type = 0x0a0d0d0a
    shb_len = 28
    shb_byte_order = 0x1a2b3c4d
    shb_major = 1
    shb_minor = 0
    shb_section_len = -1  # unknown
    
    blocks.extend(struct.pack('<I', shb_type))
    blocks.extend(struct.pack('<I', shb_len))
    blocks.extend(struct.pack('<I', shb_byte_order))
    blocks.extend(struct.pack('<HH', shb_major, shb_minor))
    blocks.extend(struct.pack('<q', shb_section_len))
    blocks.extend(struct.pack('<I', shb_len))
    
    # Interface Description Block (24 bytes)
    idb_type = 0x00000001
    idb_len = 24
    idb_link_type = 1  # Ethernet
    idb_snap_len = 65535
    idb_reserved = 0
    idb_options = 0
    
    blocks.extend(struct.pack('<I', idb_type))
    blocks.extend(struct.pack('<I', idb_len))
    blocks.extend(struct.pack('<HH', idb_link_type, idb_reserved))
    blocks.extend(struct.pack('<I', idb_snap_len))
    blocks.extend(struct.pack('<I', idb_options))
    blocks.extend(struct.pack('<I', idb_len))
    
    # Enhanced Packet Block (with 4-byte payload for alignment)
    epb_type = 0x00000006
    packet_data = b'\xde\xad\xbe\xef'
    padded_len = (len(packet_data) + 3) & ~3  # 4-byte alignment
    epb_len = 32 + padded_len
    epb_interface_id = 0
    epb_ts_high = 0
    epb_ts_low = 1000
    epb_captured_len = len(packet_data)
    epb_original_len = len(packet_data)
    
    blocks.extend(struct.pack('<I', epb_type))
    blocks.extend(struct.pack('<I', epb_len))
    blocks.extend(struct.pack('<I', epb_interface_id))
    blocks.extend(struct.pack('<II', epb_ts_high, epb_ts_low))
    blocks.extend(struct.pack('<II', epb_captured_len, epb_original_len))
    blocks.extend(packet_data)
    # Padding
    blocks.extend(b'\x00' * (padded_len - len(packet_data)))
    blocks.extend(struct.pack('<I', epb_len))
    
    with open(filename, 'wb') as f:
        f.write(blocks)
    
    print(f"Created {filename}: {len(blocks)} bytes")

if __name__ == '__main__':
    create_simple_pcap('tests/fixtures/simple.pcap')
    create_simple_pcapng('tests/fixtures/simple.pcapng')