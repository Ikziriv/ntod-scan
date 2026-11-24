#!/usr/bin/env python3
"""Generate examples/demo.pcap — synthetic LAN traffic for docs/screenshots.

Traffic mix: ARP, DNS (incl. long TXT queries), HTTP POST with cleartext
credentials, a TLS ClientHello (JA3), and a TCP SYN sweep so the analyzer's
deterministic detectors produce findings.
"""
import struct
import sys

GW_MAC = b"\xa4\x83\xe7\x11\x22\x33"
CLI_MAC = b"\x8c\xc8\x4b\xaa\xbb\xcc"
SCAN_MAC = b"\xde\xad\xbe\xef\x00\x01"
GW_IP = "192.168.1.1"
CLI_IP = "192.168.1.42"
SCAN_IP = "192.168.1.66"
DNS_IP = "1.1.1.1"
WEB_IP = "93.184.216.34"


def ip(a):
    return bytes(int(x) for x in a.split("."))


def csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(f">{len(b) // 2}H", b))
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=0x1000):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                      0x4000, 64, proto, 0, ip(src), ip(dst))
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:] + payload


def tcp(src_ip, dst_ip, sport, dport, flags, payload=b"", seq=1000):
    off = 5 << 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags,
                      32120, 0, 0)
    ph = ip(src_ip) + ip(dst_ip) + struct.pack("!BBH", 0, 6, len(seg) + len(payload))
    return seg[:16] + struct.pack("!H", csum(ph + seg + payload)) + seg[18:] + payload


def udp(src_ip, dst_ip, sport, dport, payload):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ph = ip(src_ip) + ip(dst_ip) + struct.pack("!BBH", 0, 17, len(hdr) + len(payload))
    return hdr[:6] + struct.pack("!H", csum(ph + hdr + payload)) + payload


def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def dns_query(name, qtype=1, tid=0x1234, src=CLI_IP, sport=53000):
    q = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return udp(src, DNS_IP, sport, 53, q)


def dns_resp(name, addr, tid=0x1234):
    q = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    q += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip(addr)
    return udp(DNS_IP, CLI_IP, 53, 53000, q)


def arp(op, smac, sip, tmac, tip):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + smac + ip(sip) + tmac + ip(tip)
    return eth(b"\xff" * 6 if op == 1 else tmac, smac, 0x0806, body)


def tls_clienthello():
    # SNI example.com — minimal ClientHello inside a TLS record.
    sni = b"example.com"
    ext_sni = struct.pack("!HHH", 0, len(sni) + 5, len(sni) + 3) + \
        struct.pack("!BH", 0, len(sni)) + sni
    ext = ext_sni + struct.pack("!HH", 0x002B, 3) + b"\x02\x03\x04"
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + \
        struct.pack("!H", 8) + b"\x13\x01\x13\x02\x13\x03\xc0\x2f" + \
        b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


pkts = []  # (ts_us, bytes)
t = 1_700_000_000_000_000


def add(frame, dt_us=50_000):
    global t
    t += dt_us
    pkts.append((t, frame))


# ARP discovery
add(arp(1, CLI_MAC, CLI_IP, b"\x00" * 6, GW_IP))
add(arp(2, GW_MAC, GW_IP, CLI_MAC, CLI_IP))
# DNS lookups + responses
add(eth(GW_MAC, CLI_MAC, 0x0800, ipv4(CLI_IP, DNS_IP, 17, dns_query("intranet.corp.local"))))
add(eth(CLI_MAC, GW_MAC, 0x0800, ipv4(DNS_IP, CLI_IP, 17, dns_resp("intranet.corp.local", "10.0.0.8"))))
# Suspicious TXT lookups (DNS-tunnel detector needs >= 30 names)
for i in range(34):
    name = f"{i}x7f9a2b4c8d1e6f0a3b5c7d9e1f2a4b6c8d.tunnel.exfil.example.net"
    add(eth(GW_MAC, CLI_MAC, 0x0800,
            ipv4(CLI_IP, DNS_IP, 17, dns_query(name, 16, 0x2000 + i, sport=54000 + i))),
        30_000)
# Beacon: same host, same dst:port, steady ~2s period (detector needs >= 8)
for i in range(10):
    add(eth(GW_MAC, CLI_MAC, 0x0800,
            ipv4(CLI_IP, "45.155.204.9", 6,
                 tcp(CLI_IP, "45.155.204.9", 62000, 8443, 0x02, seq=i))), 2_000_000)
# HTTP POST with cleartext creds -> credential finding
http = b"POST /login HTTP/1.1\r\nHost: intranet.corp.local\r\n" \
       b"Content-Type: application/x-www-form-urlencoded\r\n" \
       b"Content-Length: 37\r\n\r\nuser=admin&password=hunter2&next=%2F"
add(eth(GW_MAC, CLI_MAC, 0x0800,
        ipv4(CLI_IP, "10.0.0.8", 6, tcp(CLI_IP, "10.0.0.8", 49152, 80, 0x02))), 200_000)
add(eth(CLI_MAC, GW_MAC, 0x0800,
        ipv4("10.0.0.8", CLI_IP, 6, tcp("10.0.0.8", CLI_IP, 80, 49152, 0x12))), 40_000)
add(eth(GW_MAC, CLI_MAC, 0x0800,
        ipv4(CLI_IP, "10.0.0.8", 6, tcp(CLI_IP, "10.0.0.8", 49152, 80, 0x18, http))), 30_000)
add(eth(CLI_MAC, GW_MAC, 0x0800,
        ipv4("10.0.0.8", CLI_IP, 6, tcp("10.0.0.8", CLI_IP, 80, 49152, 0x18,
             b"HTTP/1.1 302 Found\r\nLocation: /dash\r\nContent-Length: 0\r\n\r\n"))), 40_000)
# HTTPS flow (JA3 on the ClientHello)
add(eth(GW_MAC, CLI_MAC, 0x0800,
        ipv4(CLI_IP, WEB_IP, 6, tcp(CLI_IP, WEB_IP, 51500, 443, 0x02))), 300_000)
add(eth(CLI_MAC, GW_MAC, 0x0800,
        ipv4(WEB_IP, CLI_IP, 6, tcp(WEB_IP, CLI_IP, 443, 51500, 0x12))), 60_000)
add(eth(GW_MAC, CLI_MAC, 0x0800,
        ipv4(CLI_IP, WEB_IP, 6, tcp(CLI_IP, WEB_IP, 51500, 443, 0x18, tls_clienthello()))), 50_000)
# SYN sweep from the odd host -> deep-sweep finding (needs >= 32 ports)
for port in range(20, 62):
    add(eth(GW_MAC, SCAN_MAC, 0x0800,
            ipv4(SCAN_IP, GW_IP, 6, tcp(SCAN_IP, GW_IP, 40000 + port, port, 0x02,
                 seq=port * 7))), 8_000)

out = sys.argv[1] if len(sys.argv) > 1 else "examples/demo.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in pkts:
        f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000,
                            len(frame), len(frame)))
        f.write(frame)
print(f"wrote {out} ({len(pkts)} packets)")
