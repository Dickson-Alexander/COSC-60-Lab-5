#!/usr/bin/env python3

#parse arguments; every int before a dash should be the beginning of a port RANGE,
#every int after a dash should be the end of a port; no dash before a comma / before the end of the string
# means a single port. commas should separate port ranges.
#the input will be in the format "1-1024, 8080". 

import argparse
from typing import List, Set

MIN_PORT = 1
MAX_PORT = 65535

# fast_syn_scan.py (function to replace your syn_scan_ports)
def syn_scan_ports_batch(host: str, ports: List[int], timeout: float = 2.0) -> Set[int]:
    try:
        from scapy.all import IP, TCP, sr, RandShort, conf
    except Exception as e:
        raise RuntimeError("Scapy required: sudo pip3 install scapy") from e

    # reduce verbosity
    conf.verb = 0

    # Build one packet containing many destination ports
    pkt = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="S")
    # sr will send the list of packets (one per dport) and return answered/unanswered
    ans, unans = sr(pkt, timeout=timeout)

    open_ports = set()
    for sent, received in ans:
        if received.haslayer(TCP):
            rflags = int(received.getlayer(TCP).flags)
            # SYN-ACK -> port open
            if (rflags & 0x12) == 0x12:
                dport = sent.getlayer(TCP).dport
                open_ports.add(dport)
                # send RST to be polite
                try:
                    from scapy.all import send
                    rst = IP(dst=host) / TCP(dport=dport, sport=sent.getlayer(TCP).sport, flags="R")
                    send(rst, verbose=0)
                except Exception:
                    pass
    return open_ports


def parse_port_spec(host: str, spec: str, timeout: float = 1.0) -> List[int]:
    if not isinstance(spec, str):
        raise TypeError("port specification must be a string")

    ports_set: Set[int] = set()
    tokens = [t.strip() for t in spec.split(',') if t.strip() != ""]

    if not tokens:
        raise ValueError("empty port specification")

    for token in tokens:
        # Range case
        if '-' in token:
            # allow only one dash; reject multiple dashes
            if token.count('-') != 1:
                raise ValueError(f"invalid range token '{token}': too many '-' characters")
            left, right = token.split('-')
            left = left.strip()
            right = right.strip()
            if left == "" or right == "":
                raise ValueError(f"invalid range token '{token}': missing start or end")
            if not (left.isdigit() and right.isdigit()):
                raise ValueError(f"invalid range token '{token}': start/end must be integers")
            start = int(left)
            end = int(right)
            if start > end:
                raise ValueError(f"invalid range '{token}': start ({start}) > end ({end})")
            if start < MIN_PORT or end > MAX_PORT:
                raise ValueError(f"range '{token}' out of valid port bounds {MIN_PORT}-{MAX_PORT}")
            # add inclusive range
            for p in range(start, end + 1):
                ports_set.add(p)
        else:
            # Single port case
            if not token.isdigit():
                raise ValueError(f"invalid port token '{token}': must be an integer")
            p = int(token)
            if p < MIN_PORT or p > MAX_PORT:
                raise ValueError(f"port {p} out of valid bounds {MIN_PORT}-{MAX_PORT}")
            ports_set.add(p)

    # Sort and return
    sorted_ports = sorted(ports_set)
    open_ports = syn_scan_ports_batch(host, sorted_ports, timeout=timeout)
    return open_ports


# Small command-line example showing how to use the parser.
def main():
    parser = argparse.ArgumentParser(description="port_scan argument parser demo (parses port ranges)")
    parser.add_argument("host", help="Target host/IP (example: 192.168.60.5)")
    parser.add_argument("ports", help='Port spec (example: "1-1024,8080" or "22,80,1000-2000")')
    args = parser.parse_args()

    try:
        ports = parse_port_spec(args.host, args.ports)
    except Exception as e:
        parser.error(f"invalid port specification: {e}")

    # For demo, print summary rather than huge output
    print(f"Host: {args.host}")
    print(f"Parsed {len(ports)} ports.")
    if len(ports) <= 100:
        print("Ports:", ports)
    else:
        print(f"First 5 ports: {ports[:5]}")
        print(f"Last 5 ports: {ports[-5:]}")
        print(f"Example contains 8080? {'8080' in map(str, ports)}")  # just an example check


if __name__ == "__main__":
    main()
    
#docker is 172.17.0.1

