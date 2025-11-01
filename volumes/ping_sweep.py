#!/usr/bin/env python3
# ping_sweep.py
# Usage:
#   sudo python3 ping_sweep.py 192.168.60.0/24
#   sudo python3 ping_sweep.py 192.168.60.0/24 --end 192.168.60.11

import argparse
import ipaddress
import subprocess
from port_find import *
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping(ip):
    """Return True if host replies to a single ICMP ping. Uses system ping."""
    # -c 1 : one packet, -W 1 : timeout 1s (Linux)
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return (str(ip), r.returncode == 0)
    except Exception:
        return (str(ip), False)

def sweep(network, end_ip=None, workers=100):
    hosts = []
    net = ipaddress.ip_network(network, strict=False)
    # list of host IPs to test (skips network & broadcast automatically with .hosts())
    all_hosts = list(net.hosts())

    if end_ip:
        # truncate host list up to and including end_ip if present
        end = ipaddress.ip_address(end_ip)
        truncated = []
        for h in all_hosts:
            truncated.append(h)
            if h == end:
                break
        all_hosts = truncated

    print(f"[+] Scanning {len(all_hosts)} addresses in {net} ...")

    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = { ex.submit(ping, ip): ip for ip in all_hosts }
        for fut in as_completed(futures):
            ip, alive = fut.result()
            if alive:
                print(f"[+] {ip} is up")
                results.append(ip)
    return results

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cidr", help="CIDR network (e.g., 192.168.60.0/24)")
    p.add_argument("--end", help="optional highest IP to probe (e.g., 192.168.60.11)")
    p.add_argument("--workers", type=int, default=100, help="concurrency")
    args = p.parse_args()

    alive = sweep(args.cidr, end_ip=args.end, workers=args.workers)
    print("\n=== Live hosts ===")
    for a in sorted(alive, key=ipaddress.ip_address):
        print(a)
    if alive:
        highest = max(alive, key=lambda s: ipaddress.ip_address(s))
        print(f"\nHighest live IP found: {highest}")
else:
    print("\nNo hosts replied.")

    ips_to_scan = alive
    results = run_port_scan_for_ips(ips_to_scan, timeout=30, max_workers=2)
    for ip, (rc, out, err, err_msg) in results.items():
        print(f"\n--- {ip} (rc={rc}) ---")
        if err_msg:
            print("ERROR:", err_msg)
        if out.strip():
            print("STDOUT:\n", out.strip())
        if err.strip():
            print("STDERR:\n", err.strip())
