#!/usr/bin/env python3
"""
netscan.py - a simple local network scanning tool.

Features:
  - Host discovery on a subnet (ping sweep)
  - TCP port scan on a target host (with common port presets)
  - Basic service name guessing from port numbers
  - Threaded for speed, with clean CLI output

Usage:
  python3 netscan.py hosts 192.168.1.0/24
  python3 netscan.py ports 192.168.1.10
  python3 netscan.py ports 192.168.1.10 --ports 1-1024
  python3 netscan.py ports scanme.nmap.org --ports 22,80,443

Notes:
  Only scan networks and hosts you own or have explicit permission to test.
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import platform
import threading
import queue
import time

BANNER = r"""
 _   _ _____ _____ ____   ____ _    _   _
| \ | | ____|_   _/ ___| / ___/ \  | \ | |
|  \| |  _|   | | \___ \| |   / _ \ |  \| |
| |\  | |___  | |  ___) | |__/ ___ \| |\  |
|_| \_|_____| |_| |____/ \____/_/   \_\_| \_|

      ln --||__   simple network scanner
"""

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg)


def ping_host(ip: str, timeout_s: float = 1.0) -> bool:
    """Return True if host responds to a single ping."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_s)), str(ip)]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_hosts(cidr: str, timeout_s: float, max_threads: int):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"Invalid network '{cidr}': {e}")
        sys.exit(1)

    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]

    print(f"\nScanning {len(hosts)} hosts on {cidr} ...\n")

    q = queue.Queue()
    for h in hosts:
        q.put(str(h))

    found = []
    found_lock = threading.Lock()

    def worker():
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            if ping_host(ip, timeout_s):
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    name = ""
                with found_lock:
                    found.append((ip, name))
                log(f"  [+] {ip}" + (f"  ({name})" if name else "") + "  is up")
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max_threads)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    found.sort(key=lambda x: ipaddress.ip_address(x[0]))
    print(f"\n{len(found)} host(s) up. Scan took {elapsed:.2f}s.\n")
    return found


def parse_ports(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def scan_ports(target: str, ports, timeout_s: float, max_threads: int):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve host: {target}")
        sys.exit(1)

    print(f"\nScanning {ip} ({target}) — {len(ports)} port(s) ...\n")

    q = queue.Queue()
    for p in ports:
        q.put(p)

    open_ports = []
    open_lock = threading.Lock()

    def worker():
        while True:
            try:
                port = q.get_nowait()
            except queue.Empty:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_s)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = COMMON_PORTS.get(port, "unknown")
                    with open_lock:
                        open_ports.append(port)
                    log(f"  [+] {port}/tcp  open   {service}")
            except Exception:
                pass
            finally:
                sock.close()
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max_threads)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    open_ports.sort()
    print(f"\n{len(open_ports)} open port(s) found. Scan took {elapsed:.2f}s.\n")
    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description="netscan - simple local network scanning tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hosts_p = sub.add_parser("hosts", help="Discover live hosts on a subnet")
    hosts_p.add_argument("cidr", help="Network in CIDR form, e.g. 192.168.1.0/24")
    hosts_p.add_argument("--timeout", type=float, default=1.0, help="Ping timeout in seconds")
    hosts_p.add_argument("--threads", type=int, default=100, help="Max concurrent threads")

    ports_p = sub.add_parser("ports", help="Scan TCP ports on a target host")
    ports_p.add_argument("target", help="IP address or hostname")
    ports_p.add_argument(
        "--ports", default="1-1024",
        help="Ports: '1-1024', '22,80,443', or 'common' (default: 1-1024)",
    )
    ports_p.add_argument("--timeout", type=float, default=0.5, help="Connect timeout in seconds")
    ports_p.add_argument("--threads", type=int, default=200, help="Max concurrent threads")

    args = parser.parse_args()

    print(BANNER)

    if args.command == "hosts":
        scan_hosts(args.cidr, args.timeout, args.threads)
    elif args.command == "ports":
        if args.ports.strip().lower() == "common":
            ports = sorted(COMMON_PORTS.keys())
        else:
            ports = parse_ports(args.ports)
        scan_ports(args.target, ports, args.timeout, args.threads)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
