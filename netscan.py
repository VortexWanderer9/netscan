#!/usr/bin/env python3
"""netscan - a small, dependency-free network scanner.

Only scan networks and hosts you own or have explicit permission to test.
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import queue
import re
import socket
import subprocess
import sys
import threading
import time

BANNER = "netscan - local network scanner"
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
COMMON_OUIS = {"001c42": "Parallels", "3c5a37": "Apple", "b827eb": "Raspberry Pi",
               "dca632": "Raspberry Pi", "00155d": "Microsoft Hyper-V",
               "000c29": "VMware", "080027": "VirtualBox"}
print_lock = threading.Lock()


def color(text, code, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text


def log(message):
    with print_lock:
        print(message, flush=True)


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                low, high = (int(value) for value in part.split("-", 1))
                ports.update(range(low, high + 1))
            else:
                ports.add(int(part))
        except ValueError as exc:
            raise ValueError(f"invalid port specification '{part}'") from exc
    return sorted(port for port in ports if 0 < port <= 65535)


def guess_os(ttl):
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "Linux/Unix (likely)"
    if ttl <= 128:
        return "Windows (likely)"
    return "Network device/macOS (likely)"


def arp_lookup(ip):
    try:
        with open("/proc/net/arp", encoding="ascii") as arp_file:
            for line in arp_file.readlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                    mac = fields[3].lower()
                    vendor = COMMON_OUIS.get(mac.replace(":", "")[:6], "Unknown")
                    return mac, vendor
    except (OSError, UnicodeError):
        pass
    return "", "Unknown"


def ping_host(ip, timeout_s=1.0):
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_s + 1)
        match = re.search(r"(?:ttl|TTL)[= :]([0-9]+)", result.stdout + result.stderr)
        ttl = int(match.group(1)) if match else None
        return result.returncode == 0, ttl
    except (OSError, subprocess.SubprocessError):
        return False, None


def progress(done, total):
    with print_lock:
        print(f"\r  Scanned {done}/{total} hosts", end="", flush=True)


def scan_hosts(cidr, timeout_s, max_threads, delay=0.0, colors=True):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid network '{cidr}': {exc}") from exc
    hosts = list(network.hosts()) or [network.network_address]
    print(f"\nScanning {len(hosts)} hosts on {cidr} ...")
    work = queue.Queue()
    for host in hosts:
        work.put(str(host))
    found, lock = [], threading.Lock()
    completed = 0

    def worker():
        nonlocal completed
        while True:
            try:
                ip = work.get_nowait()
            except queue.Empty:
                return
            alive, ttl = ping_host(ip, timeout_s)
            if alive:
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    name = ""
                mac, vendor = arp_lookup(ip)
                record = {"ip": ip, "hostname": name, "ttl": ttl, "os_guess": guess_os(ttl),
                          "mac": mac, "vendor": vendor}
                with lock:
                    found.append(record)
                log("  [+] " + color(f"{ip} is up", "32", colors) +
                    (f" ({name})" if name else "") + f"  TTL={ttl or '?'}  OS={record['os_guess']}" +
                    (f"  MAC={mac} ({vendor})" if mac else ""))
            with lock:
                completed += 1
                progress(completed, len(hosts))
            if delay:
                time.sleep(delay)
            work.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, max_threads))]
    started = time.time()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    print()
    found.sort(key=lambda record: ipaddress.ip_address(record["ip"]))
    print(f"{len(found)} host(s) up. Scan took {time.time() - started:.2f}s.\n")
    return found


def banner_grab(sock, port, timeout_s):
    sock.settimeout(min(timeout_s, 1.5))
    try:
        if port in (80, 8080, 8000, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        elif port in (53, 123, 161):
            return COMMON_PORTS[port]
        data = sock.recv(256)
        return data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()[:160]
    except (OSError, socket.timeout):
        return ""


def udp_probe(ip, port, timeout_s):
    probes = {53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
              123: b"\x1b" + b"\0" * 47,
              161: bytes.fromhex("302602010104067075626c6963a01902046d736700000000000000000000000000000000000000000000")}
    if port not in probes:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        sock.sendto(probes[port], (ip, port))
        sock.recvfrom(2048)
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()


def risk_hint(port, banner):
    if port == 23:
        return "risky: Telnet transmits credentials in plaintext"
    if port == 445 and "smb1" in banner.lower():
        return "risky: SMBv1 appears enabled"
    if port == 3389:
        return "review: RDP exposed; verify authentication and network access"
    return ""


def scan_ports(target, ports, timeout_s, max_threads, protocol="tcp", delay=0.0, colors=True, banners=True):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host: {target}") from exc
    print(f"\nScanning {ip} ({target}) - {len(ports)} {protocol.upper()} port(s) ...")
    work = queue.Queue()
    for port in ports:
        work.put(port)
    results, lock = [], threading.Lock()

    def worker():
        while True:
            try:
                port = work.get_nowait()
            except queue.Empty:
                return
            sock = None
            is_open, banner = False, ""
            try:
                if protocol == "udp":
                    is_open = udp_probe(ip, port, timeout_s)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout_s)
                    is_open = sock.connect_ex((ip, port)) == 0
                    if is_open and banners:
                        banner = banner_grab(sock, port, timeout_s)
                if is_open:
                    service = COMMON_PORTS.get(port, "unknown")
                    record = {"target": target, "ip": ip, "port": port, "protocol": protocol,
                              "service": service, "banner": banner, "risk": risk_hint(port, banner)}
                    with lock:
                        results.append(record)
                    suffix = f"  {banner}" if banner else ""
                    if record["risk"]:
                        suffix += "  " + color("[!] " + record["risk"], "33", colors)
                    log(f"  [+] {port}/{protocol}  " + color("open", "32", colors) +
                        f"  {service}{suffix}")
            except OSError:
                pass
            finally:
                if sock:
                    sock.close()
                work.task_done()
            if delay:
                time.sleep(delay)

    started = time.time()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, max_threads))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    results.sort(key=lambda record: record["port"])
    print(f"\n{len(results)} open {protocol.upper()} port(s) found. Scan took {time.time() - started:.2f}s.\n")
    return results


def export_results(records, path):
    if path.lower().endswith(".csv"):
        fields = sorted({key for record in records for key in record})
        with open(path, "w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)
    else:
        with open(path, "w", encoding="utf-8") as output:
            json.dump(records, output, indent=2)
            output.write("\n")
    print(f"Saved {len(records)} result(s) to {path}")


def diff_records(previous, current):
    def key(record):
        return (record.get("ip", record.get("target")), record.get("protocol"), record.get("port"))
    old = {key(record): record for record in previous}
    new = {key(record): record for record in current}
    return [record for item, record in new.items() if item not in old], [record for item, record in old.items() if item not in new]


def load_profile(path, name):
    """Parse the small profile format without requiring PyYAML."""
    if not os.path.exists(path):
        return {}
    profiles, current, values = {}, None, {}
    with open(path, encoding="utf-8") as source:
        for raw in source:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not raw.startswith(" ") and line.endswith(":"):
                current = line[:-1].strip()
                values = profiles.setdefault(current, {})
            elif current and ":" in line:
                key, value = line.split(":", 1)
                values[key.strip()] = value.strip().strip("'\"")
    return profiles.get(name, {})


def add_common_options(parser):
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between probes per worker")
    parser.add_argument("--output", help="write results to .json or .csv")
    parser.add_argument("--no-color", action="store_true")


def run_once(args, profile=None):
    profile = profile or {}
    ports_spec = args.ports
    if ports_spec == "profile":
        ports_spec = profile.get("ports", "common")
    ports = sorted(COMMON_PORTS) if ports_spec.lower() == "common" else parse_ports(ports_spec)
    return scan_ports(args.target, ports, args.timeout, args.threads, args.protocol, args.delay,
                      not args.no_color, not args.no_banner)


def main():
    parser = argparse.ArgumentParser(description=BANNER)
    sub = parser.add_subparsers(dest="command", required=True)
    hosts = sub.add_parser("hosts", help="discover live hosts")
    hosts.add_argument("cidr")
    hosts.add_argument("--timeout", type=float, default=1.0)
    hosts.add_argument("--threads", type=int, default=100)
    hosts.add_argument("--delay", type=float, default=0.0)
    hosts.add_argument("--output")
    hosts.add_argument("--no-color", action="store_true")
    ports = sub.add_parser("ports", help="scan TCP or UDP ports")
    ports.add_argument("target")
    ports.add_argument("--ports", default="1-1024")
    ports.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    ports.add_argument("--no-banner", action="store_true")
    add_common_options(ports)
    quick = sub.add_parser("quick", help="discover hosts, then scan each host")
    quick.add_argument("cidr")
    quick.add_argument("--ports", default="common")
    quick.add_argument("--timeout", type=float, default=0.5)
    quick.add_argument("--threads", type=int, default=100)
    quick.add_argument("--delay", type=float, default=0.0)
    quick.add_argument("--output")
    quick.add_argument("--no-color", action="store_true")
    watch = sub.add_parser("watch", help="repeat a host or port scan and print changes")
    watch.add_argument("target")
    watch.add_argument("--interval", type=float, default=30.0)
    watch.add_argument("--mode", choices=("hosts", "ports"), default="ports")
    watch.add_argument("--ports", default="common")
    watch.add_argument("--timeout", type=float, default=0.5)
    watch.add_argument("--threads", type=int, default=100)
    watch.add_argument("--delay", type=float, default=0.0)
    watch.add_argument("--no-color", action="store_true")
    config = sub.add_parser("profile", help="run a saved profile from .netscan.yaml")
    config.add_argument("name")
    config.add_argument("--config", default=".netscan.yaml")

    args = parser.parse_args()
    print(BANNER)
    if args.command == "hosts":
        records = scan_hosts(args.cidr, args.timeout, args.threads, args.delay, not args.no_color)
        if args.output:
            export_results(records, args.output)
    elif args.command == "ports":
        records = run_once(args)
        if args.output:
            export_results(records, args.output)
    elif args.command == "quick":
        hosts_found = scan_hosts(args.cidr, args.timeout, args.threads, args.delay, not args.no_color)
        records = []
        for host in hosts_found:
            port_args = argparse.Namespace(**vars(args), target=host["ip"], protocol="tcp", no_banner=False)
            records.extend(run_once(port_args))
        if args.output:
            export_results(records, args.output)
    elif args.command == "watch":
        previous = []
        while True:
            if args.mode == "hosts":
                current = scan_hosts(args.target, args.timeout, args.threads, args.delay, not args.no_color)
            else:
                ports_to_scan = parse_ports(args.ports) if args.ports != "common" else sorted(COMMON_PORTS)
                current = scan_ports(args.target, ports_to_scan, args.timeout, args.threads, "tcp", args.delay, not args.no_color)
            added, removed = diff_records(previous, current)
            for record in added:
                log(color(f"  [+] changed: {record}", "32", not args.no_color))
            for record in removed:
                log(color(f"  [-] changed: {record}", "31", not args.no_color))
            previous = current
            time.sleep(args.interval)
    elif args.command == "profile":
        values = load_profile(args.config, args.name)
        if not values:
            raise ValueError(f"profile '{args.name}' not found in {args.config}")
        target = values.get("target") or values.get("cidr")
        if not target:
            raise ValueError("profile needs target or cidr")
        if values.get("mode", "ports") == "hosts":
            records = scan_hosts(target, float(values.get("timeout", 1)), int(values.get("threads", 100)))
        else:
            port_args = argparse.Namespace(target=target, ports=values.get("ports", "common"), protocol=values.get("protocol", "tcp"),
                                           timeout=float(values.get("timeout", 0.5)), threads=int(values.get("threads", 100)),
                                           delay=float(values.get("delay", 0)), no_color=False, no_banner=False)
            records = run_once(port_args, values)
        if values.get("output"):
            export_results(records, values["output"])


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, ValueError) as exc:
        print(f"\n{exc}", file=sys.stderr)
        sys.exit(1)
