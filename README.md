# netscan

A simple, dependency-free Python terminal tool for local network scanning:
host discovery (ping sweep) and TCP port scanning.

```
 _   _ _____ _____ ____   ____ _    _   _
| \ | | ____|_   _/ ___| / ___/ \  | \ | |
|  \| |  _|   | | \___ \| |   / _ \ |  \| |
| |\  | |___  | |  ___) | |__/ ___ \| |\  |
|_| \_|_____| |_| |____/ \____/_/   \_\_| \_|

```

## Requirements

- Python 3.7+
- No third-party packages — uses only the standard library
- `ping` available on your system PATH (pre-installed on macOS/Linux/Windows)

## Install

Nothing to install. Just download `netscan.py` and run it with Python.

```bash
python3 netscan.py --help
```

## Usage

### 1. Discover live hosts on a subnet

```bash
python3 netscan.py hosts 192.168.1.0/24
```

Options:
- `--timeout SECONDS` — ping timeout per host (default: 1.0)
- `--threads N` — concurrent threads (default: 100)

### 2. Scan TCP ports on a host

```bash
python3 netscan.py ports 192.168.1.10
```

By default this scans ports 1–1024. Other ways to specify ports:

```bash
python3 netscan.py ports 192.168.1.10 --ports 1-1024
python3 netscan.py ports 192.168.1.10 --ports 22,80,443
python3 netscan.py ports 192.168.1.10 --ports common   # well-known service ports only
python3 netscan.py ports scanme.nmap.org --ports 1-1000
```

Options:
- `--timeout SECONDS` — TCP connect timeout per port (default: 0.5)
- `--threads N` — concurrent threads (default: 200)

## Example output

```
Scanning 192.168.1.10 (192.168.1.10) — 1024 port(s) ...

  [+] 22/tcp   open   SSH
  [+] 80/tcp   open   HTTP
  [+] 443/tcp  open   HTTPS

3 open port(s) found. Scan took 1.84s.
```

## How it works

- **Host discovery** shells out to the system `ping` command once per address
  in the given CIDR range, threaded for speed, and resolves reverse DNS names
  when available.
- **Port scanning** attempts a raw TCP connect (`connect_ex`) to each port in
  the given range/list, threaded for speed, and labels well-known ports
  (SSH, HTTP, HTTPS, SMB, RDP, MySQL, etc.) using a small built-in lookup
  table.

## Responsible use

Only scan networks and hosts you own or have explicit permission to test.
Scanning devices or networks you don't control may be illegal or against
their terms of service.

## License

Use, modify, and share freely.
