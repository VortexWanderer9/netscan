# netscan

A dependency-free Python terminal network scanner for authorized testing. It supports host discovery, TCP and UDP probes, service banners, lightweight OS/MAC hints, exports, reusable profiles, and scan diffs.

## Requirements

- Python 3.7+
- `ping` on the system `PATH` for host discovery
- Linux `/proc/net/arp` is used for MAC/vendor hints when available

## Commands

```bash
python3 netscan.py hosts 192.168.1.0/24
python3 netscan.py ports 192.168.1.10 --ports common
python3 netscan.py ports 192.168.1.10 --protocol udp --ports 53,123,161
python3 netscan.py quick 192.168.1.0/24 --ports 22,80,443
python3 netscan.py watch 192.168.1.10 --ports common --interval 30
```

Host results include reverse DNS, ping TTL with a rough OS guess, and ARP MAC/vendor data. Open TCP ports receive a small banner probe, including an HTTP `HEAD` request. UDP probes currently cover DNS, NTP, and SNMP; an unanswered UDP probe is reported as closed/filtered rather than definitively closed.

Common options for scans:

- `--output results.json` or `--output results.csv` — export structured records.
- `--delay SECONDS` — delay between probes per worker.
- `--threads N` and `--timeout SECONDS` — control concurrency and probe timeouts.
- `--no-color` — disable ANSI output colors.
- `ports --no-banner` — skip TCP banner grabbing.

`quick` discovers live hosts and scans every result automatically. `watch` repeats a port or host scan and prints only additions/removals after the first pass.

## Saved profiles

Create `.netscan.yaml` with simple named sections:

```yaml
office:
  target: 192.168.1.10
  ports: 22,80,443
  protocol: tcp
  timeout: 0.5
  threads: 50
  delay: 0.02
  output: office.json
```

Run it with:

```bash
python3 netscan.py profile office
```

The profile reader intentionally supports this small YAML subset and has no third-party dependency. Use `mode: hosts` with `cidr:` for a saved host discovery profile.

## Safety

Only scan networks and hosts you own or have explicit permission to test. Scanning devices or networks you do not control may be illegal or against their terms of service. The vulnerability hints are simple exposure warnings, not CVE detection.
