# Network Batch Scanners

A set of interactive Python tools for high-volume network scanning:

- `CIDR_Scanner.py`: TCP scan of IPv4 IPs and CIDR ranges, with CIDR normalization, expansion, and sampling.
- `ICMP_SCANNER.py`: Concurrent ICMP (ping) scanner from a text list of IPs, with resume support.
- `TCP_SCANNER.py`: Concurrent TCP port scanner from a text list of IPs, across one or more ports.

All tools are designed for long-running, resumable scans with batching, progress display, and multiple output formats.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
  - [CIDR scanner](#cidr-scanner)
  - [ICMP scanner](#icmp-scanner)
  - [TCP scanner](#tcp-scanner)
- [Input formats](#input-formats)
- [Outputs](#outputs)
- [CLI options & prompts](#cli-options--prompts)
- [Performance tips](#performance-tips)
- [Safety & legal](#safety--legal)
- [License](#license)

---

## Features

- **High-throughput scanning** using Python’s `ThreadPoolExecutor` and tuneable worker counts for all scripts.
- **Batching and progress bars** so you can control how much work is done per run and see live progress.
- **Resume and skip logic** for ICMP/TCP scanners via state files and CSV history, so you can stop/restart without losing work.
- **Rich outputs**: human-readable `.txt`, structured `.csv`, and line-delimited `.jsonl` for easy post-processing.
- **CIDR-aware target handling**: expand IPv4 CIDRs, sample a single host per CIDR, or cap large CIDRs to a fixed number of targets.
- **Host-based CIDR normalization**: entries such as `52.1.1.1/15` are accepted and normalized to their enclosing network with `ipaddress.ip_network(..., strict=False)`.[web:1][web:52]
- **Large CIDR cap strategy**: when a CIDR is larger than the configured per-CIDR limit in all-host mode, the scanner can select targets either sequentially or randomly instead of rejecting the CIDR.[web:34][web:1]
- **Interactive configuration**: timeouts, batch size, worker count, scan order (sequential/randomized), CIDR expansion mode, and oversized-CIDR selection mode are prompted at runtime.

---

## Requirements

- Python 3.8+.
- Standard library only (no external dependencies): `csv`, `ipaddress`, `json`, `socket`, `concurrent.futures`, etc.
- For `ICMP_SCANNER.py`, raw socket permissions are required (e.g., root on Linux or Administrator on Windows).

---

## Quick start

### General clone & run

```bash
git clone [https://github.com/alireza129/TCP-ICMP-CIDR-IP-scanners-python.git](https://github.com/alireza129/TCP-ICMP-CIDR-IP-scanners-python.git)
cd TCP-ICMP-CIDR-IP-scanners-python

# Make scripts executable (optional on Unix)
chmod +x CIDR_Scanner.py ICMP_SCANNER.py TCP_SCANNER.py
```

Create an input file (examples in [Input formats](#input-formats)), then run the tool you need.

---

### CIDR scanner

`CIDR_Scanner.py` takes a text file of IPv4 single IPs and/or CIDR ranges, normalizes host-based CIDRs, expands them (or samples per range), and tests a single TCP port using concurrent connect attempts.[web:1][web:52]

Run:

```bash
python3 CIDR_Scanner.py
```

Interactive prompts (you’ll see these in order):

- `Path to txt file with IPs or CIDRs:` path to input list.
- `Port to test (e.g. 80 or 443) [default=443]:` TCP port to scan.
- `TCP connect timeout in seconds [default=2.0]:` per-connection timeout.
- `Batch size [default=256]:` how many targets to process per batch.
- `Worker count [default=128]:` maximum concurrent connections.
- `Max targets to scan per CIDR in all-host mode [default=65536]:` per-CIDR cap for all-host mode; small CIDRs are fully expanded, while larger CIDRs are capped to this number of targets.
- `Scan order - sequential or randomized? [s/r, default=r]:` order of final targets.
- `CIDR target mode - all hosts or one sample per CIDR? [a/o, default=o]:` choose whether each CIDR contributes one target or up to the configured per-CIDR cap.
- If all-host mode is selected: `When a CIDR exceeds the per-CIDR target cap, choose targets sequentially or randomly? [s/r, default=r]:` choose whether oversized CIDRs contribute the first N usable hosts or a random subset of N hosts.[web:34][web:1]
- After each batch: `Continue after batch X/Y? [Y/n or number of more batches]:` allows early stop or automatic continuation.

Behavior notes:

- CIDRs with host bits set are accepted and normalized automatically, so input like `52.1.1.1/15` is valid and is treated as the enclosing network instead of being rejected.[web:1][web:52]
- In **sample** mode, the scanner selects one target per CIDR.
- In **all-host** mode, the scanner:
  - scans all usable hosts if the CIDR is at or below the configured cap,
  - otherwise scans up to the configured cap using either sequential or random selection.[web:34][web:1]
- `/31` and `/32` ranges are handled explicitly so they still produce scan targets even though `hosts()` has special edge-case behavior for small masks.[web:1][web:7]

Outputs:

- `open_ips.txt`: one IP per line with the port open.
- `open_ips.csv`: `IP, Ping (ms), Port, Source Range`.

---

### ICMP scanner

`ICMP_SCANNER.py` sends ICMP echo requests (ping) to a list of IPv4 addresses and records latency and status.

Run:

```bash
sudo python3 ICMP_SCANNER.py
# or run as Administrator on Windows
```

Interactive prompts:

- `Path to txt file with IPs:` input file of IPs.
- `Output filename base (example: icmp_results):` base name for `.txt`, `.csv`, `.jsonl`, and state files.
- `Timeout in seconds [default=1.5]:` ICMP reply timeout.
- `Retry count [default=0]:` additional attempts per host.
- `Batch size:` number of IPs per batch.
- `Worker count:` number of concurrent workers.
- `Scan mode - sequential or randomized? [s/r, default=r]:` host order.
- `Skip already-scanned IPs from previous run? [Y/n]:` avoid re-scanning existing entries from CSV.
- `Resume from saved progress if state exists? [Y/n]:` continue from last offset using a `.state.json` file.
- `How many batches do you want to do right now? [default=1]:` control amount of work per run, repeated between batches.

Outputs (for base `icmp_results`):

- `icmp_results.txt`: list of IPs that responded successfully.
- `icmp_results.csv`: `timestamp, ip, status, latency_ms, error, attempts`.
- `icmp_results.jsonl`: one JSON object per line with the same fields.
- `icmp_results.state.json`: contains a simple `offset` used for resuming.

---

### TCP scanner

`TCP_SCANNER.py` takes a list of IPv4 IPs (no CIDR expansion) and scans one or more TCP ports concurrently.

Run:

```bash
python3 TCP_SCANNER.py
```

Interactive prompts:

- `Path to txt file with IPs:` input file of IPs.
- `Output filename base (example: tcp_results):` base name for outputs.
- `Timeout in seconds [default=1.5]:` TCP connect timeout.
- `Retry count [default=0]:` retries per IP:port.
- `Batch size:` number of IPs per batch (each batch expands to IP×ports tasks).
- `Worker count:` maximum concurrent connections.
- `TCP ports to test (example: 80 or 80,443,22):` comma-separated list of ports, validated and deduplicated.
- `Scan mode - sequential or randomized? [s/r, default=r]:` order of IPs.
- `Skip already-scanned IP:PORT entries from previous run? [Y/n]:` uses CSV history to skip completed pairs.
- `Resume from saved progress if state exists? [Y/n]:` uses a `.state.json` offset.
- `How many batches do you want to do right now? [default=1]:` controls work per run, repeated between batches.

Outputs (for base `tcp_results`):

- `tcp_results.txt`: `ip:port` for successful connections.
- `tcp_results.csv`: `timestamp, ip, port, status, latency_ms, error, attempts`.
- `tcp_results.jsonl`: JSONL version of the same rows.
- `tcp_results.state.json`: resume state with `offset`.

---

## Input formats

### CIDR scanner input

Text file containing IPv4 single IPs and/or CIDR ranges, one per line.

Example:

```text
# Single hosts
192.168.1.10
10.0.0.5

# CIDR ranges
192.168.0.0/24
10.0.0.0/16

# Host-based CIDR is also accepted and normalized
52.1.1.1/15
```

Notes:

- Comments (`# ...`) and blank lines are ignored.
- Host-based CIDRs are accepted and normalized automatically with `strict=False`, so the typed address does not need to be the exact network boundary.[web:1][web:52]
- IPv6 entries are skipped and reported as invalid.
- In all-host mode, large CIDRs are no longer necessarily rejected; instead they can be capped to the configured number of selected targets per CIDR.[web:34][web:1]

### ICMP/TCP scanner input

Text file with IPv4 addresses, separated by newlines or commas; quotes are stripped and duplicates removed.

Example:

```text
192.168.1.10
192.168.1.11, 192.168.1.12
"8.8.8.8"
```

---

## Outputs

The tools are designed to support both manual inspection and automated post-processing.

| Script            | Success TXT                           | CSV columns                                 | JSONL fields                             |
|-------------------|---------------------------------------|---------------------------------------------|------------------------------------------|
| `CIDR_Scanner.py` | `open_ips.txt` (one IP per line)      | `IP, Ping (ms), Port, Source Range`         | Not generated by this script             |
| `ICMP_SCANNER.py` | `<base>.txt` (IP per successful ping) | `timestamp, ip, status, latency_ms, error`  | Same as CSV plus any additional metadata |
| `TCP_SCANNER.py`  | `<base>.txt` (`ip:port` per success)  | `timestamp, ip, port, status, latency_ms`   | Same as CSV plus any additional metadata |

You can post-process the CSV/JSONL files with your own scripts, `pandas`, or command-line tools like `jq` and `csvkit`.

---

## CLI options & prompts

All three tools are fully interactive and will ask for:

- Target file path (IPs or CIDRs depending on script).
- Network timing: timeouts and optional retry counts.
- Concurrency controls: batch size and worker count.
- Scan order: sequential vs randomized, where supported.
- Persistence: whether to resume from a saved state and/or skip already-scanned entries.
- Work chunking: how many batches to run in the current session.

`CIDR_Scanner.py` additionally asks how CIDRs should be handled:

- One sample per CIDR vs all-host mode.
- Maximum targets to scan per CIDR in all-host mode.
- For oversized CIDRs, whether the selected targets should be the first N sequentially or a random subset of N.[web:34][web:1]

Defaults are sensible for moderate scans, but you should adjust them based on your network size and host performance.

---

## Performance tips

- Start with a **small batch size** and **lower worker count** to verify connectivity and correctness before scaling up.
- Increase workers and batch size gradually, watching for timeouts or connection errors.
- Use randomized scan order if you want to distribute load more evenly across targets.
- For very large CIDRs in `CIDR_Scanner.py`, use a smaller per-CIDR cap first to validate behavior before scanning broader subsets.
- Use sequential oversized-CIDR selection if you want deterministic coverage and random selection if you want broader distribution across large ranges.[web:34]
- For very large scans, use the “skip already scanned” and “resume” options to spread the work across multiple sessions.

---

## Safety & legal

These tools are intended for **authorized security testing and network inventory** on systems you own or have explicit permission to scan.

- Do not scan networks or hosts without permission.
- Be aware that aggressive scanning can trigger IDS/IPS systems or rate-limiting.
- Always comply with local laws, your organization’s policies, and the terms of service of any networks you interact with.

---

## License

This project is licensed under the **GNU General Public License (GPL)**.  
See the `LICENSE` file for the full license text.
