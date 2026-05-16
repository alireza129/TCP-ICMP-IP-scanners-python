# Network Batch Scanners

A set of interactive Python tools for high‑volume network scanning:

- `CIDR_Scanner.py`: TCP scan of IPv4 IPs and CIDR ranges, with CIDR expansion and sampling.
- `ICMP_SCANNER.py`: Concurrent ICMP (ping) scanner from a text list of IPs, with resume support.
- `TCP_SCANNER.py`: Concurrent TCP port scanner from a text list of IPs, across one or more ports.

All tools are designed for long‑running, resumable scans with batching, progress display, and multiple output formats.

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

- **High‑throughput scanning** using Python’s `ThreadPoolExecutor` and tuneable worker counts for all scripts.
- **Batching and progress bars** so you can control how much work is done per run and see live progress.
- **Resume and skip logic** for ICMP/TCP scanners via state files and CSV history, so you can stop/restart without losing work.
- **Rich outputs**: human‑readable `.txt`, structured `.csv`, and line‑delimited `.jsonl` for easy post‑processing.
- **CIDR‑aware target handling**: expand IPv4 CIDRs or sample a single host per range, with duplicate and IPv6 filtering.
- **Interactive configuration**: timeouts, retries, batch size, worker count, scan order (sequential/randomized), and more are prompted at runtime.

---

## Requirements

- Python 3.8+.
- Standard library only (no external dependencies): `csv`, `ipaddress`, `json`, `socket`, `concurrent.futures`, etc.
- For `ICMP_SCANNER.py`, raw socket permissions are required (e.g., root on Linux or Administrator on Windows).

---

## Quick start

### General clone & run

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# Make scripts executable (optional on Unix)
chmod +x CIDR_Scanner.py ICMP_SCANNER.py TCP_SCANNER.py
```

Create an input file (examples in [Input formats](#input-formats)), then run the tool you need.

---

### CIDR scanner

`CIDR_Scanner.py` takes a text file of IPv4 single IPs and/or CIDR ranges, expands them (or samples per range), and tests a single TCP port using concurrent connect attempts.

Run:

```bash
python3 CIDR_Scanner.py
```

Interactive prompts (you’ll see these in order):

- `Path to txt file with IPs or CIDRs:` path to input list.
- `Port to test (e.g. 80 or 443) [default=443]:` TCP port to scan.
- `TCP connect timeout in seconds [default=2.0]:` per‑connection timeout.
- `Batch size [default=256]:` how many targets to process per batch.
- `Worker count [default=128]:` maximum concurrent connections.
- `Max hosts per CIDR for all-host mode [default=65536]:` safety limit for CIDR expansion.
- `Scan order - sequential or randomized? [s/r, default=r]:` order of targets.
- `CIDR target mode - all hosts or one sample per CIDR? [a/o, default=o]:` expand all hosts or sample a single host.
- After each batch: `Continue after batch X/Y? [Y/n or number of more batches]:` allows early stop or automatic continuation.

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
- `Skip already-scanned IPs from previous run? [Y/n]:` avoid re‑scanning existing entries from CSV.
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
- `TCP ports to test (example: 80 or 80,443,22):` comma‑separated list of ports, validated and deduplicated.
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
```

Notes:

- Comments (`# ...`) and blank lines are ignored.
- IPv6 entries and overly large CIDRs (in all‑hosts mode) are skipped and reported as invalid.

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

The tools are designed to support both manual inspection and automated post‑processing.

| Script            | Success TXT                           | CSV columns                                 | JSONL fields                                      |
|-------------------|---------------------------------------|---------------------------------------------|---------------------------------------------------|
| `CIDR_Scanner.py` | `open_ips.txt` (one IP per line)      | `IP, Ping (ms), Port, Source Range`         | Same fields as CSV per JSON object                |
| `ICMP_SCANNER.py` | `<base>.txt` (IP per successful ping) | `timestamp, ip, status, latency_ms, error`  | Same as CSV plus any additional metadata          |
| `TCP_SCANNER.py`  | `<base>.txt` (`ip:port` per success)  | `timestamp, ip, port, status, latency_ms`   | Same as CSV plus any additional metadata          |

You can post‑process the CSV/JSONL files with your own scripts, `pandas`, or command‑line tools like `jq` and `csvkit`.

---

## CLI options & prompts

All three tools are fully interactive and will ask for:

- Target file path (IPs or CIDRs depending on script).
- Network timing: timeouts and optional retry counts.
- Concurrency controls: batch size and worker count.
- Scan order: sequential vs randomized, where supported.
- Persistence: whether to resume from a saved state and/or skip already‑scanned entries.
- Work chunking: how many batches to run in the current session.

Defaults are sensible for moderate scans, but you should adjust them based on your network size and host performance.

---

## Performance tips

- Start with a **small batch size** and **lower worker count** to verify connectivity and correctness before scaling up.
- Increase workers and batch size gradually, watching for timeouts or connection errors.
- Use randomized scan order if you want to distribute load more evenly across targets.
- For very large scans, use the “skip already scanned” and “resume” options to spread the work across multiple sessions.

---

## Safety & legal

These tools are intended for **authorized security testing and network inventory** on systems you own or have explicit permission to scan.

- Do not scan networks or hosts without permission.
- Be aware that aggressive scanning can trigger IDS/IPS systems or rate‑limiting.
- Always comply with local laws, your organization’s policies, and the terms of service of any networks you interact with.

---

## License

This project is licensed under the **GNU General Public License (GPL)**.  
See the `LICENSE` file for the full license text.
