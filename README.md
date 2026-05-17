# Network Batch Scanners

A set of Python tools for high-volume network scanning:

- `scanner_gui.py`: TCP scan of IPv4 IPs and CIDR ranges with a full dark-themed GUI, streaming CIDR architecture, and real-time KPI dashboard.
- `ICMP_SCANNER.py`: Concurrent ICMP (ping) scanner from a flat IP list, with resume support and multi-format output.

All tools are designed for long-running scans with batching, progress display, and multiple output formats.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [TCP Scanner (GUI)](#tcp-scanner-gui)
  - [ICMP Scanner](#icmp-scanner)
- [Input Formats](#input-formats)
- [Outputs](#outputs)
- [Configuration Reference](#configuration-reference)
- [Performance Tips](#performance-tips)
- [Safety & Legal](#safety--legal)
- [License](#license)

---

## Features

- **High-throughput scanning** using Python's `ThreadPoolExecutor` with tuneable worker counts.
- **Streaming CIDR architecture** in `scanner_gui.py`: CIDRs are never fully expanded into RAM — memory cost is `O(lines)`, not `O(total IPs)`.
- **Real-time GUI dashboard** with live KPI cards (Total Targets, Scanned, Open, Open Rate), progress bar, log view, and an Open IPs results table.
- **Pause / Resume / Stop** scan controls during an active scan.
- **Batching and progress bars** so you can control how much work is done per run and see live progress.
- **Resume and skip logic** for the ICMP scanner via `.state.json` checkpoint and CSV history, so you can stop and restart without losing work.
- **Rich outputs**: human-readable `.txt`, structured `.csv`, and line-delimited `.jsonl` (ICMP) for easy post-processing.
- **CIDR-aware target handling**: expand IPv4 CIDRs, sample a single host per CIDR, or cap large CIDRs to a fixed number of targets.
- **Host-based CIDR normalization**: entries such as `52.1.1.1/15` are accepted and normalized to their enclosing network via `ipaddress.ip_network(..., strict=False)`.
- **Large CIDR cap strategy**: when a CIDR exceeds the configured per-CIDR limit in all-host mode, targets are selected either sequentially (first N hosts) or via reservoir sampling (random N without materializing the full list).
- **Deduplication**: single IPs and sampled CIDR targets are deduplicated at load time; full CIDR expansions are deduplicated during streaming with a global seen-set.

---

## Requirements

- Python **3.8+**
- Standard library only — no external dependencies: `csv`, `ipaddress`, `json`, `socket`, `tkinter`, `concurrent.futures`, etc.
- For `ICMP_SCANNER.py`, raw socket permissions are required (root on Linux/macOS, Administrator on Windows).

---

## Quick Start

```bash
git clone https://github.com/alireza129/TCP-ICMP-CIDR-IP-scanners-python.git
cd TCP-ICMP-CIDR-IP-scanners-python
```

Create an input file (see [Input Formats](#input-formats)), then run the tool you need.

---

### TCP Scanner (GUI)

`scanner_gui.py` takes a text file of IPv4 single IPs and/or CIDR ranges, streams them lazily (never loading the full expansion into RAM), and tests a single TCP port using concurrent connect attempts.

```bash
python3 scanner_gui.py
```

**Workflow:**

1. Click **Browse** to select your IP/CIDR list `.txt` file.
2. Configure connection, performance, and CIDR settings in the left panel.
3. Set output file names (default: `open_ips.txt` / `open_ips.csv`).
4. Click **▶ Start Scan**. Use **⏸ Pause** / **■ Stop** as needed.
5. Switch to the **Open IPs** tab to inspect results, or click **Export CSV** at any time.

**Behavior notes:**

- CIDRs with host bits set (e.g. `52.1.1.1/15`) are accepted and normalized automatically.
- In **sample** mode, only the first usable host of each CIDR is scanned.
- In **all-host** mode:
  - CIDRs at or below the cap are fully expanded and streamed.
  - Oversized CIDRs are capped to the configured limit using either sequential or reservoir-random selection.
- `/31` and `/32` ranges are handled explicitly to always yield scan targets.
- Results are written to `.txt` and `.csv` incrementally during the scan (not only at the end).

**Outputs:**

- `open_ips.txt` — one IP per line where the port was open.
- `open_ips.csv` — columns: `IP, Ping (ms), Port, Source Range`.

---

### ICMP Scanner

`ICMP_SCANNER.py` sends raw ICMP echo requests (ping) to a flat list of IPv4 addresses and records latency and status.

```bash
# Linux / macOS
sudo python3 ICMP_SCANNER.py

# Windows (run terminal as Administrator)
python ICMP_SCANNER.py
```

**Interactive prompts (in order):**

| Prompt | Default | Description |
|---|---|---|
| `Path to txt file with IPs:` | — | Input IP list |
| `Output filename base:` | `icmp_results` | Base name for all output files |
| `Timeout in seconds:` | `1.5` | ICMP reply timeout per host |
| `Retry count:` | `0` | Additional attempts per host on failure |
| `Batch size:` | — | Number of IPs per batch |
| `Worker count:` | — | Concurrent ICMP workers |
| `Scan mode:` | `r` (randomized) | `s` = sequential, `r` = randomized |
| `Skip already-scanned IPs?` | `Y` | Skip IPs already present in the output CSV |
| `Resume from saved progress?` | `Y` | Continue from `.state.json` offset |
| `How many batches to run now?` | `1` | Repeated between batches to control work per session |

**Outputs** (for base name `icmp_results`):

| File | Content |
|---|---|
| `icmp_results.txt` | IPs that responded successfully, one per line |
| `icmp_results.csv` | `timestamp, ip, status, latency_ms, error, attempts` |
| `icmp_results.jsonl` | One JSON object per successful response |
| `icmp_results.state.json` | Resume checkpoint (`offset` into IP list) |

---

## Input Formats

### TCP Scanner (GUI) — CIDR List

Text file with IPv4 addresses and/or CIDR ranges, one per line.

```text
# Single hosts
192.168.1.10
10.0.0.5

# CIDR ranges
192.168.0.0/24
10.0.0.0/16

# Host-based CIDRs are accepted and auto-normalized
52.1.1.1/15
```

- Comments (`# ...`) and blank lines are ignored.
- IPv6 entries are skipped and reported as invalid in the log.
- Host-based CIDRs are normalized with `strict=False`.

### ICMP Scanner — IP List

Text file with IPv4 addresses, separated by newlines or commas; quotes are stripped and duplicates removed.

```text
192.168.1.10
192.168.1.11, 192.168.1.12
"8.8.8.8"
```

---

## Outputs

| Script | Success TXT | CSV Columns | JSONL |
|---|---|---|---|
| `scanner_gui.py` | `open_ips.txt` (one IP per line) | `IP, Ping (ms), Port, Source Range` | Not generated |
| `ICMP_SCANNER.py` | `<base>.txt` (IPs that responded) | `timestamp, ip, status, latency_ms, error, attempts` | Same fields as CSV |

You can post-process the CSV/JSONL output with `pandas`, `jq`, `csvkit`, or any standard tooling.

---

## Configuration Reference

### `scanner_gui.py` Settings

| Setting | Default | Description |
|---|---|---|
| Port | `443` | TCP port to probe |
| Timeout | `2.0s` | Per-connection timeout |
| Batch size | `256` | IPs dispatched per batch |
| Worker threads | `128` | Concurrent TCP connections |
| Max hosts/CIDR | `65536` | Cap for oversized CIDRs in all-host mode |
| Target mode | `sample` | `sample` = first IP per CIDR; `all` = full expansion (with cap) |
| Scan order | `randomized` | `randomized` shuffles descriptor list; `sequential` preserves file order |
| Cap strategy | `random` | How oversized CIDRs are sampled: `random` (reservoir) or `sequential` (first N) |

---

## Performance Tips

- Start with a **small batch size** and **low worker count** to verify connectivity and correctness before scaling up.
- Increase workers and batch size gradually, watching for timeouts or connection errors in the log.
- Use **randomized** scan order to distribute load evenly across a large target space.
- For very large CIDRs, set a small per-CIDR cap first to validate behavior before scanning broader subsets.
- Use **sequential** cap strategy for deterministic coverage; use **random** (reservoir) for broader distribution across large ranges without materializing the full list.
- For very large ICMP scans, use the skip-already-scanned and resume options to spread work across multiple sessions.

---

## Safety & Legal

These tools are intended for **authorized security testing and network inventory** on systems you own or have explicit written permission to scan.

- Do not scan networks or hosts without permission.
- Aggressive scanning can trigger IDS/IPS systems or rate-limiting.
- Always comply with local laws, your organization's policies, and the terms of service of any networks you interact with.

---

## License

This project is licensed under the **GNU General Public License (GPL)**.  
See the `LICENSE` file for the full license text.
