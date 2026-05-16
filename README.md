# Python Batch IP Scanners

Two Python scripts for scanning large IP lists in batches using only the Python standard library.

- **TCP scanner**: tests one or more TCP ports on each IP by attempting a TCP connection.
- **ICMP scanner**: sends ICMP echo requests using raw sockets to check whether a host replies.

These scripts are built for large and interruptible runs, with support for batching, resume, validation, deduplication, retries, output files, and per-batch summaries.

## Quick Start

### TCP

```bash
python3 tcp_scanner.py
```

Example answers:

```txt
Path to txt file with IPs: ~/ips.txt
Output filename base (example: tcp_results): tcp_results
Timeout in seconds [default=1.5]:
Retry count [default=0]:
Batch size: 50
Worker count: 50
TCP ports to test (example: 80 or 80,443,22): 80,443,22
Scan mode - sequential or randomized? [s/r, default=r]:
Skip already-scanned IP:PORT entries from previous run? [Y/n]:
Resume from saved progress if state exists? [Y/n]:
How many batches do you want to do right now? [default=1]:
```

### ICMP

```bash
python3 icmp_scanner.py
```

Example answers:

```txt
Path to txt file with IPs: ~/ips.txt
Output filename base (example: icmp_results): icmp_results
Timeout in seconds [default=1.5]:
Retry count [default=0]:
Batch size: 100
Worker count: 100
Scan mode - sequential or randomized? [s/r, default=r]:
Skip already-scanned IPs from previous run? [Y/n]:
Resume from saved progress if state exists? [Y/n]:
How many batches do you want to do right now? [default=1]:
```

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Important Note About ICMP](#important-note-about-icmp)
- [Input File Format](#input-file-format)
- [Output Files](#output-files)
- [TCP Scanner Usage](#tcp-scanner-usage)
- [ICMP Scanner Usage](#icmp-scanner-usage)
- [Validation and Deduplication](#validation-and-deduplication)
- [Resume Behavior](#resume-behavior)
- [Skip Already-Scanned Behavior](#skip-already-scanned-behavior)
- [Multi-Port TCP Mode](#multi-port-tcp-mode)
- [Batch Summaries](#batch-summaries)
- [Example Output Files](#example-output-files)
- [Suggested Filenames](#suggested-filenames)
- [Notes](#notes)
- [Safety](#safety)

## Features

### Shared features

Both scanners support:

- Loading IPs from a `.txt` file
- Accepting either one IP per line or comma-separated IPs
- IP validation before scanning
- Deduplication before scanning
- Immediate saving of successful results while scanning
- Export formats:
  - `.txt`
  - `.csv`
  - `.jsonl`
- Resume support using a state file
- Optional skipping of already-scanned targets from a previous run
- Configurable:
  - batch size
  - worker count
  - timeout
  - retry count
- Running multiple batches in a row before prompting again
- Per-batch progress bars
- Per-batch summary stats

### TCP scanner features

The TCP scanner also supports:

- Single-port scanning
- Multi-port scanning
- Success output in `IP:PORT` format
- Optional skipping of already-scanned `IP:PORT` entries

### ICMP scanner features

The ICMP scanner also supports:

- ICMP echo request / reply scanning
- Success output in `IP` format
- Immediate saving of successful replies while scanning

## Requirements

- Python 3
- No third-party packages

The scripts use only standard-library modules such as:

- `socket`
- `pathlib`
- `ipaddress`
- `csv`
- `json`
- `random`
- `time`
- `concurrent.futures`

## Important Note About ICMP

The ICMP scanner uses raw sockets.

On most operating systems, raw ICMP sockets require elevated privileges:

- **Linux/macOS**: usually run with `sudo`
- **Windows**: usually run in an Administrator shell

Without sufficient privileges, the ICMP scanner may fail with a permission error.

## Input File Format

The IP input file can use either of the following formats.

### One IP per line

```txt
94.130.13.19
94.130.50.12
198.252.206.1
```

### Comma-separated

```txt
"94.130.13.19", "94.130.50.12", "198.252.206.1"
```

## Output Files

Each scanner saves successful results immediately so progress is not lost if the script is interrupted.

If the output filename base is:

```txt
tcp_results
```

the script will generate:

```txt
tcp_results.txt
tcp_results.csv
tcp_results.jsonl
tcp_results.state.json
```

### File meanings

| File | Purpose |
|---|---|
| `.txt` | Simple list of successful results |
| `.csv` | Structured output for spreadsheets, analysis, or automation |
| `.jsonl` | Append-friendly JSON output, one object per line |
| `.state.json` | Resume state for continuing from the last saved offset |

## TCP Scanner Usage

Run:

```bash
python3 tcp_scanner.py
```

### Prompts

The TCP scanner prompts for:

1. Path to the IP text file
2. Output filename base
3. Timeout in seconds
4. Retry count
5. Batch size
6. Worker count
7. TCP ports to test
8. Scan mode: sequential or randomized
9. Whether to skip already-scanned `IP:PORT` entries
10. Whether to resume from saved state
11. How many batches to run right now

## ICMP Scanner Usage

Run:

```bash
python3 icmp_scanner.py
```

### Prompts

The ICMP scanner prompts for:

1. Path to the IP text file
2. Output filename base
3. Timeout in seconds
4. Retry count
5. Batch size
6. Worker count
7. Scan mode: sequential or randomized
8. Whether to skip already-scanned IPs
9. Whether to resume from saved state
10. How many batches to run right now

## Validation and Deduplication

Before scanning begins, both scripts:

- Parse the input file
- Validate IP addresses
- Skip invalid entries
- Remove duplicates

This reduces wasted work and keeps the output cleaner.

## Resume Behavior

Both scanners support resume using a saved state file.

When resume is enabled, the script:

- Loads the saved offset from `.state.json`
- Continues from that position
- Saves progress again after each processed batch

This is useful for large scans or interrupted runs.

## Skip Already-Scanned Behavior

Both scanners can skip entries already present in prior output files.

- The TCP scanner skips previously scanned `IP:PORT` entries
- The ICMP scanner skips previously scanned IPs

This avoids repeating old work when re-running a scan.

## Multi-Port TCP Mode

The TCP scanner supports more than one port in the same run.

Example input:

```txt
80,443,22
```

Each IP will be tested against:

- port 80
- port 443
- port 22

Successful results are printed and saved as:

```txt
198.252.206.1:443
```

## Batch Summaries

After each batch, the scripts print summary information such as:

- total scanned in the batch
- total successes
- success rate
- average latency of successful results
- remaining work

This helps with monitoring long scans.

## Example Output Files

### TCP `.txt`

```txt
94.130.13.19:443
198.252.206.1:80
203.0.113.10:22
```

### ICMP `.txt`

```txt
94.130.13.19
198.252.206.1
203.0.113.10
```

### TCP `.csv`

```csv
timestamp,ip,port,status,latency_ms,error,attempts
1715880000,94.130.13.19,443,success,23.44,,1
1715880002,198.252.206.1,80,success,31.10,,1
```

### ICMP `.csv`

```csv
timestamp,ip,status,latency_ms,error,attempts
1715880100,94.130.13.19,success,18.52,,1
1715880102,198.252.206.1,success,22.90,,1
```

## Suggested Filenames

```txt
tcp_scanner.py
icmp_scanner.py
README.md
ips.txt
```

## Notes

- Sequential mode scans IPs in file order.
- Randomized mode shuffles the IP list before scanning starts.
- JSONL is used because it is easy to append to during long-running scans.
- Resume behavior is most reliable when the target order is preserved consistently between runs.

## Safety

Use these scripts only on systems and networks that you own or are explicitly authorized to test.

Large-scale TCP or ICMP scanning may trigger alerts, monitoring, throttling, or abuse detection on managed networks.
