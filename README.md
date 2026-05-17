# High‑Volume IP Scanner Toolkit

This repository contains three tools for high‑volume IP scanning: an ICMP ping scanner and both GUI and CLI TCP scanners that support IP lists and CIDR ranges without ever fully expanding large networks into memory.

- `ICMP_SCANNER.py`: Parallel ICMP ping scanner for IPv4 addresses from a text file.
- `scanner_gui.py`: Tkinter desktop app for TCP port scanning over IPv4 / CIDR targets.
- `scanner_cli.py`: Terminal‑first TCP port scanner with interactive prompts and colored output.
- Windows users can also download a prebuilt `.exe` from the Releases page.

> ⚠️ Intended for legitimate network diagnostics and research on networks you own or are explicitly authorized to test.

---

## Features

### ICMP scanner

- Raw ICMP echo requests with RTT (latency) measurement.
- Parallel scanning via `ThreadPoolExecutor` with configurable batch size and worker count.
- Resume support via `<output>.state.json` plus “skip already scanned IPs” using previous CSV runs.
- Outputs successful IPs to:
  - `<base>.txt` – successful IPs only.
  - `<base>.csv` – timestamp, IP, status, latency, error, attempts.
  - `<base>.jsonl` – JSON lines mirroring CSV rows.

### TCP scanners (GUI + CLI)

- Accept plain IPv4 addresses and CIDR ranges from a text file.
- Streaming architecture: CIDRs are never fully expanded into RAM (only descriptors are stored).
- Modes:
  - `sample`: first host of each CIDR only.
  - `all`: all hosts up to a configurable cap per CIDR.
- Randomized or sequential scan order across targets.
- Parallel TCP connect probes with configurable batch size and thread count.
- Outputs open hosts to:
  - Text file (`open_ips.txt` style) with one IP per line.
  - CSV with IP, port, latency, and original source range.
- Deduplication across descriptors so each IP is scanned at most once.

### GUI‑specific (scanner_gui-3.py)

- Dark‑themed Tkinter app with:
  - Left config panel (targets, connection, performance, CIDR options, output files).
  - Right dashboard with progress bar, KPIs, log tab, and open‑hosts table.
- Live KPIs: total targets, scanned, open count, open rate.
- Start / pause / resume / stop controls.
- Export discovered open hosts as CSV from the GUI.

### CLI‑specific (scanner_cli-2.py)

- Interactive prompts with defaults, validation, and ANSI color output.
- Batch‑oriented control loop:
  - Continue, pause, or stop between batches.
- Graceful Ctrl+C handling:
  - Finishes the current batch, saves results, and exits cleanly.
- Output files opened in append mode; CSV header written only for new files.

---

## Installation

### Requirements

- Python 3.8+.
- Standard library modules only (no external dependencies), including:
  - `ipaddress`, `socket`, `concurrent.futures`, `threading`, `csv`, `json`, `tkinter` (for GUI), etc.
- On some Linux distros you may need to install Tk bindings separately, e.g. `python3-tk` (or distro equivalent) to run the GUI.

### Clone the repository

```bash
git clone https://github.com/alireza129/TCP-ICMP-CIDR-IP-scanners-python.git
cd TCP-ICMP-CIDR-IP-scanners-python
```

Replace `<your-username>` and `<your-repo>` as appropriate.

### Windows EXE

For a no‑Python setup on Windows:

1. Go to the **Releases** section of this repository.
2. Download the latest `.exe`.
3. Run it directly from Explorer or the command prompt.

---

## Input file format (all tools)

All three tools read targets from a plain text file.

- One item per line.
- Each line can be:
  - A single IPv4 address, e.g. `192.0.2.10`
  - A CIDR range, e.g. `203.0.113.0/24`
- Lines starting with `#` are treated as comments and ignored.
- IPv6 entries are skipped.

Example:

```text
# single IPs
192.0.2.10
198.51.100.5

# CIDRs
203.0.113.0/24
203.0.113.128/25
```

---

## ICMP scanner – `ICMP_SCANNER.py`

The ICMP scanner takes a file of IPv4 addresses (no CIDRs) and probes each with ICMP echo requests using raw sockets.

### Running

```bash
python3 ICMP_SCANNER.py
```

### Interactive flow

You will be prompted for:

1. **Path to txt file with IPs**  
   - One IPv4 address per line.

2. **Output filename base**  
   - Example: `icmp_results`  
   - Produces:
     - `icmp_results.txt` – successful IPs.
     - `icmp_results.csv` – timestamp, IP, status, latency, error, attempts.
     - `icmp_results.jsonl` – JSONL rows matching CSV.

3. **Parameters**
   - Timeout in seconds (default: `1.5`).
   - Retry count (default: `0`).
   - Batch size (number of IPs per batch).
   - Worker count (number of threads per batch).
   - Scan mode: sequential or randomized.
   - Skip already scanned IPs from previous run? (yes/no).
   - Resume from saved progress if state exists? (yes/no).

4. **Batches**
   - You choose how many batches to run in each session.
   - After each set of batches, you can run more until all IPs are processed.

### Notes

- Uses raw ICMP sockets, so you typically must run as **Administrator / root**.
- Maintains a `<base>.state.json` file to resume from where it left off.
- Reads previous CSV to avoid re‑scanning IPs when “skip already scanned” is enabled.

---

## TCP GUI scanner – `scanner_gui-3.py`

The GUI tool scans a TCP port across an IP/CIDR list using a streaming architecture and a dark Tkinter dashboard.

### Running

```bash
python3 scanner_gui-3.py
```

### Configuration (left panel)

- **Target File**
  - *IP / CIDR list (.txt)* – browse to your input file.

- **Connection**
  - *Port* – TCP port to probe (default: `443`).
  - *Timeout (seconds)* – per‑connection timeout (default: `2.0`).

- **Performance**
  - *Batch size* – hosts per batch (default: `256`).
  - *Worker threads* – parallel connections per batch (default: `128`).

- **CIDR Options**
  - *Max hosts per CIDR* – per‑CIDR cap (default: `65536`).
  - *Target mode*:
    - `sample` – only the first host from each CIDR.
    - `all` – all hosts up to the per‑CIDR cap.
  - *Scan order*:
    - `randomized` – shuffle descriptors, then stream.
    - `sequential` – keep descriptor order.
  - *Cap strategy*:
    - `random` – random sample up to max hosts.
    - `sequential` – first N hosts from the range.

- **Output Files**
  - *Text output* – path for open hosts txt (e.g. `open_ips.txt`).
  - *CSV output* – path for open hosts CSV (e.g. `open_ips.csv`).

### Controls

- **▶ Start Scan** – start scanning in a background thread.
- **⏸ Pause / ▶ Resume** – pause/resume between operations.
- **■ Stop** – stop the scan; saved results remain on disk.
- **Export CSV** (Open IPs tab) – export discovered open hosts to a user‑chosen CSV file.

### Output

- **Text file:** one open IP per line.
- **CSV:** columns
  - `IP`
  - `Ping (ms)` (latency)
  - `Port`
  - `Source Range` (original line from input file)
- **Open IPs tab:** table of discovered hosts with latency and source range.
- **KPIs:** total targets, scanned count, open count, open rate (updated live).
- **Log tab:** detailed log of batches and per‑IP results.

---

## TCP CLI scanner – `scanner_cli-2.py`

The CLI scanner is an interactive terminal utility with colored output and batch‑based control.

### Running

```bash
python3 scanner_cli.py
```

### Interactive prompts

1. **Target File**
   - `IP / CIDR list (.txt)` – validated for existence.

2. **Connection**
   - `Port` – default `443`, must be in `1–65535`.
   - `Timeout (seconds)` – default `2.0`, must be `> 0`.

3. **Performance**
   - `Batch size` – default `256`, must be `> 0`.
   - `Worker threads` – default `128`, must be `> 0`.
   - `Max batches to run (default 5, 0 = unlimited)`.

4. **CIDR Options**
   - `Max hosts per CIDR` – default `65536`, must be `> 0`.
   - `Target mode` – `sample` (first IP only) or `all`.
   - `Scan order` – `randomized` or `sequential`.
   - `Cap strategy` – `random` or `sequential` when CIDR exceeds max hosts.

5. **Output Files**
   - `Text output file` – default `open_ips.txt`.
   - `CSV output file` – default `open_ips.csv`.

### Behavior

- Loads descriptors and prints summary:
  - number of descriptors,
  - estimated total hosts,
  - invalid or skipped entries,
  - number of single IPs, CIDR entries, and capped CIDRs.
- Scans in batches; after each batch:
  - Choose `continue`, `pause`, or `stop`.
- Ctrl+C:
  - Finishes the current batch,
  - Saves results,
  - Exits cleanly.
- Streaming target generation:
  - IPs produced on‑the‑fly, never holding all expanded hosts in RAM.
- Output files:
  - Text file in append mode – one open IP per line.
  - CSV in append mode – header written only if file is new.

### Output format

- **Text:** open IPs only.
- **CSV columns:**
  - `IP`
  - `Ping (ms)` (latency)
  - `Port`
  - `Source Range`
- **Progress:** live progress bar on stderr:
  - percent complete,
  - scanned count,
  - number open,
  - approximate rate in hosts/second.
- **Per‑IP log:** lines like:

```text
✓ 203.0.113.5:443 12.5 ms ← 203.0.113.0/24 [rnd 1024/65536]
```

(with ANSI colors when attached to a TTY).

---

## Script comparison

| Script           | Protocol | Interface | Input           | Output                        | Resume / Control                                |
|------------------|----------|-----------|-----------------|-------------------------------|-------------------------------------------------|
| `ICMP_SCANNER.py`  | ICMP     | CLI       | IP list (.txt)  | `.txt`, `.csv`, `.jsonl`      | State file, batch count, worker pool, resume    |
| `scanner_gui-3.py` | TCP      | GUI       | IP/CIDR list    | `.txt`, `.csv`, GUI table     | Streaming batches, pause/resume/stop buttons    |
| `scanner_cli-2.py` | TCP      | CLI       | IP/CIDR list    | `.txt`, `.csv`                | Batch loop with continue/pause/stop, Ctrl+C     |

---

## Legal and safety notes

- These tools generate significant network traffic; **only scan hosts and networks you own or are explicitly authorized to test**.
- ICMP scanning requires raw socket privileges (root/Administrator).
- Misuse may violate laws or acceptable use policies and can trigger IDS/IPS or firewall rules.
- The author(s) assume no liability for misuse or damage caused by these tools.
