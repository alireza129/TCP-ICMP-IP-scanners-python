# CIDR / IPv4 / Hostname Batch Scanner

A high-performance, interactive batch scanner for IPv4, CIDR ranges, and hostnames, built with Python 3 and using only the standard library (no external dependencies). It is designed for large-scale discovery and validation of TCP and TLS endpoints, with optional DNS and ICMP probing.

## Features

- IPv4, CIDR, and hostname/domain inputs in a single run.
- Config-driven predefined range files and catalogs (named target sets) for repeatable scans.
- Mixed IP and domain targets with IPv4-only enforcement and IPv6 auto-skip.
- Streaming, batched TCP scan over very large inputs with back-pressure and progress reporting.
- TLS handshake phase that only runs against TCP-open targets (no wasted TLS attempts).
- Optional DNS resolution validation phase for hostnames.
- Optional ICMP ping phase (requires root / raw socket support) against TCP-open IPs.
- SNI override support: auto (hostname), single SNI, or SNI domain lists from files/folder.
- Sliding-window TLS worker model with thousands of concurrent handshakes.
- Automatic deduplication of targets and of IP/SNI combinations (no duplicate TLS probe for the same pair).
- Intelligent CIDR handling: sample, all hosts, or capped (sequential or randomized) expansion.
- System-aware tuning recommendations based on CPU, RAM, OS, and privilege level.
- Structured TXT and CSV outputs suitable for further processing.

## Protocols and Phases

The scanner works as a multi-phase engine; each protocol is a **phase** that can be enabled or disabled via config or interactive prompts.

- DNS (`dns`): Resolve hostnames to IPv4 addresses, with configurable per-hostname limit (default 3 records).
- TCP (`tcp`): TCP connect tests to a configurable port (default 443) with latency measurement and error classification.
- TLS (`tls`): TLS handshake tests over TCP-open targets only, with SNI control and cipher/TLS version capture.
- ICMP (`icmp`): ICMP echo (ping) using raw sockets; only available when running as root.

You can select any combination of these (for example `tcp,tls` or `dns,tcp,tls,icmp`), and interactively choose when to switch from TCP streaming to TLS, then optionally to ICMP.

## Input Model

Targets can come from:

- Plain text files containing IPv4 addresses, CIDR ranges, or hostnames (mixed allowed).
- Predefined ranges specified in `config.json` under `predefined_ranges`.
- Catalogs defined in `config.json` as named collections of targets (`catalogs`).
- Optional built-in catalogs configured via `built_in_catalogs` and `include_builtin_catalogs_by_default`.

Each non-empty, non-comment line is parsed as:

- Single IPv4 address (v4 only; v6 is skipped).
- IPv4 CIDR (e.g. `192.0.2.0/24`).
- Hostname (with basic hostname validation).

### CIDR Expansion and Target Modes

For each IPv4 CIDR, you can control how hosts are expanded:

- `sample`: Only the first usable IP of each CIDR is probed (fast, wide coverage).
- `all`: Every usable IP in the CIDR is probed (slow, exhaustive).
- `capped`: Up to `max_cidr_hosts` per CIDR, either sequential or randomized.

The `cidr_cap_mode` can be:

- `sequential`: Take the first N usable hosts.
- `random`: Reservoir sampling over the CIDR to pick N hosts uniformly at random.

The scanner computes statistics such as total intended scan hosts, number of CIDRs capped, and invalid lines skipped (with optional printing of invalid examples).

## SNI Handling

TLS handshakes support flexible SNI selection.

- `auto`:
  - Host targets use their own hostname as SNI.
  - IP targets do not send SNI by default.

- `single`:
  - Prompt once for a single SNI hostname (e.g. `example.com`).
  - Reuse this SNI for all TLS probes.

- `folder` / file list:
  - Load candidate SNI hostnames from text files (`.txt`, `.list`, `.lst`) in a configured folder.
  - Optionally restrict to explicitly listed SNI files in `config.json` or pick interactively.
  - Build a deduplicated list of SNI candidates used to generate IP/SNI probe pairs per target.

The TLS phase maintains a per-target map of accepted SNIs and prints a TLS SNI Acceptance Summary at the end, showing for each IP which SNIs were successfully negotiated.

## Output

Outputs are appended to paths configured in `config.json` (or defaults). By default:

- TXT: `responsive_targets.txt` — one line per open result with IP and basic metadata.
- CSV: `responsive_targets.csv` — structured rows for post-processing.

CSV columns:

- `Target`: Original target string (hostname, IP, or CIDR-derived IP).
- `Kind`: `host` or `ip`.
- `Resolved IP`: Final IP used for the probe.
- `Latency ms`: Measured latency for the successful probe, if available.
- `Port`: Destination port used.
- `Phase`: `tcp`, `tls`, or `icmp`.
- `Source`: Input source (file name, catalog name, or original line).
- `Used SNI`: SNI string actually used for the TLS handshake.
- `TLS Version`: Negotiated TLS protocol version.
- `TLS Cipher`: Negotiated cipher suite.

TXT and CSV files are created with parent directories automatically if they do not exist.

## Resource Detection and Tuning

On startup, the script inspects the system environment to recommend sane defaults.

- CPU core count (via `os.cpu_count()` or `multiprocessing.cpu_count()`).
- Total RAM in GB (reads `/proc/meminfo` on Linux or uses Windows APIs).
- OS flavor detection (`Ubuntu`, `Debian`, `CentOS`, `RHEL`, `Fedora`, or generic).
- Root / admin status to determine if ICMP is available.

Based on this, it suggests one of several profiles:

- **High-Performance**: large worker counts and batch sizes for 8+ GB RAM and 8+ cores.
- **Standard**: moderate concurrency for typical systems.
- **Medium** / **Low-Resource**: smaller worker counts and longer timeouts for constrained hosts.

These recommendations directly set:

- `worker_count` (TCP workers)
- `batch_size` (targets per batch)
- `timeout` (seconds per TCP/ICMP probe)

You can accept or override these interactively.

## Configuration

Configuration is loaded from `config.json` located next to the script. If missing, runtime defaults are used and then merged with any config file values.

Key fields (with defaults):

```json
{
  "port": 443,
  "tls_timeout": 10.0,
  "tls_worker_count": 5000,
  "timeout": 3.0,
  "batch_size": 20000,
  "worker_count": 5000,
  "max_batches": 5,
  "max_cidr_hosts": 4096,
  "target_mode": "sample",
  "scan_mode": "randomized",
  "cidr_cap_mode": "random",
  "txt_output": "responsive_targets.txt",
  "csv_output": "responsive_targets.csv",
  "target_files": [],
  "predefined_ranges": [],
  "built_in_catalogs": [],
  "catalogs": {},
  "protocols": ["tcp", "tls"],
  "dns_resolve_limit": 3,
  "tls_server_name_mode": "hostname_or_target",
  "sni_source_mode": "auto",
  "sni_single": "",
  "sni_folder": "sni_domains",
  "sni_files": [],
  "include_builtin_catalogs_by_default": false,
  "interactive_confirm_summary": true,
  "show_invalid_items": false
}
```

Notes:

- `target_files`: List of file paths containing targets (relative to `config.json` directory, unless absolute).
- `predefined_ranges`: Objects with `file` and `name` for labeled target files.
- `catalogs`: Map of catalog name to text content string with targets.
- `protocols`: Subset of `[`dns`, `tcp`, `tls`, `icmp`]`.
- `scan_mode`: sample order or fully randomized target order.

The script resolves relative paths with respect to the `config.json` directory and expands `~` in paths.

## Installation

1. Ensure **Python 3.8+** is installed.
2. Clone the repository:

   ```bash
   git clone https://github.com/<your-user>/<your-repo>.git
   cd <your-repo>
   ```

3. Create or edit `config.json` next to the script (optional; see above).
4. Place any target files and SNI domain files referenced by `config.json` in the appropriate directories.

There are no external Python dependencies; everything uses the standard library.

## Usage

Basic usage:

```bash
python3 batch_scan.py
```

During execution, the script will:

1. Load `config.json` and merge it with defaults.
2. Detect system resources and recommend a profile (you can accept or override).
3. Prompt for protocol selection (DNS/TCP/TLS/ICMP).
4. Prompt for tuning parameters (port, timeouts, worker counts, batch size, CIDR cap, DNS resolve limit).
5. Prompt for SNI source (auto, single, or folder/file list).
6. Present available inputs (files, predefined ranges, catalogs) to select.
7. Ask for target mode (`sample` vs `all`).
8. Summarize the planned scan and ask for confirmation.

Example flow for a TCP+TLS scan to port 443:

```bash
python3 batch_scan.py
# Accept recommended profile
# Protocols: 2,3      # TCP + TLS
# Port: 443
# Timeout: 3.0
# Worker count: 5000
# Batch size: 20000
# Max CIDR hosts: 4096
# DNS resolve limit: 3
# SNI source: auto
# Select target inputs by indices or "a" for all
# Start scan when prompted
```

During the run, a progress bar is printed with:

- Completed vs estimated total targets.
- Count of open results in the current phase.
- Global rate and batch ETA, plus file ETA for completion.

Between phases, the tool prompts whether to:

- Continue more TCP batches.
- Switch to TLS on all current TCP-open targets.
- Start ICMP on TCP-open targets.

## ICMP Requirements

The ICMP phase uses raw sockets and therefore requires root on Linux or appropriate privileges on other platforms.

- If not root, ICMP is automatically disabled and shown as unavailable in system summary.
- If enabled and permitted, the phase sends ICMP echo requests and measures latency per IP.

## Error Handling and Deduplication

The scanner is built to handle very large and noisy input sets.

- Invalid lines and unsupported IPv6 entries are skipped; optionally, up to 20 invalid examples are printed.
- Duplicate IP or hostname entries are deduplicated at descriptor level, so each host is only scanned once per phase.
- TLS IP/SNI pairs are deduplicated so the same combination is never probed twice, even across batches.
- DNS, TCP, TLS, and ICMP errors are normalized into human-readable error codes for logging (e.g. `dns_no_a_record`, `timeout`, `tls_timeout`).

## Exit Codes

- `0`: Scan completed or explicitly aborted by user after confirmation prompts.
- `1`: Configuration or output file error (such as failing to open result files or no valid targets).

## License

Add your chosen license information here (for example MIT, Apache-2.0, etc.).
