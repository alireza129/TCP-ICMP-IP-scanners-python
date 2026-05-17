#!/usr/bin/env python3
"""
CIDR / IPv4 TCP Batch Scanner — CLI Edition
Streaming architecture: CIDRs are never fully expanded into RAM.
"""

import csv
import ipaddress
import random
import signal
import socket
import sys
import threading
import time
from itertools import islice
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ══════════════════════════════════════════════════════ core scanner logic ══

def iter_scan_hosts(net: ipaddress.IPv4Network):
    if net.prefixlen == 32:
        yield net.network_address
    elif net.prefixlen == 31:
        yield net.network_address
        yield net.broadcast_address
    else:
        yield from net.hosts()


def count_scan_hosts(net: ipaddress.IPv4Network) -> int:
    if net.prefixlen == 32:
        return 1
    if net.prefixlen == 31:
        return 2
    return max(net.num_addresses - 2, 0)


def first_scan_host(net: ipaddress.IPv4Network):
    for ip in iter_scan_hosts(net):
        return ip
    return None


def reservoir_sample(iterable, k: int):
    if k <= 0:
        return []
    sample = []
    for i, item in enumerate(iterable):
        if i < k:
            sample.append(item)
        else:
            j = random.randint(0, i)
            if j < k:
                sample[j] = item
    return sample


def descriptor_iter(desc: dict):
    t   = desc["type"]
    src = desc["source"]
    cap = desc["cap_label"]

    if t == "ip":
        yield desc["ip"], src, cap
        return

    net = desc["net"]

    if t == "cidr_sample":
        ip = first_scan_host(net)
        if ip:
            yield str(ip), src, cap
        return

    if t == "cidr_all":
        for ip in iter_scan_hosts(net):
            yield str(ip), src, cap
        return

    if t == "cidr_capped_seq":
        for ip in islice(iter_scan_hosts(net), desc["cap_k"]):
            yield str(ip), src, cap
        return

    if t == "cidr_capped_rnd":
        for ip in reservoir_sample(iter_scan_hosts(net), desc["cap_k"]):
            yield str(ip), src, cap
        return


def parse_line_to_descriptor(raw, target_mode, max_cidr_hosts, cidr_cap_mode):
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            return None, True, f"{raw} ({e})"

        if net.version != 4:
            return None, True, f"{raw} (IPv6 skipped)"

        total = count_scan_hosts(net)
        if total == 0:
            return None, True, f"{raw} (no usable host)"

        if target_mode == "sample":
            return {"type": "cidr_sample", "net": net, "source": raw,
                    "cap_label": None, "count": 1}, False, None

        if total <= max_cidr_hosts:
            return {"type": "cidr_all", "net": net, "source": raw,
                    "cap_label": None, "count": total}, False, None

        if cidr_cap_mode == "sequential":
            cap_label, dtype = f"seq {max_cidr_hosts}/{total}", "cidr_capped_seq"
        else:
            cap_label, dtype = f"rnd {max_cidr_hosts}/{total}", "cidr_capped_rnd"

        return {"type": dtype, "net": net, "source": raw, "cap_label": cap_label,
                "count": max_cidr_hosts, "cap_k": max_cidr_hosts}, False, None

    else:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None, True, raw

        if ip.version != 4:
            return None, True, f"{raw} (IPv6 skipped)"

        return {"type": "ip", "ip": str(ip), "source": raw,
                "cap_label": None, "count": 1}, False, None


def load_descriptors(file_path, target_mode, max_cidr_hosts, cidr_cap_mode):
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    descriptors, invalid, seen_ips = [], [], set()
    stats = {"raw_entries": 0, "single_ips": 0, "cidr_entries": 0,
             "total_scan_hosts": 0, "cidrs_capped": 0, "invalid_items": 0}

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            stats["raw_entries"] += 1

            desc, is_invalid, err_msg = parse_line_to_descriptor(
                raw, target_mode, max_cidr_hosts, cidr_cap_mode)

            if is_invalid:
                invalid.append(err_msg)
                continue

            if desc["type"] == "ip":
                if desc["ip"] in seen_ips:
                    continue
                seen_ips.add(desc["ip"])
                stats["single_ips"] += 1
            elif desc["type"] == "cidr_sample":
                ip = first_scan_host(desc["net"])
                if ip and str(ip) in seen_ips:
                    continue
                if ip:
                    seen_ips.add(str(ip))
                stats["cidr_entries"] += 1
            else:
                stats["cidr_entries"] += 1
                if desc["type"] in ("cidr_capped_seq", "cidr_capped_rnd"):
                    stats["cidrs_capped"] += 1

            stats["total_scan_hosts"] += desc["count"]
            descriptors.append(desc)

    stats["invalid_items"] = len(invalid)
    return descriptors, invalid, stats


def stream_targets(descriptors, scan_mode):
    if scan_mode == "randomized":
        descriptors = descriptors[:]
        random.shuffle(descriptors)

    seen = set()
    for desc in descriptors:
        for ip, src, cap in descriptor_iter(desc):
            if ip in seen:
                continue
            seen.add(ip)
            yield ip, src, cap


def tcp_probe(ip, port, timeout):
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"ip": ip, "status": "open", "latency_ms": round(elapsed_ms, 2), "error": ""}
    except socket.timeout:
        err = "timeout"
    except OSError as e:
        err = type(e).__name__
    return {"ip": ip, "status": "closed", "latency_ms": None, "error": err}


# ══════════════════════════════════════════════════════════════════ ANSI ══

def _tty():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _tty() else text

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def dim(t):    return _c("2",  t)
def bold(t):   return _c("1",  t)


# ══════════════════════════════════════════════════════════ prompt helpers ══

def ask(prompt, default=None, cast=str, validate=None):
    """
    Print a prompt, read a line, apply cast + validate.
    Keeps re-asking on bad input. Press Enter to accept the default.
    """
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            raw = input(cyan(f"  {prompt}{hint}: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw == "" and default is not None:
            raw = str(default)

        if raw == "":
            print(yellow("    ↳ required, please enter a value"))
            continue

        try:
            value = cast(raw)
        except (ValueError, TypeError):
            print(yellow(f"    ↳ invalid value, expected {cast.__name__}"))
            continue

        if validate:
            err = validate(value)
            if err:
                print(yellow(f"    ↳ {err}"))
                continue

        return value


def ask_choice(prompt, choices, default=None):
    """Ask for one of a fixed set of choices; accepts full word or first letter."""
    # build display like  [s]ample/[a]ll
    def fmt(c):
        label = f"[{c[0]}]{c[1:]}"
        return bold(label) if c == default else label
    options = "/".join(fmt(c) for c in choices)
    first_letters = {c[0]: c for c in choices}

    while True:
        try:
            raw = input(cyan(f"  {prompt} ({options}): ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw == "" and default is not None:
            return default

        if raw in choices:
            return raw

        if raw in first_letters:
            return first_letters[raw]

        print(yellow(f"    ↳ choose one of: {', '.join(choices)} (or first letter)"))


def ask_file(prompt, default=None):
    """Ask for a readable file path; keeps re-asking if the file doesn't exist."""
    hint = f" [{default}]" if default else ""
    while True:
        try:
            raw = input(cyan(f"  {prompt}{hint}: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw == "" and default:
            raw = default

        if not raw:
            print(yellow("    ↳ required, please enter a path"))
            continue

        path = Path(raw).expanduser()
        if not path.is_file():
            print(yellow(f"    ↳ file not found: {path}"))
            continue

        return str(path)


# ══════════════════════════════════════════════════════════════ scan loop ══

def print_progress(done, total, open_count, start_time, width=40):
    pct  = done / total if total else 0
    fill = int(pct * width)
    bar  = "█" * fill + "░" * (width - fill)
    elapsed  = time.perf_counter() - start_time
    rate_str = f"{done/elapsed:.0f}/s" if elapsed > 0.5 else "..."
    line = (f"\r  [{bar}] {pct*100:5.1f}%  "
            f"{done}/{total}  open:{open_count}  {rate_str}  ")
    sys.stderr.write(line)
    sys.stderr.flush()


def run_scan(p, txt_file, csv_writer, stop_event, pause_event,
             open_total_ref, completed_ref, scan_start, total_units):
    """
    Run one session of batches against already-open output files.
    open_total_ref / completed_ref are single-element lists used as mutable ints
    so the caller can accumulate totals across multiple sessions.
    Returns (exhausted: bool) — True if the target stream ran dry.
    """
    max_batches   = p.get("max_batches")   # None = unlimited this session
    batch_num     = 0
    exhausted     = False
    target_stream = p["_stream"]

    while not exhausted and not stop_event.is_set():
        if max_batches and batch_num >= max_batches:
            break

        batch = []
        for item in target_stream:
            batch.append(item)
            if len(batch) >= p["batch_size"]:
                break
        else:
            exhausted = True

        if not batch:
            break

        batch_num += 1
        batch_open = 0
        print(f"\n  {bold(f'── Batch {batch_num}')}"
              + (f"/{max_batches}" if max_batches else "")
              + f"  ({len(batch)} hosts)")
        t0 = time.perf_counter()

        with ThreadPoolExecutor(
                max_workers=min(p["worker_count"], len(batch))) as ex:
            futures = {
                ex.submit(tcp_probe, ip, p["port"], p["timeout"]): (ip, src, cap)
                for ip, src, cap in batch
            }
            for future in as_completed(futures):
                pause_event.wait()

                if stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break

                ip, src, cap = futures[future]
                result = future.result()
                completed_ref[0] += 1

                if result["status"] == "open":
                    open_total_ref[0] += 1
                    batch_open += 1
                    lat = result["latency_ms"]

                    txt_file.write(ip + "\n")
                    txt_file.flush()
                    csv_writer.writerow([ip, lat, p["port"], src])
                    # csv_writer flushes via the underlying file handle below
                    txt_file.flush()

                    cap_s = f"  [{cap}]" if cap else ""
                    src_s = f"  ← {src}" if src != ip else ""
                    sys.stderr.write("\r" + " " * 80 + "\r")
                    sys.stderr.flush()
                    print(green(f"  ✓ {ip}:{p['port']}  {lat} ms{src_s}{cap_s}"))

                print_progress(completed_ref[0], total_units,
                               open_total_ref[0], scan_start)

        elapsed = time.perf_counter() - t0
        rate_s  = f"{batch_open/len(batch)*100:.1f}%" if batch else "—"
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()
        print(dim(f"  Batch done: {len(batch)} scanned, "
                  f"{batch_open} open ({rate_s})  [{elapsed:.2f}s]"))

        if stop_event.is_set():
            break

    return exhausted


def start_scan(p):
    """
    Top-level scan controller.
    Opens output files in APPEND mode, runs sessions, prompts to continue.
    """
    print(bold(cyan("\n  ══════════════════════════════════════════════════")))
    print(f"  {bold('Loading targets')} from {p['file_path']} …")

    try:
        descriptors, invalid, stats = load_descriptors(
            p["file_path"], p["target_mode"], p["max_cidr_hosts"], p["cidr_cap_mode"])
    except FileNotFoundError as e:
        print(red(f"  ERROR: {e}"))
        return 1

    if not descriptors:
        print(red("  No valid IPv4 targets found."))
        return 1

    total_units = stats["total_scan_hosts"]

    print(bold(cyan("  ══════════════════════════════════════════════════")))
    print(f"  {bold('Descriptors loaded')} : {len(descriptors)}")
    print(f"  Est. total hosts   : {total_units}")
    print((yellow if stats["invalid_items"] else dim)(
          f"  Invalid/skipped    : {stats['invalid_items']}"))
    print(f"  Single IPs         : {stats['single_ips']}")
    print(f"  CIDR entries       : {stats['cidr_entries']}")
    print(f"  CIDRs capped       : {stats['cidrs_capped']}")
    print(f"  Port / Timeout     : {p['port']}  /  {p['timeout']}s")
    print(f"  Batch / Workers    : {p['batch_size']}  /  {p['worker_count']}")
    print(f"  Max batches        : {p['max_batches'] if p['max_batches'] else 'unlimited'}")
    print(f"  Target mode        : {p['target_mode']}")
    print(f"  Scan order         : {p['scan_mode']}")
    print(dim("  ⚡ Streaming mode  : IPs generated on-the-fly, low RAM"))
    print(dim("  ⏸  Pause/continue/stop is available at batch boundaries"))
    print(dim("  ■  Ctrl+C stops after current batch and saves"))
    print(bold(cyan("  ══════════════════════════════════════════════════\n")))

    # ── open output files in APPEND mode ─────────────────────────────────
    try:
        txt_file = open(p["txt_output"], "a", encoding="utf-8", newline="")
        csv_handle = open(p["csv_output"], "a", encoding="utf-8", newline="")
        # write CSV header only if the file is brand new (size == 0)
        csv_writer = csv.writer(csv_handle)
        if csv_handle.tell() == 0:
            csv_writer.writerow(["IP", "Ping (ms)", "Port", "Source Range"])
    except OSError as e:
        print(red(f"  Cannot open output files: {e}"))
        return 1

    # ── shared events ─────────────────────────────────────────────────────
    stop_event  = threading.Event()
    pause_event = threading.Event()
    pause_event.set()

    def _batch_boundary_prompt():
        print(dim("  Commands at batch boundaries: [p]ause, [c]ontinue, [s]top"))
    def _sigint(sig, frame):
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()
        print(yellow("\n  Ctrl+C — stopping after current batch, results are saved…"))
        stop_event.set()
        pause_event.set()

    signal.signal(signal.SIGINT, _sigint)

    # ── mutable accumulators ──────────────────────────────────────────────
    open_total_ref = [0]
    completed_ref  = [0]
    scan_start     = time.perf_counter()

    # build the stream once — it persists across sessions so we never
    # re-scan already-processed IPs
    target_stream = stream_targets(descriptors, p["scan_mode"])
    p["_stream"]  = target_stream

    try:
        while True:
            exhausted = run_scan(
                p, txt_file, csv_writer,
                stop_event, pause_event,
                open_total_ref, completed_ref,
                scan_start, total_units,
            )

            # clear progress bar
            sys.stderr.write("\r" + " " * 80 + "\r")
            sys.stderr.flush()

            if stop_event.is_set() or exhausted:
                break

            # ── prompt: run more batches? ─────────────────────────────────
            print(bold(cyan("\n  ── Session complete ─────────────────────────────")))
            print(f"  Open so far : {green(str(open_total_ref[0]))}  |  "
                  f"Scanned : {completed_ref[0]}  |  "
                  f"Saved → {p['txt_output']}")
            print(cyan("  ──────────────────────────────────────────────────"))

            print(dim("  Enter number of extra batches, or 0 for all remaining, or leave blank to do 1 more."))
            extra_raw = ask(
                "Extra batches (0 = all remaining, s = stop)",
                default="1", cast=str,
            )
            val = extra_raw.strip().lower()
            if val in ("s", "stop"):
                break
            try:
                n = int(val)
            except ValueError:
                n = 1
            p["max_batches"] = None if n == 0 else max(n, 1)



    finally:
        txt_file.close()
        csv_handle.close()
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()
        # restore default SIGINT so the process can be killed normally
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    total_elapsed = time.perf_counter() - scan_start
    print(bold(cyan("\n  ══════════════════════════════════════════════════")))
    print(bold(f"  Done — {open_total_ref[0]} open / {completed_ref[0]} scanned  "
               f"[{total_elapsed:.1f}s]"))
    print(f"  Saved → {p['txt_output']}  |  {p['csv_output']}")
    print(bold(cyan("  ══════════════════════════════════════════════════\n")))
    return 0


# ══════════════════════════════════════════════════════════════════ main ══

def main():
    print(bold(cyan("""
  ╔══════════════════════════════════════════╗
  ║       CIDR / IPv4 TCP Batch Scanner      ║
  ╚══════════════════════════════════════════╝
""")))
    print(dim("  Press Enter to accept the value shown in [brackets].\n"))

    print(bold("  ─── Target File ───────────────────────────────────"))
    file_path = ask_file("IP / CIDR list (.txt)")

    print(bold("\n  ─── Connection ─────────────────────────────────────"))
    port    = ask("Port", default=443, cast=int,
                  validate=lambda v: None if 1 <= v <= 65535 else "must be 1–65535")
    timeout = ask("Timeout (seconds)", default=2.0, cast=float,
                  validate=lambda v: None if v > 0 else "must be > 0")

    print(bold("\n  ─── Performance ────────────────────────────────────"))
    batch_size   = ask("Batch size",     default=256, cast=int,
                       validate=lambda v: None if v > 0 else "must be > 0")
    worker_count = ask("Worker threads", default=128, cast=int,
                       validate=lambda v: None if v > 0 else "must be > 0")
    max_batches_raw = ask(
        "Max batches to run (default 5, 0 = unlimited)", default=5, cast=int,
        validate=lambda v: None if v >= 0 else "must be 0 or more")
    max_batches = max_batches_raw if max_batches_raw > 0 else None

    print(bold("\n  ─── CIDR Options ───────────────────────────────────"))
    max_cidr_hosts = ask("Max hosts per CIDR", default=65536, cast=int,
                         validate=lambda v: None if v > 0 else "must be > 0")
    target_mode  = ask_choice("Target mode   (sample=first IP only, all=every IP)",
                              ["sample", "all"], default="sample")
    scan_order   = ask_choice("Scan order",
                              ["randomized", "sequential"], default="randomized")
    cap_strategy = ask_choice("Cap strategy  (when CIDR exceeds max hosts)",
                              ["random", "sequential"], default="random")

    print(bold("\n  ─── Output Files ───────────────────────────────────"))
    txt_output = ask("Text output file", default="open_ips.txt")
    csv_output = ask("CSV output file",  default="open_ips.csv")

    params = dict(
        file_path      = file_path,
        port           = port,
        timeout        = timeout,
        batch_size     = batch_size,
        worker_count   = worker_count,
        max_batches    = max_batches,
        max_cidr_hosts = max_cidr_hosts,
        target_mode    = target_mode,
        scan_mode      = scan_order,
        cidr_cap_mode  = cap_strategy,
        txt_output     = txt_output,
        csv_output     = csv_output,
    )

    print()
    sys.exit(start_scan(params))


if __name__ == "__main__":
    main()
