#!/usr/bin/env python3
"""
CIDR / IPv4 TCP Batch Scanner
Config-driven with minimal runtime prompts for range selection and target mode.
"""

import asyncio, csv, ipaddress, json, queue as _queue, random, signal, sys
import threading, time
from itertools import islice
from pathlib import Path

CONFIG_FILE = Path("config.json")

DEFAULTS = {
    "port": 443,
    "timeout": 2.0,
    "batch_size": 256,
    "worker_count": 512,
    "max_batches": 5,
    "max_cidr_hosts": 65536,
    "target_mode": "sample",
    "scan_mode": "randomized",
    "cidr_cap_mode": "random",
    "txt_output": "open_ips.txt",
    "csv_output": "open_ips.csv",
    "target_files": [],
    "predefined_ranges": []
}

def load_config() -> dict:
    cfg = DEFAULTS.copy()
    if CONFIG_FILE.is_file():
        with CONFIG_FILE.open() as f:
            cfg.update({k: v for k, v in json.load(f).items() if not k.startswith("_")})
    cfg["max_batches"] = cfg["max_batches"] or None
    return cfg

# ── runtime prompts ───────────────────────────────────────────────────────────

def _tty(): return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
def _c(code, t): return f"\033[{code}m{t}\033[0m" if _tty() else t
green  = lambda t: _c("32", t)
yellow = lambda t: _c("33", t)
red    = lambda t: _c("31", t)
cyan   = lambda t: _c("36", t)
dim    = lambda t: _c("2", t)
bold   = lambda t: _c("1", t)

def prompt_ranges(cfg: dict) -> list[str]:
    """Print numbered list of predefined_ranges + target_files, return selected file paths."""
    ranges = cfg.get("predefined_ranges", [])
    extra  = cfg.get("target_files", [])

    entries = []  # (label, file_path)
    for r in ranges:
        entries.append((r.get("name", r.get("file", "?")), r["file"]))
    for f in extra:
        entries.append((f, f))

    if not entries:
        print(red(" No ranges defined in config.json."))
        sys.exit(1)

    print(bold(cyan("\n ── Available Ranges ────────────────────────────────")))
    for i, (name, _) in enumerate(entries, 1):
        print(f"  {bold(str(i)):>4}.  {name}")
    print(cyan(" ────────────────────────────────────────────────────"))
    print(dim("  Enter number(s) separated by commas, or \'a\' for all."))

    while True:
        try:
            raw = input(cyan("  Select ranges: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)

        if raw.lower() == "a":
            return [e[1] for e in entries]

        try:
            indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if not indices: raise ValueError
            if any(i < 1 or i > len(entries) for i in indices):
                raise ValueError
        except ValueError:
            print(yellow(f"  ↳ enter number(s) between 1 and {len(entries)}, e.g. 1,3,5  or  a"))
            continue

        selected = [entries[i - 1][1] for i in indices]
        labels   = [entries[i - 1][0] for i in indices]
        print(dim(f"  ✓ Selected: {', '.join(labels)}"))
        return selected

def prompt_target_mode(default: str) -> str:
    """Ask sample vs all, with config default pre-highlighted."""
    opts = ["sample", "all"]
    formatted = "  /  ".join(
        bold(f"[{o}]") if o == default else o for o in opts
    )
    print(bold(cyan("\n ── Target Mode ─────────────────────────────────────")))
    print(f"  sample  — probe only the first IP of each CIDR (fast, broad coverage)")
    print(f"  all     — probe every IP in each CIDR (slow, thorough)")
    print(cyan(" ────────────────────────────────────────────────────"))
    while True:
        try:
            raw = input(cyan(f"  Mode ({formatted}): ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if raw == "":
            print(dim(f"  ✓ Using default: {default}"))
            return default
        if raw in opts or raw in ("s", "a"):
            result = "sample" if raw in ("sample", "s") else "all"
            print(dim(f"  ✓ {result}"))
            return result
        print(yellow("  ↳ type  sample  or  all  (or s / a), Enter to keep default"))

# ── scanning core ─────────────────────────────────────────────────────────────

def iter_scan_hosts(net):
    if net.prefixlen == 32: yield net.network_address
    elif net.prefixlen == 31: yield net.network_address; yield net.broadcast_address
    else: yield from net.hosts()

def count_scan_hosts(net):
    if net.prefixlen == 32: return 1
    if net.prefixlen == 31: return 2
    return max(net.num_addresses - 2, 0)

def first_scan_host(net):
    for ip in iter_scan_hosts(net): return ip

def reservoir_sample(iterable, k):
    if k <= 0: return []
    sample = []
    for i, item in enumerate(iterable):
        if i < k: sample.append(item)
        else:
            j = random.randint(0, i)
            if j < k: sample[j] = item
    return sample

def descriptor_iter(desc):
    t, src, cap = desc["type"], desc["source"], desc["cap_label"]
    if t == "ip":
        yield desc["ip"], src, cap; return
    net = desc["net"]
    if t == "cidr_sample":
        ip = first_scan_host(net)
        if ip: yield str(ip), src, cap
    elif t == "cidr_all":
        for ip in iter_scan_hosts(net): yield str(ip), src, cap
    elif t == "cidr_capped_seq":
        for ip in islice(iter_scan_hosts(net), desc["cap_k"]): yield str(ip), src, cap
    elif t == "cidr_capped_rnd":
        for ip in reservoir_sample(iter_scan_hosts(net), desc["cap_k"]): yield str(ip), src, cap

def parse_line(raw, target_mode, max_cidr_hosts, cidr_cap_mode):
    if "/" in raw:
        try: net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e: return None, True, f"{raw} ({e})"
        if net.version != 4: return None, True, f"{raw} (IPv6 skipped)"
        total = count_scan_hosts(net)
        if total == 0: return None, True, f"{raw} (no usable host)"
        if target_mode == "sample":
            return {"type":"cidr_sample","net":net,"source":raw,"cap_label":None,"count":1}, False, None
        if total <= max_cidr_hosts:
            return {"type":"cidr_all","net":net,"source":raw,"cap_label":None,"count":total}, False, None
        cap_label = f"seq {max_cidr_hosts}/{total}" if cidr_cap_mode == "sequential" else f"rnd {max_cidr_hosts}/{total}"
        dtype = "cidr_capped_seq" if cidr_cap_mode == "sequential" else "cidr_capped_rnd"
        return {"type":dtype,"net":net,"source":raw,"cap_label":cap_label,"count":max_cidr_hosts,"cap_k":max_cidr_hosts}, False, None
    else:
        try: ip = ipaddress.ip_address(raw)
        except ValueError: return None, True, raw
        if ip.version != 4: return None, True, f"{raw} (IPv6 skipped)"
        return {"type":"ip","ip":str(ip),"source":raw,"cap_label":None,"count":1}, False, None

def load_descriptors(file_path, target_mode, max_cidr_hosts, cidr_cap_mode):
    path = Path(file_path).expanduser()
    if not path.is_file(): raise FileNotFoundError(f"File not found: {path}")
    descriptors, invalid, seen = [], [], set()
    stats = dict(raw_entries=0, single_ips=0, cidr_entries=0, total_scan_hosts=0, cidrs_capped=0, invalid_items=0)
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"): continue
            stats["raw_entries"] += 1
            desc, is_bad, err = parse_line(raw, target_mode, max_cidr_hosts, cidr_cap_mode)
            if is_bad: invalid.append(err); continue
            if desc["type"] == "ip":
                if desc["ip"] in seen: continue
                seen.add(desc["ip"]); stats["single_ips"] += 1
            elif desc["type"] == "cidr_sample":
                ip = first_scan_host(desc["net"])
                if ip and str(ip) in seen: continue
                if ip: seen.add(str(ip))
                stats["cidr_entries"] += 1
            else:
                stats["cidr_entries"] += 1
            if desc["type"] in ("cidr_capped_seq","cidr_capped_rnd"): stats["cidrs_capped"] += 1
            stats["total_scan_hosts"] += desc["count"]
            descriptors.append(desc)
    stats["invalid_items"] = len(invalid)
    return descriptors, invalid, stats

def stream_targets(descriptors, scan_mode):
    if scan_mode == "randomized": descriptors = random.sample(descriptors, len(descriptors))
    seen = set()
    for desc in descriptors:
        for ip, src, cap in descriptor_iter(desc):
            if ip in seen: continue
            seen.add(ip); yield ip, src, cap

# ── progress / ETA ────────────────────────────────────────────────────────────

def _fmt_eta(s):
    if s < 0: return "—"
    if s < 60: return f"{s:.0f}s"
    m, s = divmod(int(s), 60)
    if m < 60: return f"{m}m{s:02d}s"
    h, m = divmod(m, 60); return f"{h}h{m:02d}m"

def print_progress(done, total, opens, t0, bd=0, bt=0, bt0=None, w=40):
    pct = done / total if total else 0
    bar = "█" * int(pct * w) + "░" * (w - int(pct * w))
    elapsed = time.perf_counter() - t0
    rate = done / elapsed if elapsed > 0.5 else 0
    rate_s = f"{rate:.0f}/s" if elapsed > 0.5 else "..."
    file_eta = _fmt_eta((total - done) / rate) if rate > 0 and total > done else ("done" if done >= total > 0 else "...")
    if bt0 and bd > 0:
        br = bd / (time.perf_counter() - bt0) if (time.perf_counter() - bt0) > 0 else 0
        b_eta = _fmt_eta((bt - bd) / br) if br > 0 and bt > bd else ("done" if bd >= bt else "...")
    else:
        b_eta = "..."
    sys.stderr.write(f"\r [{bar}] {pct*100:5.1f}% {done}/{total} open:{opens} {rate_s} │ batch:{b_eta} file:{file_eta} ")
    sys.stderr.flush()

# ── async scan engine ─────────────────────────────────────────────────────────

async def tcp_probe(ip, port, timeout, sem):
    async with sem:
        t = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            try: await writer.wait_closed()
            except: pass
            return {"ip": ip, "status": "open", "latency_ms": round((time.perf_counter() - t) * 1000, 2), "error": ""}
        except (asyncio.TimeoutError, TimeoutError): err = "timeout"
        except OSError as e: err = type(e).__name__
        return {"ip": ip, "status": "closed", "latency_ms": None, "error": err}

async def _probe_q(ip, src, cap, port, timeout, sem, q):
    await q.put((await tcp_probe(ip, port, timeout, sem), src, cap))

def _prefetcher(stream, bsize, q, stop):
    try:
        while not stop.is_set():
            batch = list(islice(stream, bsize))
            if not batch: q.put(None); return
            q.put(batch)
    except: pass
    finally:
        try: q.put_nowait(None)
        except _queue.Full: pass

async def _scan_loop(p, txt, csv_w, stop, pause, opens_ref, done_ref, t0, total):
    max_b = p.get("max_batches"); bnum = 0; exhausted = False
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(p["worker_count"])
    pq = _queue.Queue(maxsize=1)
    th = threading.Thread(target=_prefetcher, args=(p["_stream"], p["batch_size"], pq, stop), daemon=True)
    th.start()
    try:
        while not exhausted and not stop.is_set():
            if max_b and bnum >= max_b: break
            batch = await loop.run_in_executor(None, pq.get)
            if batch is None: exhausted = True; break
            bnum += 1; b_open = 0; b_done = 0
            suffix = f"/{max_b}" if max_b else ""
            print(f"\n {bold(f'── Batch {bnum}{suffix}')} ({len(batch)} hosts)")
            bt0 = time.perf_counter()
            rq = asyncio.Queue()
            tasks = [asyncio.create_task(_probe_q(ip, src, cap, p["port"], p["timeout"], sem, rq)) for ip, src, cap in batch]
            for _ in range(len(batch)):
                while not pause.is_set(): await asyncio.sleep(0.05)
                if stop.is_set():
                    for t in tasks: t.cancel()
                    break
                result, src, cap = await rq.get()
                done_ref[0] += 1; b_done += 1
                if result["status"] == "open":
                    opens_ref[0] += 1; b_open += 1; lat = result["latency_ms"]
                    txt.write(result["ip"] + "\n"); txt.flush()
                    csv_w.writerow([result["ip"], lat, p["port"], src]); txt.flush()
                    cap_s = f" [{cap}]" if cap else ""
                    src_s = f" ← {src}" if src != result["ip"] else ""
                    sys.stderr.write("\r" + " " * 80 + "\r"); sys.stderr.flush()
                    print(green(f" ✓ {result['ip']}:{p['port']} {lat} ms{src_s}{cap_s}"))
                print_progress(done_ref[0], total, opens_ref[0], t0, b_done, len(batch), bt0)
            await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.perf_counter() - bt0
            sys.stderr.write("\r" + " " * 80 + "\r"); sys.stderr.flush()
            print(dim(f" Batch done: {len(batch)} scanned, {b_open} open ({b_open/len(batch)*100:.1f}%) [{elapsed:.2f}s]"))
            if stop.is_set(): break
    finally:
        th.join(timeout=2)
    return exhausted

def run_scan(p, txt, csv_w, stop, pause, opens, done, t0, total):
    return asyncio.run(_scan_loop(p, txt, csv_w, stop, pause, opens, done, t0, total))

# ── controller ────────────────────────────────────────────────────────────────

def start_scan(p, all_files):
    all_descriptors = []; total_units = 0
    print(bold(cyan("\n ══════════════════════════════════════════════════")))
    for fpath in all_files:
        print(f" {bold('Loading')} {fpath} …")
        try:
            descs, invalid, stats = load_descriptors(fpath, p["target_mode"], p["max_cidr_hosts"], p["cidr_cap_mode"])
        except FileNotFoundError as e:
            print(red(f" SKIP: {e}")); continue
        all_descriptors.extend(descs)
        total_units += stats["total_scan_hosts"]
        if invalid: print(yellow(f"  {len(invalid)} invalid entries skipped"))

    if not all_descriptors:
        print(red(" No valid IPv4 targets found.")); return 1

    print(bold(cyan(" ══════════════════════════════════════════════════")))
    print(f" Total descriptors : {len(all_descriptors)}")
    print(f" Est. total hosts  : {total_units}")
    print(f" Port / Timeout    : {p['port']} / {p['timeout']}s")
    print(f" Batch / Conns     : {p['batch_size']} / {p['worker_count']}")
    print(f" Max batches       : {p['max_batches'] or 'unlimited'}")
    print(f" Target mode       : {p['target_mode']}  |  Scan order: {p['scan_mode']}")
    print(bold(cyan(" ══════════════════════════════════════════════════\n")))

    try:
        txt = open(p["txt_output"], "a", encoding="utf-8", newline="")
        csv_h = open(p["csv_output"], "a", encoding="utf-8", newline="")
        csv_w = csv.writer(csv_h)
        if csv_h.tell() == 0: csv_w.writerow(["IP", "Ping (ms)", "Port", "Source Range"])
    except OSError as e:
        print(red(f" Cannot open output files: {e}")); return 1

    stop = threading.Event(); pause = threading.Event(); pause.set()

    def _sig(s, f):
        sys.stderr.write("\r" + " " * 80 + "\r"); sys.stderr.flush()
        print(yellow("\n Ctrl+C — stopping after current batch…"))
        stop.set(); pause.set()
    signal.signal(signal.SIGINT, _sig)

    opens = [0]; done = [0]; t0 = time.perf_counter()
    p["_stream"] = stream_targets(all_descriptors, p["scan_mode"])

    try:
        while True:
            exhausted = run_scan(p, txt, csv_w, stop, pause, opens, done, t0, total_units)
            sys.stderr.write("\r" + " " * 80 + "\r"); sys.stderr.flush()
            if stop.is_set() or exhausted: break
            print(bold(cyan("\n ── Session complete ─────────────────────────────")))
            print(f" Open: {green(str(opens[0]))} | Scanned: {done[0]} | Saved → {p['txt_output']}")
            ans = input(cyan(" Continue? (n=stop, 0=all remaining, N=N more batches): ")).strip().lower()
            if ans in ("n", "no", "s", "stop"): break
            try: p["max_batches"] = None if int(ans) == 0 else max(int(ans), 1)
            except ValueError: p["max_batches"] = 1
    finally:
        txt.close(); csv_h.close()
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    elapsed = time.perf_counter() - t0
    print(bold(cyan("\n ══════════════════════════════════════════════════")))
    print(bold(f" Done — {opens[0]} open / {done[0]} scanned [{elapsed:.1f}s]"))
    print(f" Saved → {p['txt_output']} | {p['csv_output']}")
    print(bold(cyan(" ══════════════════════════════════════════════════\n")))
    return 0

def main():
    print(bold(cyan("""
╔══════════════════════════════════════════╗
║  CIDR / IPv4 TCP Batch Scanner           ║
╚══════════════════════════════════════════╝""")))
    cfg = load_config()

    # ── interactive prompts ────────────────────────────────────────────────
    selected_files = prompt_ranges(cfg)
    cfg["target_mode"] = prompt_target_mode(cfg.get("target_mode", "sample"))
    # ──────────────────────────────────────────────────────────────────────

    sys.exit(start_scan(cfg, selected_files))

if __name__ == "__main__":
    main()
