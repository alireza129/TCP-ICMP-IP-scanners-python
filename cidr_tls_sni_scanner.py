#!/usr/bin/env python3
"""
CIDR / IPv4 / Hostname Batch Scanner
Zero external dependencies, stdlib only.

Features:
- IPv4, CIDR, and hostname/domain inputs
- Config-driven predefined range files
- Mixed IP + domain targets in one run
- Streaming TCP scan over very large inputs
- TLS only on TCP-open targets
- Optional ICMP probes
- Reusable phase engine classes
- Prevent duplicate TLS scans across multiple 't' runs
- Summary of TCP-open but TLS-not-yet-tested targets
- SNI override support from prompt, folder, or file selection
"""

import asyncio
import csv
import ipaddress
import json
import multiprocessing
import os
import queue as _queue
import random
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

CONFIG_FILE = Path("config.json").resolve()
CONFIG_DIR = CONFIG_FILE.parent

DEFAULTS = {
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
    "builtin_catalogs": [],
    "catalogs": {},
    "protocols": ["tcp", "tls"],
    "dns_resolve_limit": 3,
    "tls_server_name_mode": "hostname_or_target",
    "sni_source_mode": "auto",
    "sni_single": "",
    "sni_folder": "sni_domains",
    "sni_files": [],
    "include_builtin_catalogs_by_default": False,
    "interactive_confirm_summary": True,
    "show_invalid_items": False,
}

PROTO_CHOICES = {
    "1": ("dns", "DNS resolution validation"),
    "2": ("tcp", "TCP connect test"),
    "3": ("tls", "TLS handshake test (only on TCP-open results)"),
    "4": ("icmp", "ICMP ping (requires root)"),
}


def load_config() -> dict:
    cfg = DEFAULTS.copy()
    if CONFIG_FILE.is_file():
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            cfg.update({k: v for k, v in json.load(f).items() if not k.startswith("_")})
    cfg["max_batches"] = cfg["max_batches"] or None
    return cfg


def resolve_config_path(path_str: str) -> Path:
    path = Path(path_str).expanduser()
    if not path.is_absolute():
        path = (CONFIG_DIR / path).resolve()
    return path


def _tty():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _tty() else text


green = lambda t: _c("32", t)
yellow = lambda t: _c("33", t)
red = lambda t: _c("31", t)
cyan = lambda t: _c("36", t)
dim = lambda t: _c("2", t)
bold = lambda t: _c("1", t)


def ask(prompt, cast=str, default=None):
    try:
        raw = input(cyan(prompt)).strip()
        return default if raw == "" else cast(raw)
    except Exception:
        return default


def get_cpu_count() -> int:
    return os.cpu_count() or multiprocessing.cpu_count() or 1


def get_ram_gb() -> float:
    if os.name == "nt":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return round(stat.ullTotalPhys / 1024 / 1024 / 1024, 2)
        except Exception:
            return 1.0

    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    return round(kb / 1024 / 1024, 2)
    except Exception:
        pass
    return 1.0


def detect_os() -> str:
    if os.name == "nt":
        return "Windows"
    for path in ["/etc/os-release", "/etc/centos-release", "/etc/redhat-release"]:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
            if "Ubuntu" in text:
                return "Ubuntu"
            if "Debian" in text:
                return "Debian"
            if "CentOS" in text:
                return "CentOS"
            if "Red Hat" in text:
                return "RHEL"
            if "Fedora" in text:
                return "Fedora"
        except Exception:
            pass
    return os.name


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def recommended_profile(ram_gb: float, cpu_count: int) -> dict:
    if ram_gb >= 8 and cpu_count >= 8:
        return {"profile": "High-Performance", "worker_count": 5000, "batch_size": 20000, "timeout": 3.0}
    if ram_gb >= 4 and cpu_count >= 4:
        return {"profile": "Standard", "worker_count": 2500, "batch_size": 10000, "timeout": 3.0}
    if ram_gb >= 2:
        return {"profile": "Medium", "worker_count": 1259, "batch_size": 5000, "timeout": 3.5}
    return {"profile": "Low-Resource", "worker_count": 500, "batch_size": 2000, "timeout": 4.0}


def prompt_system_profile(cfg: dict) -> dict:
    ram_gb = get_ram_gb()
    cpu_count = get_cpu_count()
    os_name = detect_os()
    root = is_root()
    rec = recommended_profile(ram_gb, cpu_count)

    print(bold(cyan("\n ── System Resources ───────────────────────────────")))
    print(f"  CPU cores : {cpu_count}")
    print(f"  RAM       : {ram_gb} GB")
    print(f"  OS        : {os_name}")
    print(f"  Root      : {'YES (ICMP available)' if root else 'NO (ICMP disabled)'}")
    print(cyan(" ────────────────────────────────────────────────────"))
    print(f"  Recommended profile : {green(rec['profile'])}")
    print(f"  Workers             : {rec['worker_count']}")
    print(f"  Batch size          : {rec['batch_size']}")
    print(f"  Timeout             : {rec['timeout']}s")

    if ask("  Use recommended settings? [Y/n]: ", str, "y").lower() != "n":
        cfg["worker_count"] = rec["worker_count"]
        cfg["batch_size"] = rec["batch_size"]
        cfg["timeout"] = rec["timeout"]
    return cfg


def prompt_protocols(cfg: dict) -> dict:
    print(bold(cyan("\n ── Protocol Selection ─────────────────────────────")))
    for k, (proto, desc) in PROTO_CHOICES.items():
        suffix = " (root required)" if proto == "icmp" and not is_root() else ""
        print(f"  [{k}] {proto:<5} — {desc}{suffix}")
    print(cyan(" ────────────────────────────────────────────────────"))
    print(dim("  Select one or more (comma-separated), e.g. 2,3"))

    default = [k for k, (p, _) in PROTO_CHOICES.items() if p in cfg.get("protocols", [])]
    default_str = ",".join(default) or "2,3"
    raw = ask(f"  Protocols [default: {default_str}]: ", str, default_str)

    selected = []
    for s in raw.split(","):
        s = s.strip()
        if s in PROTO_CHOICES:
            p = PROTO_CHOICES[s][0]
            if p == "icmp" and not is_root():
                print(yellow("  ↳ ICMP skipped — root required"))
                continue
            selected.append(p)

    cfg["protocols"] = selected or ["tcp", "tls"]
    return cfg


def prompt_more_settings(cfg: dict) -> dict:
    print(bold(cyan("\n ── Scan Tuning ─────────────────────────────────────")))
    fields = [
        ("port", int, "Port"),
        ("timeout", float, "Timeout seconds"),
        ("worker_count", int, "Worker count"),
        ("batch_size", int, "Batch size"),
        ("max_cidr_hosts", int, "Max CIDR hosts"),
        ("dns_resolve_limit", int, "DNS resolve limit per hostname"),
    ]
    for key, cast, label in fields:
        cfg[key] = ask(f"  {label} [{cfg[key]}]: ", cast, cfg[key])
    return cfg


def prompt_ranges(cfg: dict):
    entries = []

    for r in cfg.get("predefined_ranges", []):
        file_path = r.get("file")
        name = r.get("name", file_path or "?")
        if file_path:
            entries.append(("file", name, file_path))

    for f in cfg.get("target_files", []):
        entries.append(("file", f, f))

    catalogs = cfg.get("builtin_catalogs", [])
    if cfg.get("include_builtin_catalogs_by_default") and not catalogs:
        catalogs = list(cfg.get("catalogs", {}).keys())

    for c in catalogs:
        if c in cfg.get("catalogs", {}):
            entries.append(("catalog", f"[catalog] {c}", c))

    if not entries:
        print(red(" No ranges or catalogs defined in config.json."))
        sys.exit(1)

    print(bold(cyan("\n ── Available Inputs ───────────────────────────────")))
    for i, (_, name, value) in enumerate(entries, 1):
        shown = f"{name} -> {value}" if value != name and not name.startswith("[catalog]") else name
        print(f"  {i}.  {shown}")
    print(cyan(" ────────────────────────────────────────────────────"))
    print(dim("  Enter number(s) separated by commas, or 'a' for all."))

    while True:
        try:
            raw = input(cyan("  Select inputs: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw.lower() == "a":
            return [(e[0], e[2]) for e in entries]

        try:
            indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if not indices or any(i < 1 or i > len(entries) for i in indices):
                raise ValueError
        except ValueError:
            print(yellow(f"  ↳ enter number(s) between 1 and {len(entries)}, e.g. 1,3,5  or  a"))
            continue

        selected = [(entries[i - 1][0], entries[i - 1][2]) for i in indices]
        labels = [entries[i - 1][1] for i in indices]
        print(dim(f"  ✓ Selected: {', '.join(labels)}"))
        return selected


def prompt_target_mode(default: str) -> str:
    opts = ["sample", "all"]
    formatted = "  /  ".join(bold(f"[{o}]") if o == default else o for o in opts)
    print(bold(cyan("\n ── Target Mode ─────────────────────────────────────")))
    print("  sample  — probe only the first IP of each CIDR (fast, broad coverage)")
    print("  all     — probe every IP in each CIDR (slow, thorough)")
    print(cyan(" ────────────────────────────────────────────────────"))
    while True:
        try:
            raw = input(cyan(f"  Mode ({formatted}): ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if raw == "":
            print(dim(f"  ✓ Using default: {default}"))
            return default
        if raw in opts or raw in ("s", "a"):
            result = "sample" if raw in ("sample", "s") else "all"
            print(dim(f"  ✓ {result}"))
            return result
        print(yellow("  ↳ type sample or all (or s / a), Enter to keep default"))


def is_hostname(raw: str) -> bool:
    if not raw or " " in raw:
        return False
    try:
        ipaddress.ip_address(raw)
        return False
    except ValueError:
        pass
    parts = raw.split(".")
    return "." in raw and all(parts) and all(len(p) <= 63 for p in parts)


def load_sni_domains_from_lines(lines):
    domains = []
    seen = set()
    for line in lines:
        raw = line.strip().lower()
        if not raw or raw.startswith("#"):
            continue
        if is_hostname(raw) and raw not in seen:
            seen.add(raw)
            domains.append(raw)
    return domains


def load_sni_domains_from_file(path_str: str):
    path = resolve_config_path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"SNI file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return load_sni_domains_from_lines(f)


def list_sni_folder_files(cfg: dict):
    folder = resolve_config_path(cfg.get("sni_folder", "sni_domains"))
    if not folder.exists() or not folder.is_dir():
        return []
    return sorted([p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".txt", ".list", ".lst")])


def load_sni_domains_from_folder(cfg: dict, selected_files=None):
    files = selected_files or list_sni_folder_files(cfg)
    domains = []
    seen = set()
    for path in files:
        with path.open("r", encoding="utf-8") as f:
            for domain in load_sni_domains_from_lines(f):
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains


def prompt_sni_config(cfg: dict) -> dict:
    print(bold(cyan("\n ── SNI Source ──────────────────────────────────────")))
    print("  [1] Auto            — host target uses its own hostname, IP target uses no SNI override")
    print("  [2] Single SNI      — prompt for one SNI domain and reuse it for all TLS probes")
    print("  [3] SNI file/folder — load SNI domain candidates from configured folder or file list")
    print(cyan(" ────────────────────────────────────────────────────"))

    default_map = {"auto": "1", "single": "2", "folder": "3"}
    default_choice = default_map.get(cfg.get("sni_source_mode", "auto"), "1")
    choice = ask(f"  SNI source [default: {default_choice}]: ", str, default_choice).strip()

    if choice == "2":
        while True:
            sni = ask("  Enter SNI domain: ", str, cfg.get("sni_single", "")).strip().lower()
            if sni and is_hostname(sni):
                cfg["sni_source_mode"] = "single"
                cfg["sni_single"] = sni
                cfg["sni_files"] = []
                break
            print(yellow("  ↳ enter a valid hostname like example.com"))
        return cfg

    if choice == "3":
        cfg["sni_source_mode"] = "folder"
        files = list_sni_folder_files(cfg)
        configured = cfg.get("sni_files", []) or []
        if configured:
            print(dim(f"  Configured SNI files: {', '.join(configured)}"))
            use_cfg = ask("  Use configured SNI file list? [Y/n]: ", str, "y").strip().lower()
            if use_cfg != "n":
                cfg["sni_files"] = configured
                return cfg
        if not files:
            print(yellow(f"  ↳ no SNI files found in folder: {resolve_config_path(cfg.get('sni_folder', 'sni_domains'))}"))
            print(dim("  Falling back to single SNI prompt."))
            while True:
                sni = ask("  Enter SNI domain: ", str, cfg.get("sni_single", "")).strip().lower()
                if sni and is_hostname(sni):
                    cfg["sni_source_mode"] = "single"
                    cfg["sni_single"] = sni
                    cfg["sni_files"] = []
                    break
                print(yellow("  ↳ enter a valid hostname like example.com"))
            return cfg

        print(bold(cyan("\n ── Available SNI Files ─────────────────────────────")))
        for i, path in enumerate(files, 1):
            print(f"  {i}.  {path.name}")
        print(cyan(" ────────────────────────────────────────────────────"))
        print(dim("  Enter number(s) separated by commas, or 'a' for all."))

        while True:
            raw = ask("  Select SNI files: ", str, "a").strip().lower()
            if raw == "a":
                cfg["sni_files"] = [str(p.relative_to(CONFIG_DIR)) for p in files]
                break
            try:
                indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
                if not indices or any(i < 1 or i > len(files) for i in indices):
                    raise ValueError
            except ValueError:
                print(yellow(f"  ↳ enter number(s) between 1 and {len(files)}, e.g. 1,3 or a"))
                continue
            selected = [files[i - 1] for i in indices]
            cfg["sni_files"] = [str(p.relative_to(CONFIG_DIR)) for p in selected]
            break
        return cfg

    cfg["sni_source_mode"] = "auto"
    cfg["sni_single"] = ""
    cfg["sni_files"] = []
    return cfg


def iter_scan_hosts(net):
    if net.prefixlen == 32:
        yield net.network_address
    elif net.prefixlen == 31:
        yield net.network_address
        yield net.broadcast_address
    else:
        yield from net.hosts()


def count_scan_hosts(net):
    if net.prefixlen == 32:
        return 1
    if net.prefixlen == 31:
        return 2
    return max(net.num_addresses - 2, 0)


def first_scan_host(net):
    for ip in iter_scan_hosts(net):
        return ip


def reservoir_sample(iterable, k):
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


@dataclass(frozen=True)
class TargetItem:
    kind: str
    target: str
    source: str
    cap: str | None = None

    @property
    def key(self):
        return (self.kind, self.target)


def descriptor_iter(desc):
    t, src, cap = desc["type"], desc["source"], desc["cap_label"]
    if t == "ip":
        yield TargetItem("ip", desc["ip"], src, cap)
        return
    if t == "host":
        yield TargetItem("host", desc["host"], src, cap)
        return

    net = desc["net"]
    if t == "cidr_sample":
        ip = first_scan_host(net)
        if ip:
            yield TargetItem("ip", str(ip), src, cap)
    elif t == "cidr_all":
        for ip in iter_scan_hosts(net):
            yield TargetItem("ip", str(ip), src, cap)
    elif t == "cidr_capped_seq":
        for ip in islice(iter_scan_hosts(net), desc["cap_k"]):
            yield TargetItem("ip", str(ip), src, cap)
    elif t == "cidr_capped_rnd":
        for ip in reservoir_sample(iter_scan_hosts(net), desc["cap_k"]):
            yield TargetItem("ip", str(ip), src, cap)


def parse_line(raw, target_mode, max_cidr_hosts, cidr_cap_mode):
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
            return {"type": "cidr_sample", "net": net, "source": raw, "cap_label": None, "count": 1}, False, None

        if total <= max_cidr_hosts:
            return {"type": "cidr_all", "net": net, "source": raw, "cap_label": None, "count": total}, False, None

        cap_label = f"seq {max_cidr_hosts}/{total}" if cidr_cap_mode == "sequential" else f"rnd {max_cidr_hosts}/{total}"
        dtype = "cidr_capped_seq" if cidr_cap_mode == "sequential" else "cidr_capped_rnd"
        return {
            "type": dtype,
            "net": net,
            "source": raw,
            "cap_label": cap_label,
            "count": max_cidr_hosts,
            "cap_k": max_cidr_hosts,
        }, False, None

    try:
        ip = ipaddress.ip_address(raw)
        if ip.version != 4:
            return None, True, f"{raw} (IPv6 skipped)"
        return {"type": "ip", "ip": str(ip), "source": raw, "cap_label": None, "count": 1}, False, None
    except ValueError:
        pass

    if is_hostname(raw):
        return {"type": "host", "host": raw, "source": raw, "cap_label": None, "count": 1}, False, None

    return None, True, raw


def load_descriptors_from_lines(lines, target_mode, max_cidr_hosts, cidr_cap_mode):
    descriptors, invalid, seen = [], [], set()
    stats = {
        "raw_entries": 0,
        "single_ips": 0,
        "cidr_entries": 0,
        "host_entries": 0,
        "total_scan_hosts": 0,
        "cidrs_capped": 0,
        "invalid_items": 0,
    }

    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue

        stats["raw_entries"] += 1
        desc, is_bad, err = parse_line(raw, target_mode, max_cidr_hosts, cidr_cap_mode)
        if is_bad:
            invalid.append(err)
            continue

        key = (desc["type"], desc.get("ip") or desc.get("host") or desc["source"])
        if key in seen and desc["type"] in ("ip", "host"):
            continue
        seen.add(key)

        if desc["type"] == "ip":
            stats["single_ips"] += 1
        elif desc["type"] == "host":
            stats["host_entries"] += 1
        else:
            stats["cidr_entries"] += 1
            if desc["type"] in ("cidr_capped_seq", "cidr_capped_rnd"):
                stats["cidrs_capped"] += 1

        stats["total_scan_hosts"] += desc["count"]
        descriptors.append(desc)

    stats["invalid_items"] = len(invalid)
    return descriptors, invalid, stats


def load_descriptors(file_path, target_mode, max_cidr_hosts, cidr_cap_mode):
    path = resolve_config_path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return load_descriptors_from_lines(f, target_mode, max_cidr_hosts, cidr_cap_mode)


def load_catalog_descriptors(cfg, name, target_mode, max_cidr_hosts, cidr_cap_mode):
    return load_descriptors_from_lines(cfg.get("catalogs", {}).get(name, []), target_mode, max_cidr_hosts, cidr_cap_mode)


def stream_targets(descriptors, scan_mode):
    if scan_mode == "randomized":
        descriptors = random.sample(descriptors, len(descriptors))
    seen = set()
    for desc in descriptors:
        for item in descriptor_iter(desc):
            if item.key in seen:
                continue
            seen.add(item.key)
            yield item


async def resolve_ipv4s(target, port=None, limit=3):
    infos = await asyncio.to_thread(socket.getaddrinfo, target, port, socket.AF_INET, socket.SOCK_STREAM)
    ipv4s = []
    for info in infos:
        ip = info[4][0]
        if ip not in ipv4s:
            ipv4s.append(ip)
    return ipv4s[:limit]


def result_ok(latency=None, ip="", **extra):
    return {"status": "open", "latency_ms": latency, "error": "", "resolved_ip": ip, **extra}


def result_fail(error, **extra):
    return {"status": "closed", "latency_ms": None, "error": error, "resolved_ip": "", **extra}


async def dns_probe(item, timeout):
    if item.kind != "host":
        return {"status": "skipped", "latency_ms": None, "error": "not_hostname", "resolved_ip": ""}
    t = time.perf_counter()
    try:
        ipv4s = await resolve_ipv4s(item.target, limit=3)
        return {
            "status": "open" if ipv4s else "closed",
            "latency_ms": round((time.perf_counter() - t) * 1000, 2),
            "error": "" if ipv4s else "dns_no_a_record",
            "resolved_ip": ",".join(ipv4s[:3]),
        }
    except Exception as e:
        return {"status": "closed", "latency_ms": None, "error": type(e).__name__, "resolved_ip": ""}


async def tcp_probe(item, port, timeout, sem, dns_resolve_limit):
    async with sem:
        t = time.perf_counter()
        target = item.target
        try:
            if item.kind == "host":
                ipv4s = await resolve_ipv4s(target, port, dns_resolve_limit)
                if not ipv4s:
                    return result_fail("dns_no_a_record")

                last_err = "connect_failed"
                for ip in ipv4s:
                    writer = None
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port),
                            timeout=timeout,
                        )
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
                        except Exception:
                            pass
                        return result_ok(round((time.perf_counter() - t) * 1000, 2), ip)
                    except (asyncio.TimeoutError, TimeoutError):
                        last_err = "timeout"
                    except OSError as e:
                        last_err = type(e).__name__
                    finally:
                        if writer is not None:
                            try:
                                writer.close()
                            except Exception:
                                pass

                return result_fail(last_err)

            else:
                writer = None
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout,
                    )
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
                    except Exception:
                        pass
                    return result_ok(round((time.perf_counter() - t) * 1000, 2), target)
                finally:
                    if writer is not None:
                        try:
                            writer.close()
                        except Exception:
                            pass

        except socket.gaierror:
            return result_fail("dns_failed")
        except (asyncio.TimeoutError, TimeoutError):
            return result_fail("timeout")
        except OSError as e:
            return result_fail(type(e).__name__)

def _sync_tls_handshake(host_for_connect, connect_port, sni_name, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    with socket.create_connection((host_for_connect, connect_port), timeout=timeout) as raw:
        raw.settimeout(timeout)

        with ctx.wrap_socket(
            raw,
            server_hostname=sni_name,
            do_handshake_on_connect=False,
        ) as tls_sock:
            tls_sock.settimeout(timeout)
            tls_sock.do_handshake()
            cipher = tls_sock.cipher()
            return {
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "used_sni": sni_name,
                "tls_version": tls_sock.version() or "",
                "tls_cipher": cipher[0] if cipher else "",
            }

def get_sni_candidates(item, cfg, state):
    mode = cfg.get("sni_source_mode", "auto")
    if mode == "single":
        return [cfg.get("sni_single", "")] if cfg.get("sni_single") else []
    if mode == "folder":
        return list(state.sni_candidates)
    if item.kind == "host" and cfg.get("tls_server_name_mode") == "hostname_or_target":
        return [item.target]
    return []


async def tls_probe_single_sni(item, port, timeout, sem, dns_resolve_limit, sni, resolved_ip=None):
    """Probe a single (IP, SNI) pair. Returns a result dict for that one combination."""
    async with sem:
        try:
            if resolved_ip:
                ip = resolved_ip
            elif item.kind == "host":
                ipv4s = await resolve_ipv4s(item.target, port, dns_resolve_limit)
                if not ipv4s:
                    return result_fail("dns_no_a_record", used_sni=sni, tls_version="", tls_cipher="")
                ip = ipv4s[0]
            else:
                ip = item.target

            info = await asyncio.wait_for(
                asyncio.to_thread(_sync_tls_handshake, ip, port, sni, timeout),
                timeout=timeout + 1.0,
            )

            return result_ok(
                info["latency_ms"],
                ip,
                used_sni=info["used_sni"],
                tls_version=info["tls_version"],
                tls_cipher=info["tls_cipher"],
            )

        except (asyncio.TimeoutError, TimeoutError, socket.timeout):
            return result_fail("tls_timeout", used_sni=sni, tls_version="", tls_cipher="")
        except ssl.SSLError as e:
            return result_fail(f"{type(e).__name__}@{sni}", used_sni=sni, tls_version="", tls_cipher="")
        except OSError as e:
            return result_fail(f"{type(e).__name__}@{sni}", used_sni=sni, tls_version="", tls_cipher="")
        except Exception as e:
            return result_fail(f"{type(e).__name__}@{sni}", used_sni=sni, tls_version="", tls_cipher="")

async def tls_probe(item, port, timeout, sem, dns_resolve_limit, cfg, state, sni_override=None, sni_candidates=None):
    """Legacy single-probe wrapper kept for compatibility. Returns first success."""
    target = item.target
    try:
        if item.kind == "host":
            ipv4s = await resolve_ipv4s(target, port, dns_resolve_limit)
            if not ipv4s:
                return result_fail("dns_no_a_record")
        else:
            ipv4s = [target]

        candidates = []
        if sni_override:
            candidates = [sni_override]
        elif sni_candidates is not None:
            candidates = [s for s in sni_candidates if s]
        else:
            candidates = get_sni_candidates(item, cfg, state)

        seen = set()
        ordered_candidates = []
        for c in candidates:
            c = c.strip().lower()
            if c and c not in seen:
                seen.add(c)
                ordered_candidates.append(c)

        if not ordered_candidates:
            return result_fail("no_sni_candidates", used_sni="", tls_version="", tls_cipher="")

        last_err = "tls_failed"
        for ip in ipv4s:
            for sni in ordered_candidates:
                r = await tls_probe_single_sni(item, port, timeout, sem, dns_resolve_limit, sni, resolved_ip=ip)
                if r["status"] == "open":
                    return r
                last_err = r["error"]
        return result_fail(last_err, used_sni="", tls_version="", tls_cipher="")
    except Exception as e:
        return result_fail(type(e).__name__, used_sni="", tls_version="", tls_cipher="")


def _icmp_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += data[i] + (data[i + 1] << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _sync_icmp_probe(ip: str, timeout: float):
    if not is_root():
        raise PermissionError("root required")
    resolved = socket.gethostbyname(ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    pid = os.getpid() & 0xFFFF
    seq = 1
    header = struct.pack("bbHHh", 8, 0, 0, pid, seq)
    data = b"batch-scan"
    chk = _icmp_checksum(header + data)
    header = struct.pack("bbHHh", 8, 0, chk, pid, seq)
    packet = header + data
    t0 = time.perf_counter()
    sock.sendto(packet, (resolved, 0))
    while True:
        ready = select.select([sock], [], [], timeout)
        if not ready[0]:
            sock.close()
            raise TimeoutError("icmp timeout")
        recv, _ = sock.recvfrom(1024)
        if len(recv) >= 28:
            icmp_hdr = recv[20:28]
            r_type, _, _, r_pid, _ = struct.unpack("bbHHh", icmp_hdr)
            if r_type == 0 and r_pid == pid:
                sock.close()
                return round((time.perf_counter() - t0) * 1000, 2)


async def icmp_probe(item, timeout):
    if not is_root():
        return {"status": "skipped", "latency_ms": None, "error": "root_required", "resolved_ip": ""}
    if item.kind == "host":
        try:
            ipv4s = await resolve_ipv4s(item.target, limit=1)
            if not ipv4s:
                return result_fail("dns_no_a_record")
            ip = ipv4s[0]
        except Exception as e:
            return result_fail(type(e).__name__)
    else:
        ip = item.target
    try:
        latency = await asyncio.to_thread(_sync_icmp_probe, ip, timeout)
        return result_ok(latency, ip)
    except Exception as e:
        return result_fail(type(e).__name__)


@dataclass
class PhaseRecord:
    item: TargetItem
    result: dict

    @property
    def is_open(self):
        return self.result.get("status") == "open"


@dataclass
class ScanState:
    tcp_open: dict = field(default_factory=dict)
    tls_seen: set = field(default_factory=set)
    tls_open: dict = field(default_factory=dict)
    # Maps item.key -> set of accepted SNIs
    tls_sni_hits: dict = field(default_factory=dict)
    sni_candidates: list = field(default_factory=list)
    tcp_stream: object | None = None
    tcp_exhausted: bool = False
    tcp_done_total: int = 0

    def add_tcp_open(self, item: TargetItem):
        self.tcp_open[item.key] = item

    def mark_tls_seen(self, item: TargetItem):
        self.tls_seen.add(item.key)

    def add_tls_open(self, item: TargetItem, sni: str = ""):
        self.tls_open[item.key] = item
        self.tls_seen.add(item.key)
        if sni:
            self.tls_sni_hits.setdefault(item.key, set()).add(sni)

    def record_tls_sni_hit(self, item: TargetItem, sni: str):
        """Record a successful (IP, SNI) pair. Marks the IP as tls_open."""
        self.tls_open[item.key] = item
        self.tls_seen.add(item.key)
        if sni:
            self.tls_sni_hits.setdefault(item.key, set()).add(sni)

    @property
    def tcp_open_count(self):
        return len(self.tcp_open)

    @property
    def tls_tested_count(self):
        return len(self.tls_seen)

    @property
    def tls_open_count(self):
        return len(self.tls_open)

    @property
    def tls_total_sni_hits(self):
        return sum(len(v) for v in self.tls_sni_hits.values())

    def tls_pending_items(self):
        return [item for key, item in self.tcp_open.items() if key not in self.tls_seen]

    @property
    def tls_pending_count(self):
        return len(self.tls_pending_items())


def _prefetcher(stream, bsize, q, stop):
    try:
        while not stop.is_set():
            batch = list(islice(stream, bsize))
            if not batch:
                q.put(None)
                return
            q.put(batch)
    except Exception:
        pass
    finally:
        try:
            q.put_nowait(None)
        except _queue.Full:
            pass


def _fmt_eta(seconds):
    if seconds < 0:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def print_progress(done, total_hint, opens, t0, bd=0, bt=0, bt0=None, w=40, label=""):
    pct = (done / total_hint) if total_hint else 0
    bar = "█" * int(min(pct, 1) * w) + "░" * (w - int(min(pct, 1) * w))
    elapsed = time.perf_counter() - t0
    rate = done / elapsed if elapsed > 0.5 else 0
    rate_s = f"{rate:.0f}/s" if elapsed > 0.5 else "..."
    total_s = total_hint if total_hint else "?"
    file_eta = _fmt_eta((total_hint - done) / rate) if rate > 0 and total_hint and total_hint > done else ("..." if not total_hint else "done")
    if bt0 and bd > 0:
        br = bd / (time.perf_counter() - bt0) if (time.perf_counter() - bt0) > 0 else 0
        b_eta = _fmt_eta((bt - bd) / br) if br > 0 and bt > bd else ("done" if bd >= bt else "...")
    else:
        b_eta = "..."
    prefix = f"{label} " if label else ""
    sys.stderr.write(f"\r {prefix}[{bar}] {pct*100:5.1f}% {done}/{total_s} open:{opens} {rate_s} │ batch:{b_eta} file:{file_eta} ")
    sys.stderr.flush()


class ScanPhase:
    name = "BASE"

    def __init__(self, cfg, txt, csv_w, stop, pause, t0, state=None):
        self.cfg = cfg
        self.txt = txt
        self.csv_w = csv_w
        self.stop = stop
        self.pause = pause
        self.t0 = t0
        self.state = state
        self.sem = asyncio.Semaphore(cfg["worker_count"])

    async def probe_one(self, item: TargetItem) -> PhaseRecord:
        raise NotImplementedError

    def on_open(self, record: PhaseRecord, state: ScanState):
        pass

    def write_open(self, record: PhaseRecord):
        best = record.result.get("resolved_ip") or record.item.target
        lat = record.result.get("latency_ms")
        used_sni = record.result.get("used_sni", "")
        tls_version = record.result.get("tls_version", "")
        tls_cipher = record.result.get("tls_cipher", "")
        self.txt.write(best + "\n")
        self.txt.flush()
        self.csv_w.writerow([
            record.item.target,
            record.item.kind,
            best,
            lat,
            self.cfg["port"],
            self.name.lower(),
            record.item.source,
            used_sni,
            tls_version,
            tls_cipher,
        ])
        cap_s = f" [{record.item.cap}]" if record.item.cap else ""
        src_s = f" ← {record.item.source}" if record.item.source != record.item.target else ""
        sni_s = f" sni={used_sni}" if used_sni else ""
        sys.stderr.write("\r" + " " * 120 + "\r")
        sys.stderr.flush()
        print(green(f" ✓ [{self.name}] {record.item.target} -> {best}:{self.cfg['port']} {lat if lat is not None else '-'} ms{sni_s}{src_s}{cap_s}"))

    async def _probe_q(self, item, q):
        await q.put(await self.probe_one(item))


class TCPPhase(ScanPhase):
    name = "TCP"

    async def probe_one(self, item: TargetItem) -> PhaseRecord:
        r = await tcp_probe(item, self.cfg["port"], self.cfg["timeout"], self.sem, self.cfg["dns_resolve_limit"])
        return PhaseRecord(item=item, result=r)

    def on_open(self, record: PhaseRecord, state: ScanState):
        state.add_tcp_open(record.item)

    async def run_stream(self, state: ScanState, total_hint=None):
        loop = asyncio.get_running_loop()
        pq = _queue.Queue(maxsize=1)
        th = threading.Thread(target=_prefetcher, args=(state.tcp_stream, self.cfg["batch_size"], pq, self.stop), daemon=True)
        th.start()
        max_b = self.cfg.get("max_batches")
        bnum = 0
        done = 0
        opens = 0
        exhausted = False

        try:
            while not self.stop.is_set():
                if max_b and bnum >= max_b:
                    break

                batch = await loop.run_in_executor(None, pq.get)
                if batch is None:
                    exhausted = True
                    state.tcp_exhausted = True
                    break

                bnum += 1
                b_done = 0
                b_open = 0
                suffix = f"/{max_b}" if max_b else ""
                print(f"\n {bold(f'── {self.name} Batch {bnum}{suffix}')} ({len(batch)} targets)")
                bt0 = time.perf_counter()
                rq = asyncio.Queue()
                tasks = [asyncio.create_task(self._probe_q(item, rq)) for item in batch]

                for _ in range(len(batch)):
                    while not self.pause.is_set():
                        await asyncio.sleep(0.05)

                    if self.stop.is_set():
                        for t in tasks:
                            t.cancel()
                        break

                    record = await rq.get()
                    done += 1
                    state.tcp_done_total += 1
                    b_done += 1

                    if record.is_open:
                        opens += 1
                        b_open += 1
                        self.on_open(record, state)
                        self.write_open(record)

                    print_progress(state.tcp_done_total, total_hint, state.tcp_open_count, self.t0, b_done, len(batch), bt0, label=self.name)

                await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.perf_counter() - bt0
                sys.stderr.write("\r" + " " * 120 + "\r")
                sys.stderr.flush()
                print(dim(f" {self.name} batch done: {len(batch)} scanned, {b_open} responsive ({b_open/len(batch)*100:.1f}%) [{elapsed:.2f}s]"))
        finally:
            th.join(timeout=2)

        return {"done": done, "open": opens, "exhausted": exhausted}


@dataclass(frozen=True)
class TLSProbeTask:
    """Represents one (item, resolved_ip, sni) unit of TLS work."""
    item: TargetItem
    resolved_ip: str
    sni: str

    @property
    def key(self):
        return (self.resolved_ip, self.sni)


class TLSPhase(ScanPhase):
    name = "TLS"

    def __init__(self, cfg, txt, csv_w, stop, pause, t0, state=None):
        super().__init__(cfg, txt, csv_w, stop, pause, t0, state)
        self.sem = asyncio.Semaphore(cfg.get("tls_worker_count", 2000))

    async def probe_one(self, item: TargetItem) -> PhaseRecord:
        # Legacy single-probe path (used if TLSPhase is ever called outside run_items)
        r = await tls_probe(
            item,
            self.cfg["port"],
            self.cfg.get("tls_timeout", 10.0),
            self.sem,
            self.cfg["dns_resolve_limit"],
            self.cfg,
            self.state,
        )
        return PhaseRecord(item=item, result=r)

    def on_open(self, record: PhaseRecord, state: ScanState):
        sni = record.result.get("used_sni", "")
        state.record_tls_sni_hit(record.item, sni)

    def write_sni_hit(self, task: TLSProbeTask, result: dict):
        """Write one successful (IP, SNI) result row."""
        lat = result.get("latency_ms")
        sni = result.get("used_sni", task.sni)
        tls_version = result.get("tls_version", "")
        tls_cipher = result.get("tls_cipher", "")
        ip = result.get("resolved_ip") or task.resolved_ip

        self.txt.write(ip + "\n")
        self.txt.flush()
        self.csv_w.writerow([
            task.item.target,
            task.item.kind,
            ip,
            lat,
            self.cfg["port"],
            "tls",
            task.item.source,
            sni,
            tls_version,
            tls_cipher,
        ])
        cap_s = f" [{task.item.cap}]" if task.item.cap else ""
        src_s = f" ← {task.item.source}" if task.item.source != task.item.target else ""
        sys.stderr.write("\r" + " " * 120 + "\r")
        sys.stderr.flush()
        print(green(f" ✓ [TLS] {task.item.target} ({ip}) sni={sni} {lat if lat is not None else '-'} ms {tls_version}{src_s}{cap_s}"))

    async def _probe_sni_task_q(self, task: TLSProbeTask, q: asyncio.Queue):
        """Probe one (IP, SNI) pair and push result to queue."""
        r = await tls_probe_single_sni(
            task.item,
            self.cfg["port"],
            self.cfg.get("tls_timeout", 10.0),
            self.sem,
            self.cfg["dns_resolve_limit"],
            task.sni,
            resolved_ip=task.resolved_ip,
        )
        await q.put((task, r))

    async def _expand_items_to_tasks(self, items: list) -> list:
        """
        Resolve each TargetItem to its IPs and pair with every SNI candidate,
        producing a flat list of TLSProbeTask objects.
        """
        sni_list = list(self.state.sni_candidates) if self.state else []
        mode = self.cfg.get("sni_source_mode", "auto")

        tasks = []
        for item in items:
            # Resolve IPs
            if item.kind == "host":
                try:
                    ipv4s = await resolve_ipv4s(item.target, self.cfg["port"], self.cfg["dns_resolve_limit"])
                except Exception:
                    ipv4s = []
                if not ipv4s:
                    # Mark as seen so it doesn't linger in pending
                    self.state.mark_tls_seen(item)
                    continue
            else:
                ipv4s = [item.target]

            # Determine SNI candidates for this item
            if mode == "single":
                snis = [self.cfg.get("sni_single", "")] if self.cfg.get("sni_single") else []
            elif mode == "folder":
                snis = sni_list
            else:
                # auto: use hostname as SNI for host items, empty for IPs
                snis = [item.target] if item.kind == "host" else []

            if not snis:
                self.state.mark_tls_seen(item)
                continue

            # Mark the item as TLS-tested (we're about to probe it)
            self.state.mark_tls_seen(item)

            # Deduplicate SNIs
            seen_sni: set = set()
            for sni in snis:
                sni = sni.strip().lower()
                if sni and sni not in seen_sni:
                    seen_sni.add(sni)
                    for ip in ipv4s:
                        tasks.append(TLSProbeTask(item=item, resolved_ip=ip, sni=sni))

        return tasks

    async def run_items(self, items, state: ScanState):
        """
        Expand items into (IP × SNI) pairs and probe them all with a true
        sliding-window model. The semaphore (tls_worker_count) caps concurrency;
        results are consumed in completion order so a single slow timeout
        never stalls the rest.
        """
        items = list(items)

        print(dim(f"\n Resolving IPs and expanding SNI pairs for {len(items)} TCP-open target(s)…"))
        all_tasks = await self._expand_items_to_tasks(items)

        if not all_tasks:
            print(yellow(" No (IP, SNI) pairs to probe — check SNI source config."))
            return {"done": 0, "open": 0, "exhausted": True}

        sni_count = len(self.state.sni_candidates) if self.state and self.state.sni_candidates else "?"
        print(dim(f" Expanded to {len(all_tasks)} (IP × SNI) probe pairs "
                  f"({len(items)} IP(s) × {sni_count} SNI(s))"))

        total = len(all_tasks)
        done = 0
        opens = 0
        bt0 = time.perf_counter()

        rq: asyncio.Queue = asyncio.Queue()

        async def _fire(tls_task: TLSProbeTask):
            r = await tls_probe_single_sni(
                tls_task.item,
                self.cfg["port"],
                self.cfg.get("tls_timeout", 10.0),
                self.sem,
                self.cfg["dns_resolve_limit"],
                tls_task.sni,
                resolved_ip=tls_task.resolved_ip,
            )
            await rq.put((tls_task, r))

        all_async_tasks = [
            asyncio.create_task(_fire(t))
            for t in all_tasks
            if not self.stop.is_set()
        ]

        try:
            for _ in range(len(all_async_tasks)):
                while not self.pause.is_set():
                    await asyncio.sleep(0.05)

                if self.stop.is_set():
                    for at in all_async_tasks:
                        at.cancel()
                    break

                tls_task, result = await rq.get()
                done += 1

                if result.get("status") == "open":
                    opens += 1
                    state.record_tls_sni_hit(tls_task.item, result.get("used_sni", tls_task.sni))
                    self.write_sni_hit(tls_task, result)

                print_progress(done, total, opens, self.t0, done, total, bt0, label=self.name)

        finally:
            await asyncio.gather(*all_async_tasks, return_exceptions=True)

        
        if state.tls_sni_hits:
            print(bold(cyan("\n ── TLS SNI Acceptance Summary ─────────────────────")))
            for key, accepted_snis in sorted(state.tls_sni_hits.items()):
                ip = key[1]
                print(f"  {green(ip)}: {len(accepted_snis)} SNI(s) accepted")
                for sni in sorted(accepted_snis):
                    print(dim(f"    • {sni}"))
            print(cyan(" ────────────────────────────────────────────────────"))

        return {"done": done, "open": opens, "exhausted": done >= total}


class ICMPPhase(ScanPhase):
    name = "ICMP"

    async def probe_one(self, item: TargetItem) -> PhaseRecord:
        r = await icmp_probe(item, self.cfg["timeout"])
        return PhaseRecord(item=item, result=r)

    async def run_items(self, items, state: ScanState):
        items = list(items)
        total = len(items)
        done = 0
        opens = 0
        loop = asyncio.get_running_loop()
        pq = _queue.Queue(maxsize=1)
        th = threading.Thread(target=_prefetcher, args=(iter(items), self.cfg["batch_size"], pq, self.stop), daemon=True)
        th.start()
        max_b = self.cfg.get("max_batches")
        bnum = 0

        try:
            while not self.stop.is_set():
                if max_b and bnum >= max_b:
                    break

                batch = await loop.run_in_executor(None, pq.get)
                if batch is None:
                    break

                bnum += 1
                b_done = 0
                b_open = 0
                suffix = f"/{max_b}" if max_b else ""
                print(f"\n {bold(f'── {self.name} Batch {bnum}{suffix}')} ({len(batch)} targets)")
                bt0 = time.perf_counter()
                rq = asyncio.Queue()
                tasks = [asyncio.create_task(self._probe_q(item, rq)) for item in batch]

                for _ in range(len(batch)):
                    while not self.pause.is_set():
                        await asyncio.sleep(0.05)

                    if self.stop.is_set():
                        for t in tasks:
                            t.cancel()
                        break

                    record = await rq.get()
                    done += 1
                    b_done += 1

                    if record.is_open:
                        opens += 1
                        b_open += 1
                        self.write_open(record)

                    print_progress(done, total, opens, self.t0, b_done, len(batch), bt0, label=self.name)

                await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.perf_counter() - bt0
                sys.stderr.write("\r" + " " * 120 + "\r")
                sys.stderr.flush()
                print(dim(f" {self.name} batch done: {len(batch)} scanned, {b_open} responsive ({b_open/len(batch)*100:.1f}%) [{elapsed:.2f}s]"))
        finally:
            th.join(timeout=2)

        return {"done": done, "open": opens, "exhausted": done >= total}


def run_tcp_phase(phase: TCPPhase, state: ScanState, total_hint=None):
    return asyncio.run(phase.run_stream(state, total_hint))


def run_items_phase(method, items, state: ScanState):
    return asyncio.run(method(items, state))


def load_all_inputs(cfg, all_inputs):
    all_descriptors = []
    total_units = 0

    print(bold(cyan("\n ══════════════════════════════════════════════════")))
    for kind, value in all_inputs:
        print(f" {bold('Loading')} {value} …")
        try:
            if kind == "catalog":
                descs, invalid, stats = load_catalog_descriptors(
                    cfg, value, cfg["target_mode"], cfg["max_cidr_hosts"], cfg["cidr_cap_mode"]
                )
            else:
                descs, invalid, stats = load_descriptors(
                    value, cfg["target_mode"], cfg["max_cidr_hosts"], cfg["cidr_cap_mode"]
                )
        except FileNotFoundError as e:
            print(red(f" SKIP: {e}"))
            continue

        all_descriptors.extend(descs)
        total_units += stats["total_scan_hosts"]

        if invalid and cfg.get("show_invalid_items"):
            for bad in invalid[:20]:
                print(yellow(f"  invalid: {bad}"))
        elif invalid:
            print(yellow(f"  {len(invalid)} invalid entries skipped"))

    if not all_descriptors:
        print(red(" No valid IPv4 or hostname targets found."))
        return None, 0

    return all_descriptors, total_units


def print_state_summary(state: ScanState):
    print(bold(cyan("\n ── Phase Summary ─────────────────────────────────")))
    print(f" TCP scanned total           : {state.tcp_done_total}")
    print(f" TCP-open total              : {green(str(state.tcp_open_count))}")
    print(f" TLS-tested total (IPs)      : {state.tls_tested_count}")
    print(f" TLS-open total (IPs)        : {green(str(state.tls_open_count))}")
    print(f" TLS SNI hits (IP×SNI pairs) : {green(str(state.tls_total_sni_hits))}")
    print(f" TCP-open, TLS pending       : {yellow(str(state.tls_pending_count))}")
    print(f" TCP source exhausted        : {'yes' if state.tcp_exhausted else 'no'}")
    print(cyan(" ────────────────────────────────────────────────────"))


def prepare_sni_candidates(cfg, state):
    mode = cfg.get("sni_source_mode", "auto")
    if mode == "single":
        state.sni_candidates = [cfg["sni_single"]] if cfg.get("sni_single") else []
        return
    if mode == "folder":
        selected_files = []
        for file_path in cfg.get("sni_files", []) or []:
            try:
                selected_files.append(resolve_config_path(file_path))
            except Exception:
                pass
        if not selected_files:
            selected_files = list_sni_folder_files(cfg)
        state.sni_candidates = load_sni_domains_from_folder(cfg, selected_files)
        return
    state.sni_candidates = []


def start_scan(cfg, all_inputs):
    all_descriptors, total_units = load_all_inputs(cfg, all_inputs)
    if not all_descriptors:
        return 1

    state = ScanState()
    prepare_sni_candidates(cfg, state)
    state.tcp_stream = stream_targets(all_descriptors, cfg["scan_mode"])

    print(bold(cyan(" ══════════════════════════════════════════════════")))
    print(f" Total descriptors : {len(all_descriptors)}")
    print(f" Est. total targets: {total_units}")
    print(f" Port / Timeout    : {cfg['port']} / {cfg['timeout']}s")
    print(f" Batch / Workers   : {cfg['batch_size']} / {cfg['worker_count']}")
    print(f" Max batches       : {cfg['max_batches'] or 'unlimited'}")
    print(f" Target mode       : {cfg['target_mode']}  |  Scan order: {cfg['scan_mode']}")
    print(f" Protocols         : {', '.join(cfg['protocols'])}")
    print(f" SNI mode          : {cfg['sni_source_mode']}")
    if cfg['sni_source_mode'] == 'single' and cfg.get('sni_single'):
        print(f" SNI single        : {cfg['sni_single']}")
    elif cfg['sni_source_mode'] == 'folder':
        print(f" SNI candidates    : {len(state.sni_candidates)} loaded")
    print(f" Output            : {cfg['txt_output']} | {cfg['csv_output']}")
    print(bold(cyan(" ══════════════════════════════════════════════════\n")))

    if cfg.get("interactive_confirm_summary", True):
        raw = input(cyan(" Start scan? [Y/n]: ")).strip().lower()
        if raw == "n":
            print("Aborted.")
            return 0

    try:
        txt_path = resolve_config_path(cfg["txt_output"])
        csv_path = resolve_config_path(cfg["csv_output"])
        txt_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        txt = open(txt_path, "a", encoding="utf-8", newline="")
        csv_h = open(csv_path, "a", encoding="utf-8", newline="")
        csv_w = csv.writer(csv_h)
        if csv_h.tell() == 0:
            csv_w.writerow(["Target", "Kind", "Resolved IP", "Latency (ms)", "Port", "Phase", "Source", "Used SNI", "TLS Version", "TLS Cipher"])
    except OSError as e:
        print(red(f" Cannot open output files: {e}"))
        return 1

    stop = threading.Event()
    pause = threading.Event()
    pause.set()

    def _sig(_s, _f):
        sys.stderr.write("\r" + " " * 120 + "\r")
        sys.stderr.flush()
        print(yellow("\n Ctrl+C — stopping after current batch…"))
        stop.set()
        pause.set()

    signal.signal(signal.SIGINT, _sig)
    t0 = time.perf_counter()

    try:
        if "tcp" in cfg["protocols"] or "tls" in cfg["protocols"]:
            while not stop.is_set() and not state.tcp_exhausted:
                tcp_phase = TCPPhase(cfg, txt, csv_w, stop, pause, t0, state)
                run_tcp_phase(tcp_phase, state, total_units)

                print_state_summary(state)

                if stop.is_set() or state.tcp_exhausted:
                    break

                if "tls" in cfg["protocols"] and state.tls_pending_count:
                    ans = input(cyan(" Continue TCP, start TLS now, or stop? [c/t/n]: ")).strip().lower() or "c"
                    if ans in ("n", "no", "s", "stop"):
                        break
                    if ans in ("t", "tls"):
                        tls_items = state.tls_pending_items()
                        if tls_items:
                            tls_phase = TLSPhase(cfg, txt, csv_w, stop, pause, t0, state)
                            tls_result = run_items_phase(tls_phase.run_items, tls_items, state)
                            print(dim(f" TLS session complete: {tls_result['open']} IP×SNI hits / {tls_result['done']} pairs probed | {state.tls_total_sni_hits} total SNI hits across {state.tls_open_count} IPs"))
                            print_state_summary(state)

                        ans2 = input(cyan(" Resume TCP batches? [Y/n]: ")).strip().lower()
                        if ans2 == "n":
                            break
                    else:
                        try:
                            raw = input(cyan(" More TCP batches? (0=all remaining, N=count, Enter=1): ")).strip()
                            cfg["max_batches"] = 1 if raw == "" else (None if int(raw) == 0 else max(int(raw), 1))
                        except ValueError:
                            cfg["max_batches"] = 1
                else:
                    try:
                        raw = input(cyan(" More TCP batches? (0=all remaining, N=count, Enter=1, n=stop): ")).strip().lower()
                        if raw in ("n", "no", "s", "stop"):
                            break
                        cfg["max_batches"] = 1 if raw == "" else (None if int(raw) == 0 else max(int(raw), 1))
                    except ValueError:
                        cfg["max_batches"] = 1

        if "tls" in cfg["protocols"] and state.tls_pending_count and not stop.is_set():
            print_state_summary(state)
            ans = input(cyan(" Start TLS phase on all pending TCP-open targets? [Y/n]: ")).strip().lower()
            if ans != "n":
                cfg["max_batches"] = None
                tls_items = state.tls_pending_items()
                tls_phase = TLSPhase(cfg, txt, csv_w, stop, pause, t0, state)
                tls_result = run_items_phase(tls_phase.run_items, tls_items, state)
                print(dim(f" TLS session complete: {tls_result['open']} IP×SNI hits / {tls_result['done']} pairs probed | {state.tls_total_sni_hits} total SNI hits across {state.tls_open_count} IPs"))
                print_state_summary(state)

        if "icmp" in cfg["protocols"] and not stop.is_set():
            ans = input(cyan(" Start ICMP phase on TCP-open targets only? [y/N]: ")).strip().lower()
            if ans == "y":
                cfg["max_batches"] = None
                icmp_phase = ICMPPhase(cfg, txt, csv_w, stop, pause, t0, state)
                icmp_result = run_items_phase(icmp_phase.run_items, list(state.tcp_open.values()), state)
                print(dim(f" ICMP session complete: {icmp_result['open']} responsive / {icmp_result['done']} scanned"))

    finally:
        txt.close()
        csv_h.close()
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    elapsed = time.perf_counter() - t0
    print(bold(cyan("\n ══════════════════════════════════════════════════")))
    print(bold(f" Done [{elapsed:.1f}s]"))
    print(f" Saved → {txt_path} | {csv_path}")
    print(bold(cyan(" ══════════════════════════════════════════════════\n")))
    return 0


def main():
    print(bold(cyan("""
╔══════════════════════════════════════════╗
║  CIDR / IPv4 / Hostname Batch Scanner    ║
╚══════════════════════════════════════════╝""")))
    cfg = load_config()
    cfg = prompt_system_profile(cfg)
    cfg = prompt_protocols(cfg)
    cfg = prompt_more_settings(cfg)
    cfg = prompt_sni_config(cfg)
    selected_inputs = prompt_ranges(cfg)
    cfg["target_mode"] = prompt_target_mode(cfg.get("target_mode", "sample"))
    sys.exit(start_scan(cfg, selected_inputs))


if __name__ == "__main__":
    main()
