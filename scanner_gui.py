#!/usr/bin/env python3
"""
CIDR / IPv4 TCP Batch Scanner — GUI Edition
Streaming architecture: CIDRs are never fully expanded into RAM.
"""

import csv
import ipaddress
import random
import socket
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from itertools import islice
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    """Uniform random sample of size k without materializing the full sequence."""
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


def take_first_n(iterable, n: int):
    return list(islice(iterable, n))


# ── Target descriptor ────────────────────────────────────────────────────────
#
# Instead of expanding CIDRs into IP lists at load time, we store descriptors.
# Each descriptor knows how to STREAM its IPs on demand.
#
# descriptor = {
#   "type":       "ip" | "cidr_sample" | "cidr_all" | "cidr_capped_seq" | "cidr_capped_rnd"
#   "ip":         str   (for type=="ip")
#   "net":        IPv4Network
#   "source":     original line string
#   "cap_label":  str | None
#   "count":      int   (how many IPs this descriptor will yield)
#   "cap_k":      int   (for capped types — how many to take)
# }

def descriptor_iter(desc: dict):
    """Yield (ip_str, source, cap_label) tuples from a descriptor, lazily."""
    t = desc["type"]
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
        # reservoir sample — must buffer cap_k items max, not the full CIDR
        for ip in reservoir_sample(iter_scan_hosts(net), desc["cap_k"]):
            yield str(ip), src, cap
        return


def descriptor_count(desc: dict) -> int:
    return desc["count"]


def parse_line_to_descriptor(raw: str, target_mode: str,
                              max_cidr_hosts: int, cidr_cap_mode: str):
    """
    Parse one line from the target file into a descriptor dict.
    Returns (descriptor, is_invalid, error_msg).
    Never allocates the full IP list.
    """
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
            return {
                "type": "cidr_sample",
                "net": net,
                "source": raw,
                "cap_label": None,
                "count": 1,
            }, False, None

        # all-host mode
        if total <= max_cidr_hosts:
            return {
                "type": "cidr_all",
                "net": net,
                "source": raw,
                "cap_label": None,
                "count": total,
            }, False, None

        # oversized — cap it
        if cidr_cap_mode == "sequential":
            cap_label = f"seq {max_cidr_hosts}/{total}"
            dtype = "cidr_capped_seq"
        else:
            cap_label = f"rnd {max_cidr_hosts}/{total}"
            dtype = "cidr_capped_rnd"

        return {
            "type": dtype,
            "net": net,
            "source": raw,
            "cap_label": cap_label,
            "count": max_cidr_hosts,
            "cap_k": max_cidr_hosts,
        }, False, None

    else:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None, True, raw

        if ip.version != 4:
            return None, True, f"{raw} (IPv6 skipped)"

        return {
            "type": "ip",
            "ip": str(ip),
            "source": raw,
            "cap_label": None,
            "count": 1,
        }, False, None


def load_descriptors(file_path: str, target_mode: str,
                     max_cidr_hosts: int, cidr_cap_mode: str):
    """
    Read the target file and return a list of descriptors + stats.
    Memory cost: O(number of lines), NOT O(total IPs).
    Deduplication for single IPs and cidr_sample is done here.
    For cidr_all / capped types, per-IP dedup happens during streaming.
    """
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    descriptors = []
    invalid = []
    seen_ips = set()   # for single IPs and sampled CIDRs only

    stats = {
        "raw_entries": 0,
        "single_ips": 0,
        "cidr_entries": 0,
        "total_scan_hosts": 0,
        "cidrs_capped": 0,
        "invalid_items": 0,
    }

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

            # lightweight dedup for single IPs and samples
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


def stream_targets(descriptors: list, scan_mode: str):
    """
    Yield (ip, source, cap_label) from descriptors without ever holding
    the full expanded list in memory.

    For randomized mode we shuffle the descriptor list (cheap — O(D) where
    D = number of lines, not IPs), then stream each descriptor in shuffled order.
    Within each CIDR the order is preserved; this is a good enough approximation
    for large scans and costs zero extra RAM.
    """
    if scan_mode == "randomized":
        descriptors = descriptors[:]   # shallow copy, don't mutate original
        random.shuffle(descriptors)

    seen = set()   # global dedup across all descriptors during streaming

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
        return {"ip": ip, "status": "open",
                "latency_ms": round(elapsed_ms, 2), "error": ""}
    except socket.timeout:
        err = "timeout"
    except OSError as e:
        err = type(e).__name__
    return {"ip": ip, "status": "closed", "latency_ms": None, "error": err}


# ══════════════════════════════════════════════════════════════ UI tokens ══

DARK_BG     = "#0f0f0f"
DARK_PANEL  = "#161616"
DARK_CARD   = "#1c1c1c"
DARK_BORDER = "#2a2a2a"
ACCENT      = "#00c9a7"
ACCENT_DIM  = "#008c75"
RED         = "#ff4d6d"
YELLOW      = "#ffd166"
TEXT_BRIGHT = "#f0f0f0"
TEXT_MUTED  = "#888888"
TEXT_FAINT  = "#555555"

FONT_MONO  = ("Consolas", 10)
FONT_UI    = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)


# ═══════════════════════════════════════════════════════════════ App class ══

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CIDR / IPv4 TCP Scanner")
        self.configure(bg=DARK_BG)
        self.geometry("1060x760")
        self.minsize(860, 620)

        self._scan_thread  = None
        self._stop_event   = threading.Event()
        self._pause_event  = threading.Event()
        self._pause_event.set()
        self._open_results = []

        self._apply_theme()
        self._build_ui()

    # ── theme ────────────────────────────────────────────────────────────────

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("Teal.Horizontal.TProgressbar",
                        troughcolor=DARK_BORDER, background=ACCENT,
                        darkcolor=ACCENT, lightcolor=ACCENT,
                        bordercolor=DARK_BORDER)
        style.configure("TScrollbar",
                        troughcolor=DARK_PANEL, background=DARK_BORDER,
                        arrowcolor=TEXT_FAINT, bordercolor=DARK_PANEL,
                        relief="flat")
        style.configure("TCombobox",
                        fieldbackground=DARK_CARD, background=DARK_CARD,
                        foreground=TEXT_BRIGHT, insertcolor=ACCENT,
                        selectbackground=ACCENT_DIM,
                        selectforeground=TEXT_BRIGHT,
                        arrowcolor=TEXT_MUTED)
        style.map("TCombobox",
                  fieldbackground=[("readonly", DARK_CARD)],
                  selectbackground=[("readonly", DARK_CARD)],
                  foreground=[("readonly", TEXT_BRIGHT)])
        self.option_add("*TCombobox*Listbox.background",       DARK_CARD)
        self.option_add("*TCombobox*Listbox.foreground",       TEXT_BRIGHT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DIM)
        style.configure("Dark.TNotebook", background=DARK_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                        background=DARK_CARD, foreground=TEXT_MUTED,
                        padding=[12, 6], font=FONT_SMALL)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", DARK_PANEL)],
                  foreground=[("selected", TEXT_BRIGHT)])
        style.configure("Treeview",
                        background=DARK_CARD, fieldbackground=DARK_CARD,
                        foreground=TEXT_BRIGHT, rowheight=24,
                        borderwidth=0, font=FONT_MONO)
        style.configure("Treeview.Heading",
                        background=DARK_PANEL, foreground=TEXT_MUTED,
                        relief="flat", font=FONT_SMALL)
        style.map("Treeview", background=[("selected", ACCENT_DIM)])

    # ── layout ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        topbar = tk.Frame(self, bg=DARK_PANEL, height=48)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="⬡  TCP Scanner",
                 bg=DARK_PANEL, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=16, pady=10)
        self._status_var = tk.StringVar(value="Idle")
        tk.Label(topbar, textvariable=self._status_var,
                 bg=DARK_PANEL, fg=TEXT_MUTED,
                 font=FONT_SMALL).pack(side="right", padx=16)
        tk.Frame(self, bg=DARK_BORDER, height=1).pack(fill="x")

        pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=DARK_BG,
                              sashwidth=4, sashrelief="flat")
        pane.pack(fill="both", expand=True)

        left = tk.Frame(pane, bg=DARK_PANEL, width=320)
        left.pack_propagate(False)
        pane.add(left, minsize=260)

        right = tk.Frame(pane, bg=DARK_BG)
        pane.add(right, minsize=440)

        self._build_config(left)
        self._build_output(right)

    def _build_config(self, parent):
        canvas = tk.Canvas(parent, bg=DARK_PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=sb.set)

        inner = tk.Frame(canvas, bg=DARK_PANEL)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(wid, width=e.width))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        def section(title):
            f = tk.Frame(inner, bg=DARK_PANEL)
            f.pack(fill="x", padx=16, pady=(14, 2))
            tk.Frame(f, bg=DARK_BORDER, height=1).pack(fill="x")
            tk.Label(f, text=title.upper(), bg=DARK_PANEL, fg=TEXT_FAINT,
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(4, 0))

        def field(label):
            f = tk.Frame(inner, bg=DARK_PANEL)
            f.pack(fill="x", padx=16, pady=3)
            tk.Label(f, text=label, bg=DARK_PANEL, fg=TEXT_MUTED,
                     font=FONT_SMALL, anchor="w").pack(fill="x")
            return f

        def entry(p, var):
            return tk.Entry(p, textvariable=var, bg=DARK_CARD, fg=TEXT_BRIGHT,
                            insertbackground=ACCENT, relief="flat", font=FONT_UI,
                            bd=0, highlightthickness=1,
                            highlightbackground=DARK_BORDER, highlightcolor=ACCENT)

        def combo(p, var, values):
            return ttk.Combobox(p, textvariable=var, values=values,
                                state="readonly", font=FONT_UI)

        section("Target File")
        f = field("IP / CIDR list (.txt)")
        row = tk.Frame(f, bg=DARK_PANEL)
        row.pack(fill="x", pady=(2, 0))
        self._file_var = tk.StringVar()
        entry(row, self._file_var).pack(side="left", fill="x", expand=True)
        tk.Button(row, text="Browse", bg=DARK_CARD, fg=ACCENT,
                  activebackground=DARK_BORDER, activeforeground=ACCENT,
                  relief="flat", font=FONT_SMALL, cursor="hand2",
                  command=self._browse_file,
                  padx=8).pack(side="left", padx=(4, 0))

        section("Connection")
        self._port_var    = tk.StringVar(value="443")
        self._timeout_var = tk.StringVar(value="2.0")
        f = field("Port");              entry(f, self._port_var).pack(fill="x", pady=(2,0))
        f = field("Timeout (seconds)"); entry(f, self._timeout_var).pack(fill="x", pady=(2,0))

        section("Performance")
        self._batch_var   = tk.StringVar(value="256")
        self._workers_var = tk.StringVar(value="128")
        f = field("Batch size");     entry(f, self._batch_var).pack(fill="x", pady=(2,0))
        f = field("Worker threads"); entry(f, self._workers_var).pack(fill="x", pady=(2,0))

        section("CIDR Options")
        self._max_cidr_var  = tk.StringVar(value="65536")
        self._target_mode   = tk.StringVar(value="sample")
        self._scan_mode     = tk.StringVar(value="randomized")
        self._cidr_cap_mode = tk.StringVar(value="random")

        f = field("Max hosts per CIDR");
        entry(f, self._max_cidr_var).pack(fill="x", pady=(2,0))
        f = field("Target mode");
        combo(f, self._target_mode,   ["sample", "all"]).pack(fill="x", pady=(2,0))
        f = field("Scan order");
        combo(f, self._scan_mode,     ["randomized", "sequential"]).pack(fill="x", pady=(2,0))
        f = field("Cap strategy");
        combo(f, self._cidr_cap_mode, ["random", "sequential"]).pack(fill="x", pady=(2,0))

        section("Output Files")
        self._txt_out_var = tk.StringVar(value="open_ips.txt")
        self._csv_out_var = tk.StringVar(value="open_ips.csv")
        f = field("Text output"); entry(f, self._txt_out_var).pack(fill="x", pady=(2,0))
        f = field("CSV output");  entry(f, self._csv_out_var).pack(fill="x", pady=(2,0))

        tk.Frame(inner, bg=DARK_PANEL, height=12).pack()
        bf = tk.Frame(inner, bg=DARK_PANEL)
        bf.pack(fill="x", padx=16, pady=(0, 20))

        self._start_btn = tk.Button(
            bf, text="▶  Start Scan", bg=ACCENT, fg="#000",
            activebackground=ACCENT_DIM, activeforeground="#000",
            relief="flat", font=("Segoe UI", 10, "bold"),
            cursor="hand2", pady=9, command=self._start_scan)
        self._start_btn.pack(fill="x", pady=(0, 6))

        self._pause_btn = tk.Button(
            bf, text="⏸  Pause", bg=DARK_CARD, fg=YELLOW,
            activebackground=DARK_BORDER, activeforeground=YELLOW,
            relief="flat", font=FONT_UI, cursor="hand2",
            pady=6, state="disabled", command=self._toggle_pause)
        self._pause_btn.pack(fill="x", pady=(0, 6))

        self._stop_btn = tk.Button(
            bf, text="■  Stop", bg=DARK_CARD, fg=RED,
            activebackground=DARK_BORDER, activeforeground=RED,
            relief="flat", font=FONT_UI, cursor="hand2",
            pady=6, state="disabled", command=self._stop_scan)
        self._stop_btn.pack(fill="x")

    def _build_output(self, parent):
        kpi_row = tk.Frame(parent, bg=DARK_BG)
        kpi_row.pack(fill="x", padx=12, pady=(10, 6))
        self._kpi_total = self._kpi_card(kpi_row, "TOTAL TARGETS", "—")
        self._kpi_done  = self._kpi_card(kpi_row, "SCANNED",       "—")
        self._kpi_open  = self._kpi_card(kpi_row, "OPEN",          "—", ACCENT)
        self._kpi_rate  = self._kpi_card(kpi_row, "OPEN RATE",     "—", ACCENT)
        for k in (self._kpi_total, self._kpi_done, self._kpi_open, self._kpi_rate):
            k.pack(side="left", fill="both", expand=True, padx=4)

        pb = tk.Frame(parent, bg=DARK_BG)
        pb.pack(fill="x", padx=16, pady=(0, 6))
        self._progress = ttk.Progressbar(pb, mode="determinate",
                                         style="Teal.Horizontal.TProgressbar")
        self._progress.pack(fill="x")
        self._prog_lbl = tk.Label(pb, text="", bg=DARK_BG,
                                  fg=TEXT_MUTED, font=FONT_SMALL)
        self._prog_lbl.pack(anchor="e", pady=(2, 0))

        nb = ttk.Notebook(parent, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        log_frame = tk.Frame(nb, bg=DARK_BG)
        nb.add(log_frame, text="  Log  ")
        self._log = scrolledtext.ScrolledText(
            log_frame, bg=DARK_BG, fg=TEXT_BRIGHT, font=FONT_MONO,
            insertbackground=ACCENT, relief="flat", bd=0,
            selectbackground=ACCENT_DIM, state="disabled", wrap="none")
        self._log.pack(fill="both", expand=True, padx=4, pady=4)
        self._log.tag_config("open",    foreground=ACCENT)
        self._log.tag_config("info",    foreground=TEXT_MUTED)
        self._log.tag_config("warn",    foreground=YELLOW)
        self._log.tag_config("error",   foreground=RED)
        self._log.tag_config("heading", foreground=TEXT_BRIGHT,
                              font=("Consolas", 10, "bold"))
        self._log.tag_config("dim",     foreground=TEXT_FAINT)

        res_frame = tk.Frame(nb, bg=DARK_BG)
        nb.add(res_frame, text="  Open IPs  ")
        toolbar = tk.Frame(res_frame, bg=DARK_PANEL)
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Open hosts discovered during scan",
                 bg=DARK_PANEL, fg=TEXT_MUTED,
                 font=FONT_SMALL).pack(side="left", padx=10, pady=6)
        tk.Button(toolbar, text="Export CSV", bg=DARK_CARD, fg=ACCENT,
                  activebackground=DARK_BORDER, activeforeground=ACCENT,
                  relief="flat", font=FONT_SMALL, cursor="hand2",
                  command=self._export_csv,
                  padx=8).pack(side="right", padx=10, pady=4)

        cols = ("IP", "Port", "Latency (ms)", "Source Range")
        self._tree = ttk.Treeview(res_frame, columns=cols,
                                   show="headings", selectmode="browse")
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=260 if c == "Source Range" else 160, minwidth=80)
        vsb = ttk.Scrollbar(res_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

    # ── KPI card ─────────────────────────────────────────────────────────────

    def _kpi_card(self, parent, label, value, color=TEXT_BRIGHT):
        f = tk.Frame(parent, bg=DARK_CARD,
                     highlightthickness=1, highlightbackground=DARK_BORDER)
        tk.Label(f, text=label, bg=DARK_CARD, fg=TEXT_FAINT,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=10, pady=(8,0))
        lbl = tk.Label(f, text=value, bg=DARK_CARD, fg=color,
                       font=("Segoe UI", 18, "bold"))
        lbl.pack(anchor="w", padx=10, pady=(0, 8))
        f._val = lbl
        return f

    def _kpi_set(self, card, value):
        card._val.config(text=str(value))

    # ── actions ──────────────────────────────────────────────────────────────

    def _browse_file(self):
        p = filedialog.askopenfilename(
            title="Select IP / CIDR list",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p:
            self._file_var.set(p)

    def _set_scanning(self, scanning: bool):
        if scanning:
            self._start_btn.config(state="disabled", bg=DARK_CARD, fg=TEXT_FAINT)
            self._pause_btn.config(state="normal")
            self._stop_btn.config(state="normal")
        else:
            self._start_btn.config(state="normal", bg=ACCENT, fg="#000")
            self._pause_btn.config(state="disabled", text="⏸  Pause")
            self._stop_btn.config(state="disabled")

    def _toggle_pause(self):
        if self._pause_event.is_set():
            self._pause_event.clear()
            self._pause_btn.config(text="▶  Resume")
            self._status_var.set("Paused")
        else:
            self._pause_event.set()
            self._pause_btn.config(text="⏸  Pause")
            self._status_var.set("Scanning…")

    def _stop_scan(self):
        self._stop_event.set()
        self._pause_event.set()

    def _export_csv(self):
        if not self._open_results:
            messagebox.showinfo("Export", "No open IPs to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=self._csv_out_var.get())
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Port", "Latency (ms)", "Source Range"])
            w.writerows(self._open_results)
        messagebox.showinfo("Exported",
                            f"Saved {len(self._open_results)} rows to:\n{path}")

    def _log_write(self, msg, tag="info"):
        self._log.configure(state="normal")
        self._log.insert("end", msg + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _log_clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    def _emit(self, fn):
        self.after(0, fn)

    # ── validate + start ─────────────────────────────────────────────────────

    def _validate(self):
        errs = []
        if not self._file_var.get().strip():
            errs.append("Target file is required.")
        try:
            assert 1 <= int(self._port_var.get()) <= 65535
        except Exception:
            errs.append("Port must be 1–65535.")
        try:
            assert float(self._timeout_var.get()) > 0
        except Exception:
            errs.append("Timeout must be a positive number.")
        try:
            assert int(self._batch_var.get()) > 0
        except Exception:
            errs.append("Batch size must be a positive integer.")
        try:
            assert int(self._workers_var.get()) > 0
        except Exception:
            errs.append("Worker count must be a positive integer.")
        try:
            assert int(self._max_cidr_var.get()) > 0
        except Exception:
            errs.append("Max CIDR hosts must be a positive integer.")
        return errs

    def _start_scan(self):
        errs = self._validate()
        if errs:
            messagebox.showerror("Invalid Input", "\n".join(errs))
            return

        self._stop_event.clear()
        self._pause_event.set()
        self._open_results.clear()
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._log_clear()
        self._set_scanning(True)
        self._progress["value"] = 0
        self._prog_lbl.config(text="")
        for k in (self._kpi_total, self._kpi_done, self._kpi_open, self._kpi_rate):
            self._kpi_set(k, "—")
        self._status_var.set("Loading targets…")

        params = dict(
            file_path      = self._file_var.get().strip(),
            port           = int(self._port_var.get()),
            timeout        = float(self._timeout_var.get()),
            batch_size     = int(self._batch_var.get()),
            worker_count   = int(self._workers_var.get()),
            max_cidr_hosts = int(self._max_cidr_var.get()),
            target_mode    = self._target_mode.get(),
            scan_mode      = self._scan_mode.get(),
            cidr_cap_mode  = self._cidr_cap_mode.get(),
            txt_output     = self._txt_out_var.get().strip() or "open_ips.txt",
            csv_output     = self._csv_out_var.get().strip() or "open_ips.csv",
        )

        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(params,), daemon=True)
        self._scan_thread.start()

    # ── scan thread ──────────────────────────────────────────────────────────

    def _run_scan(self, p):

        def log(msg, tag="info"):
            self._emit(lambda m=msg, t=tag: self._log_write(m, t))

        def set_progress(done, total):
            pct  = done / total * 100 if total else 0
            txt  = f"{done}/{total}  ({pct:.1f}%)"
            self._emit(lambda v=pct: self._progress.configure(value=v))
            self._emit(lambda t=txt: self._prog_lbl.config(text=t))

        def set_kpis(total, done, open_c):
            rate = f"{open_c/done*100:.1f}%" if done else "—"
            self._emit(lambda: self._kpi_set(self._kpi_total, total))
            self._emit(lambda: self._kpi_set(self._kpi_done,  done))
            self._emit(lambda: self._kpi_set(self._kpi_open,  open_c))
            self._emit(lambda r=rate: self._kpi_set(self._kpi_rate, r))

        # ── load descriptors (cheap — O(lines), not O(IPs)) ──
        try:
            descriptors, invalid, stats = load_descriptors(
                p["file_path"], p["target_mode"],
                p["max_cidr_hosts"], p["cidr_cap_mode"])
        except Exception as e:
            log(f"Failed to load targets: {e}", "error")
            self._emit(lambda: self._set_scanning(False))
            self._emit(lambda: self._status_var.set("Error"))
            return

        if not descriptors:
            log("No valid IPv4 targets found.", "error")
            self._emit(lambda: self._set_scanning(False))
            self._emit(lambda: self._status_var.set("No targets"))
            return

        total_units = stats["total_scan_hosts"]

        log("═" * 54, "dim")
        log(f"  Descriptors loaded : {len(descriptors)}", "heading")
        log(f"  Est. total hosts   : {total_units}")
        log(f"  Invalid/skipped    : {stats['invalid_items']}",
            "warn" if stats["invalid_items"] else "info")
        log(f"  Single IPs         : {stats['single_ips']}")
        log(f"  CIDR entries       : {stats['cidr_entries']}")
        log(f"  CIDRs capped       : {stats['cidrs_capped']}")
        log(f"  Port / Timeout     : {p['port']}  /  {p['timeout']}s")
        log(f"  Batch / Workers    : {p['batch_size']}  /  {p['worker_count']}")
        log(f"  Target mode        : {p['target_mode']}")
        log(f"  Scan order         : {p['scan_mode']}")
        log(f"  ⚡ Streaming mode  : IPs generated on-the-fly, low RAM", "dim")
        log("═" * 54, "dim")

        self._emit(lambda: self._status_var.set("Scanning…"))
        self._emit(lambda n=total_units: self._kpi_set(self._kpi_total, n))

        open_total = 0
        completed  = 0

        try:
            txt_file   = open(p["txt_output"], "w", encoding="utf-8", newline="")
            csv_file   = open(p["csv_output"], "w", encoding="utf-8", newline="")
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["IP", "Ping (ms)", "Port", "Source Range"])
        except Exception as e:
            log(f"Cannot create output files: {e}", "error")
            self._emit(lambda: self._set_scanning(False))
            return

        # ── streaming batch loop ──────────────────────────────────────────
        # Pull IPs lazily from the generator, fill batches of batch_size,
        # dispatch them to the thread pool, repeat. RAM stays O(batch_size).

        try:
            target_stream = stream_targets(descriptors, p["scan_mode"])
            batch_num     = 0
            exhausted     = False

            while not exhausted and not self._stop_event.is_set():
                # fill one batch from the stream
                batch = []
                for item in target_stream:
                    batch.append(item)
                    if len(batch) >= p["batch_size"]:
                        break
                else:
                    exhausted = True   # generator ran out

                if not batch:
                    break

                batch_num  += 1
                batch_open  = 0
                log(f"\n  ── Batch {batch_num}  ({len(batch)} hosts) ──", "heading")
                t0 = time.perf_counter()

                with ThreadPoolExecutor(
                        max_workers=min(p["worker_count"], len(batch))) as ex:
                    futures = {
                        ex.submit(tcp_probe, ip, p["port"], p["timeout"]): (ip, src, cap)
                        for ip, src, cap in batch
                    }
                    for future in as_completed(futures):
                        self._pause_event.wait()
                        if self._stop_event.is_set():
                            ex.shutdown(wait=False, cancel_futures=True)
                            break

                        ip, src, cap = futures[future]
                        result = future.result()
                        completed += 1

                        if result["status"] == "open":
                            open_total += 1
                            batch_open += 1
                            lat = result["latency_ms"]

                            txt_file.write(ip + "\n")
                            txt_file.flush()
                            csv_writer.writerow([ip, lat, p["port"], src])
                            csv_file.flush()

                            row_data = (ip, p["port"], lat, src or ip)
                            self._open_results.append(row_data)
                            self._emit(lambda r=row_data:
                                       self._tree.insert("", "end", values=r))

                            cap_s = f"  [{cap}]" if cap else ""
                            src_s = f"  ← {src}" if src != ip else ""
                            log(f"  ✓ {ip}:{p['port']}  {lat} ms{src_s}{cap_s}", "open")

                        # progress uses completed/total_units as estimate
                        set_progress(completed, total_units)
                        set_kpis(total_units, completed, open_total)

                elapsed = time.perf_counter() - t0
                rate    = f"{batch_open/len(batch)*100:.1f}%" if batch else "—"
                log(f"  Batch done: {len(batch)} scanned, "
                    f"{batch_open} open ({rate})  [{elapsed:.2f}s]", "dim")

                if self._stop_event.is_set():
                    log("Scan stopped by user.", "warn")
                    break

        finally:
            txt_file.close()
            csv_file.close()

        log("\n" + "═" * 54, "dim")
        log(f"  Scan complete — {open_total} open / {completed} scanned", "heading")
        log(f"  Saved → {p['txt_output']}  |  {p['csv_output']}", "info")
        log("═" * 54, "dim")

        self._emit(lambda: self._set_scanning(False))
        self._emit(lambda: self._status_var.set(
            f"Done — {open_total} open / {completed} scanned"))
        self._emit(lambda: self._progress.configure(value=100))


# ══════════════════════════════════════════════════════════════════ entry ══

if __name__ == "__main__":
    app = App()
    app.mainloop()