#!/usr/bin/env python3
import csv
import ipaddress
import json
import os
import random
import select
import socket
import struct
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
STATE_SUFFIX = ".state.json"


def ask_positive_int(prompt: str, default=None):
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
        if default is not None:
            print(f"Please enter a positive integer, or press Enter for {default}.")
        else:
            print("Please enter a positive integer.")


def ask_float(prompt: str, default=None):
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
        if default is not None:
            print(f"Please enter a positive number, or press Enter for {default}.")
        else:
            print("Please enter a positive number.")


def ask_yes_no(prompt: str, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        raw = input(f"{prompt} {suffix}: ").strip().lower()
        if raw == "":
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please answer y/yes or n/no.")


def ask_scan_mode():
    raw = input("Scan mode - sequential or randomized? [s/r, default=r]: ").strip().lower()
    if raw in {"s", "seq", "sequential"}:
        return "sequential"
    return "randomized"


def load_and_prepare_ips(file_path: str):
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    content = path.read_text(encoding="utf-8")
    parts = [p.strip() for p in content.replace("\n", ",").split(",")]

    raw_ips = [p.strip('"').strip("'").strip() for p in parts if p.strip()]
    valid_ips = []
    invalid_ips = []
    seen = set()

    for raw in raw_ips:
        try:
            ip = str(ipaddress.ip_address(raw))
            if ip not in seen:
                seen.add(ip)
                valid_ips.append(ip)
        except ValueError:
            invalid_ips.append(raw)

    duplicates_removed = len(raw_ips) - len(invalid_ips) - len(valid_ips)
    return valid_ips, invalid_ips, duplicates_removed


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def create_icmp_packet(identifier: int, sequence: int):
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    payload = struct.pack("!d", time.perf_counter()) + b"icmp-scan"
    chksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, identifier, sequence)
    return header + payload


def icmp_probe(ip: str, timeout: float, retries: int):
    last_error = None
    for attempt in range(retries + 1):
        try:
            proto = socket.getprotobyname("icmp")
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, proto) as sock:
                sock.settimeout(timeout)
                identifier = os.getpid() & 0xFFFF
                sequence = random.randint(0, 65535)
                packet = create_icmp_packet(identifier, sequence)
                start = time.perf_counter()
                sock.sendto(packet, (ip, 0))

                while True:
                    remaining = timeout - (time.perf_counter() - start)
                    if remaining <= 0:
                        last_error = "timeout"
                        break

                    ready = select.select([sock], [], [], remaining)
                    if not ready[0]:
                        last_error = "timeout"
                        break

                    recv_packet, addr = sock.recvfrom(1024)
                    if addr[0] != ip:
                        continue

                    ip_header_len = (recv_packet[0] & 0x0F) * 4
                    icmp_header = recv_packet[ip_header_len:ip_header_len + 8]
                    if len(icmp_header) < 8:
                        continue

                    icmp_type, code, recv_checksum, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_header)
                    if icmp_type == ICMP_ECHO_REPLY and recv_id == identifier and recv_seq == sequence:
                        latency_ms = (time.perf_counter() - start) * 1000
                        return {
                            "ip": ip,
                            "status": "success",
                            "latency_ms": round(latency_ms, 2),
                            "error": "",
                            "attempts": attempt + 1,
                        }

        except PermissionError:
            raise
        except OSError as e:
            last_error = type(e).__name__

    return {
        "ip": ip,
        "status": "failed",
        "latency_ms": None,
        "error": last_error or "unknown_error",
        "attempts": retries + 1,
    }


class ResultWriter:
    def __init__(self, base_filename: str):
        self.base = Path(base_filename).expanduser()
        self.txt_path = self.base.with_suffix(".txt")
        self.csv_path = self.base.with_suffix(".csv")
        self.jsonl_path = self.base.with_suffix(".jsonl")

        self.csv_file = self.csv_path.open("a", newline="", encoding="utf-8")
        self.csv_writer = csv.DictWriter(
            self.csv_file,
            fieldnames=["timestamp", "ip", "status", "latency_ms", "error", "attempts"]
        )
        if self.csv_path.stat().st_size == 0:
            self.csv_writer.writeheader()

        self.jsonl_file = self.jsonl_path.open("a", encoding="utf-8")

    def write_success(self, row):
        with self.txt_path.open("a", encoding="utf-8") as f:
            f.write(f"{row['ip']}\n")

        self.csv_writer.writerow(row)
        self.csv_file.flush()

        self.jsonl_file.write(json.dumps(row, ensure_ascii=False) + "\n")
        self.jsonl_file.flush()

    def close(self):
        self.csv_file.close()
        self.jsonl_file.close()


def load_state(state_path: Path):
    if not state_path.is_file():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state_path: Path, state: dict):
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_already_scanned(csv_path: Path):
    scanned = set()
    if not csv_path.is_file():
        return scanned

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip")
            if ip:
                scanned.add(ip)
    return scanned


def print_progress(done: int, total: int, width: int = 32):
    ratio = done / total if total else 1
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    percent = ratio * 100
    sys.stdout.write(f"\r[{bar}] {done}/{total} ({percent:5.1f}%)")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def print_batch_summary(batch_results, batch_elapsed, completed_units, total_units):
    success_rows = [r for r in batch_results if r["status"] == "success"]
    success_count = len(success_rows)
    total_count = len(batch_results)
    success_rate = (success_count / total_count * 100) if total_count else 0
    avg_latency = (
        sum(r["latency_ms"] for r in success_rows if r["latency_ms"] is not None) / len(success_rows)
        if success_rows else 0
    )
    remaining_units = total_units - completed_units
    print(f"Batch summary: scanned={total_count}, success={success_count}, success_rate={success_rate:.2f}%")
    print(f"Average success latency: {avg_latency:.2f} ms")
    print(f"Completed units: {completed_units}/{total_units}, remaining: {remaining_units}")
    print(f"Batch elapsed: {batch_elapsed:.2f}s")


def main():
    file_path = input("Path to txt file with IPs: ").strip()
    output_base = input("Output filename base (example: icmp_results): ").strip() or "icmp_results"
    timeout = ask_float("Timeout in seconds [default=1.5]: ", default=1.5)
    retries = ask_positive_int("Retry count [default=0]: ", default=0)
    batch_size = ask_positive_int("Batch size: ")
    worker_count = ask_positive_int("Worker count: ")
    scan_mode = ask_scan_mode()
    skip_scanned = ask_yes_no("Skip already-scanned IPs from previous run?", default=True)
    resume = ask_yes_no("Resume from saved progress if state exists?", default=True)

    try:
        ips, invalid_ips, duplicates_removed = load_and_prepare_ips(file_path)
    except Exception as e:
        print(f"Failed to load IPs: {e}")
        return

    if not ips:
        print("No valid IPs found.")
        return

    if scan_mode == "randomized":
        random.shuffle(ips)

    writer = ResultWriter(output_base)
    state_path = Path(output_base).expanduser().with_suffix(STATE_SUFFIX)
    state = load_state(state_path) if resume else {}
    offset = int(state.get("offset", 0)) if state else 0
    if offset < 0 or offset > len(ips):
        offset = 0

    already_scanned = load_already_scanned(writer.csv_path) if skip_scanned else set()

    print(f"\nValid IPs: {len(ips)}")
    print(f"Invalid IPs skipped: {len(invalid_ips)}")
    print(f"Duplicates removed: {duplicates_removed}")
    print(f"Scan mode: {scan_mode}")
    print(f"Timeout: {timeout}s")
    print(f"Retries: {retries}")
    print(f"Batch size: {batch_size}")
    print(f"Worker count: {worker_count}")
    print(f"Resume offset: {offset}")
    print(f"Skip already scanned: {skip_scanned}")
    print("-" * 60)

    total_units = len(ips)
    completed_units = len(already_scanned) if skip_scanned else 0

    batches_to_run = ask_positive_int("How many batches do you want to do right now? [default=1]: ", default=1)

    while offset < len(ips):
        for _ in range(batches_to_run):
            if offset >= len(ips):
                break

            batch_ips = ips[offset:offset + batch_size]
            tasks = [ip for ip in batch_ips if ip not in already_scanned]
            batch_number = (offset // batch_size) + 1
            total_batches = (len(ips) + batch_size - 1) // batch_size

            print(f"\nBatch {batch_number}/{total_batches} - IPs {len(batch_ips)}, tasks {len(tasks)}")

            if not tasks:
                print("Nothing to do in this batch (all IPs already scanned/skipped).")
                offset += len(batch_ips)
                state = {"offset": offset}
                save_state(state_path, state)
                continue

            batch_results = []
            batch_start = time.perf_counter()

            with ThreadPoolExecutor(max_workers=min(worker_count, len(tasks) or 1)) as executor:
                future_map = {executor.submit(icmp_probe, ip, timeout, retries): ip for ip in tasks}

                done = 0
                total = len(tasks)
                print_progress(0, total)

                for future in as_completed(future_map):
                    ip = future_map[future]
                    try:
                        result = future.result()
                    except PermissionError:
                        print("\nPermission denied for raw ICMP sockets. Run as root/Administrator.")
                        writer.close()
                        return

                    done += 1
                    completed_units += 1
                    batch_results.append(result)
                    already_scanned.add(ip)

                    if result["status"] == "success":
                        row = {
                            "timestamp": int(time.time()),
                            **result,
                        }
                        writer.write_success(row)
                        sys.stdout.write("\r" + " " * 120 + "\r")
                        print(f"[OK] {result['ip']} ({result['latency_ms']} ms)")
                    print_progress(done, total)

            batch_elapsed = time.perf_counter() - batch_start
            print_batch_summary(batch_results, batch_elapsed, completed_units, total_units)

            offset += len(batch_ips)
            state = {"offset": offset}
            save_state(state_path, state)

        if offset >= len(ips):
            break

        remaining_ips = len(ips) - offset
        remaining_batches = (remaining_ips + batch_size - 1) // batch_size
        print(f"\nRemaining IPs: {remaining_ips}")
        print(f"Remaining batches: {remaining_batches}")
        batches_to_run = ask_positive_int("How many more batches do you want to do now? [default=1]: ", default=1)

    writer.close()
    print("\nFinished.")


if __name__ == "__main__":
    main()