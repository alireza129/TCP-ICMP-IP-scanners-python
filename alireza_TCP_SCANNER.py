#!/usr/bin/env python3
import socket
import sys
import random
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

CONNECT_TIMEOUT = 1.5


def load_ips_from_file(file_path: str):
    path = Path(file_path).expanduser()

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    content = path.read_text(encoding="utf-8")
    parts = [p.strip() for p in content.replace("\n", ",").split(",")]
    ips = [p.strip('"').strip("'").strip() for p in parts if p.strip()]
    return ips


def choose_scan_mode():
    answer = input("Scan mode - sequential or randomized? [s/r, default=r]: ").strip().lower()
    if answer in {"s", "seq", "sequential"}:
        return "sequential"
    return "randomized"


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
            print(f"Please enter a positive number, or press Enter for {default}.")
        else:
            print("Please enter a positive number.")


def tcp_ping(ip: str, port: int, timeout: float = CONNECT_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return False


def print_progress(done: int, total: int, width: int = 32):
    ratio = done / total if total else 1
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    percent = ratio * 100
    sys.stdout.write(f"\r[{bar}] {done}/{total} ({percent:5.1f}%)")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def scan_batch(ips, port: int, worker_count: int):
    successful = []
    total = len(ips)
    done = 0

    with ThreadPoolExecutor(max_workers=min(worker_count, total or 1)) as executor:
        future_to_ip = {executor.submit(tcp_ping, ip, port): ip for ip in ips}

        print_progress(0, total)

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                ok = future.result()
            except Exception:
                ok = False

            done += 1

            if ok:
                result = f"{ip}:{port}"
                successful.append(result)
                sys.stdout.write("\r" + " " * 100 + "\r")
                print(f"[OK] {result}")
                print_progress(done, total)
            else:
                print_progress(done, total)

    return successful


def main():
    file_path = input("Path to txt file with IPs: ").strip()

    try:
        ips = load_ips_from_file(file_path)
    except Exception as e:
        print(f"Failed to load IPs: {e}")
        return

    if not ips:
        print("No IPs found in file.")
        return

    scan_mode = choose_scan_mode()
    if scan_mode == "randomized":
        random.shuffle(ips)

    batch_size = ask_positive_int("Batch size: ")
    worker_count = ask_positive_int("Worker count: ")

    try:
        port = int(input("TCP port to test (example 80, 443, 22): ").strip())
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print("Invalid port.")
        return

    all_successful = []
    current_index = 0
    total_ips = len(ips)
    total_batches = (total_ips + batch_size - 1) // batch_size

    print(f"\nLoaded {total_ips} IPs from file")
    print(f"Scan mode: {scan_mode}")
    print(f"Batch size: {batch_size}")
    print(f"Worker count: {worker_count}")
    print(f"Port: {port}")
    print(f"Timeout: {CONNECT_TIMEOUT}s")
    print("-" * 50)

    batches_to_run = ask_positive_int("How many batches do you want to do right now? [default=1]: ", default=1)

    while current_index < total_ips:
        for _ in range(batches_to_run):
            if current_index >= total_ips:
                break

            batch_number = (current_index // batch_size) + 1
            batch = ips[current_index:current_index + batch_size]

            print(f"\nBatch {batch_number}/{total_batches} - scanning {len(batch)} IPs")
            successful = scan_batch(batch, port, worker_count)
            all_successful.extend(successful)

            print(f"Batch {batch_number} done. Successes in this batch: {len(successful)}")
            current_index += len(batch)

        if current_index >= total_ips:
            break

        remaining_ips = total_ips - current_index
        remaining_batches = (remaining_ips + batch_size - 1) // batch_size
        print(f"\nRemaining IPs: {remaining_ips}")
        print(f"Remaining batches: {remaining_batches}")

        batches_to_run = ask_positive_int(
            "How many more batches do you want to do now? [default=1]: ",
            default=1
        )

    print("\nFinished.")
    print(f"Total successful results: {len(all_successful)}")

    if all_successful:
        print("\nSuccessful IP:PORT entries:")
        for item in all_successful:
            print(item)


if __name__ == "__main__":
    main()