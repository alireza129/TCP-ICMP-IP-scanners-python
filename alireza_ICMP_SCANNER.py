#!/usr/bin/env python3
import os
import sys
import time
import struct
import random
import select
import socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIMEOUT = 1.5


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


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xffff) + (total >> 16)

    return ~total & 0xffff


def create_icmp_packet(identifier: int, sequence: int) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    payload = struct.pack("!d", time.time()) + b"standard-library-icmp"
    chksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, identifier, sequence)
    return header + payload


def icmp_ping(ip: str, timeout: float = ICMP_TIMEOUT) -> bool:
    try:
        proto = socket.getprotobyname("icmp")
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, proto) as sock:
            sock.settimeout(timeout)

            identifier = os.getpid() & 0xFFFF
            sequence = random.randint(0, 65535)
            packet = create_icmp_packet(identifier, sequence)

            start = time.time()
            sock.sendto(packet, (ip, 0))

            while True:
                remaining = timeout - (time.time() - start)
                if remaining <= 0:
                    return False

                ready = select.select([sock], [], [], remaining)
                if not ready[0]:
                    return False

                recv_packet, addr = sock.recvfrom(1024)
                if addr[0] != ip:
                    continue

                ip_header_len = (recv_packet[0] & 0x0F) * 4
                icmp_header = recv_packet[ip_header_len:ip_header_len + 8]
                if len(icmp_header) < 8:
                    continue

                icmp_type, code, recv_checksum, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_header)

                if icmp_type == ICMP_ECHO_REPLY and recv_id == identifier and recv_seq == sequence:
                    return True

    except PermissionError:
        raise
    except Exception:
        return False

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


def scan_batch(ips, worker_count: int):
    successful = []
    total = len(ips)
    done = 0

    with ThreadPoolExecutor(max_workers=min(worker_count, total or 1)) as executor:
        future_to_ip = {executor.submit(icmp_ping, ip): ip for ip in ips}

        print_progress(0, total)

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                ok = future.result()
            except PermissionError:
                print("\nPermission denied for raw ICMP sockets. Run as root/Administrator.")
                sys.exit(1)
            except Exception:
                ok = False

            done += 1

            if ok:
                successful.append(ip)
                sys.stdout.write("\r" + " " * 100 + "\r")
                print(f"[OK] {ip}")
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

    total_ips = len(ips)
    current_index = 0
    total_batches = (total_ips + batch_size - 1) // batch_size
    all_successful = []

    print(f"\nLoaded {total_ips} IPs from file")
    print(f"Scan mode: {scan_mode}")
    print(f"Batch size: {batch_size}")
    print(f"Worker count: {worker_count}")
    print(f"ICMP timeout: {ICMP_TIMEOUT}s")
    print("-" * 50)

    batches_to_run = ask_positive_int("How many batches do you want to do right now? [default=1]: ", default=1)

    while current_index < total_ips:
        for _ in range(batches_to_run):
            if current_index >= total_ips:
                break

            batch_number = (current_index // batch_size) + 1
            batch = ips[current_index:current_index + batch_size]

            print(f"\nBatch {batch_number}/{total_batches} - scanning {len(batch)} IPs")
            successful = scan_batch(batch, worker_count)
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
    print(f"Total successful ICMP replies: {len(all_successful)}")

    if all_successful:
        print("\nSuccessful IPs:")
        for ip in all_successful:
            print(ip)


if __name__ == "__main__":
    main()