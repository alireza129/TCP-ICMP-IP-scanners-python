#!/usr/bin/env python3
import csv
import ipaddress
import random
import socket
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def ask_scan_mode():
    raw = input("Scan order - sequential or randomized? [s/r, default=r]: ").strip().lower()
    if raw in {"s", "seq", "sequential"}:
        return "sequential"
    return "randomized"


def ask_target_mode():
    raw = input("CIDR target mode - all hosts or one sample per CIDR? [a/o, default=o]: ").strip().lower()
    if raw in {"a", "all"}:
        return "all"
    return "sample"


def ask_continue_batches(batch_number, total_batches):
    while True:
        raw = input(
            f"Continue after batch {batch_number}/{total_batches}? [Y/n or number of more batches]: "
        ).strip().lower()

        if raw == "" or raw in {"y", "yes"}:
            return True, 0

        if raw in {"n", "no"}:
            return False, 0

        try:
            more_batches = int(raw)
            if more_batches > 0:
                return True, more_batches
        except ValueError:
            pass

        print("Enter Y, N, or a positive number like 50.")


def iter_scan_hosts(net: ipaddress.IPv4Network):
    """
    Return the actual IPv4 targets this scanner should probe for a CIDR.

    Behavior:
    - /32 -> the single address itself
    - /31 -> both addresses
    - everything else -> usable hosts() only
    """
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
    """
    Uniform random sample of size k from an iterable of unknown/large length.
    Returns a list of sampled items.
    """
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


def expand_cidr_targets(raw_cidr: str, target_mode: str, max_cidr_hosts: int):
    """
    Parse a CIDR that may contain host bits, normalize it, and return:
      normalized_net, selected_targets, total_scanable_hosts, sampled_down

    sample mode:
      - returns one host per CIDR

    all mode:
      - returns all scanable hosts if <= max_cidr_hosts
      - otherwise returns a random sample of max_cidr_hosts hosts
    """
    net = ipaddress.ip_network(raw_cidr, strict=False)

    if net.version != 4:
        raise ValueError("IPv6 skipped in this scanner")

    total_scanable_hosts = count_scan_hosts(net)

    if total_scanable_hosts == 0:
        raise ValueError("no usable host")

    if target_mode == "sample":
        ip = first_scan_host(net)
        if ip is None:
            raise ValueError("no usable host")
        return net, [str(ip)], total_scanable_hosts, False

    if total_scanable_hosts <= max_cidr_hosts:
        targets = [str(ip) for ip in iter_scan_hosts(net)]
        return net, targets, total_scanable_hosts, False

    sampled = reservoir_sample(iter_scan_hosts(net), max_cidr_hosts)
    sampled_targets = [str(ip) for ip in sampled]
    return net, sampled_targets, total_scanable_hosts, True


def load_targets(file_path: str, max_cidr_hosts: int, target_mode: str):
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    seen = set()
    invalid = []
    targets = []
    stats = {
        "raw_entries": 0,
        "single_ips": 0,
        "cidr_entries": 0,
        "expanded_from_cidr": 0,
        "sampled_from_cidr": 0,
        "cidrs_capped_randomly": 0,
        "duplicates_removed": 0,
        "invalid_items": 0,
    }

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            stats["raw_entries"] += 1

            try:
                if "/" in raw:
                    stats["cidr_entries"] += 1

                    try:
                        normalized_net, cidr_targets, total_scanable_hosts, sampled_down = expand_cidr_targets(
                            raw_cidr=raw,
                            target_mode=target_mode,
                            max_cidr_hosts=max_cidr_hosts,
                        )
                    except ValueError as e:
                        invalid.append(f"{raw} ({e})")
                        continue

                    if sampled_down:
                        stats["cidrs_capped_randomly"] += 1

                    if target_mode == "sample":
                        s = cidr_targets[0]
                        if s in seen:
                            stats["duplicates_removed"] += 1
                            continue
                        seen.add(s)
                        stats["sampled_from_cidr"] += 1
                        targets.append((s, raw))
                    else:
                        for s in cidr_targets:
                            if s in seen:
                                stats["duplicates_removed"] += 1
                                continue
                            seen.add(s)
                            stats["expanded_from_cidr"] += 1
                            targets.append((s, raw))

                else:
                    ip = ipaddress.ip_address(raw)
                    if ip.version != 4:
                        invalid.append(f"{raw} (IPv6 skipped in this scanner)")
                        continue

                    s = str(ip)
                    if s in seen:
                        stats["duplicates_removed"] += 1
                        continue
                    seen.add(s)
                    stats["single_ips"] += 1
                    targets.append((s, raw))

            except ValueError:
                invalid.append(raw)

    stats["invalid_items"] = len(invalid)
    return targets, invalid, stats


def print_progress(done: int, total: int, width: int = 32):
    ratio = done / total if total else 1
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    percent = ratio * 100
    sys.stdout.write(f"\r[{bar}] {done}/{total} ({percent:5.1f}%)")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def tcp_probe(ip: str, port: int, timeout: float):
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "ip": ip,
            "status": "open",
            "latency_ms": round(elapsed_ms, 2),
            "error": "",
        }
    except socket.timeout:
        err = "timeout"
    except OSError as e:
        err = type(e).__name__

    return {
        "ip": ip,
        "status": "closed",
        "latency_ms": None,
        "error": err,
    }


def init_output_files(txt_output="open_ips.txt", csv_output="open_ips.csv"):
    txt_path = Path(txt_output)
    csv_path = Path(csv_output)

    txt_file = txt_path.open("w", encoding="utf-8", newline="")
    csv_file = csv_path.open("w", encoding="utf-8", newline="")

    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP", "Ping (ms)", "Port", "Source Range"])
    csv_file.flush()

    return txt_file, csv_file, csv_writer


def append_open_result(txt_file, csv_file, csv_writer, ip, latency_ms, port, source_range):
    txt_file.write(ip + "\n")
    txt_file.flush()

    csv_writer.writerow([ip, latency_ms, port, source_range])
    csv_file.flush()


def main():
    file_path = input("Path to txt file with IPs or CIDRs: ").strip()
    port = ask_positive_int("Port to test (e.g. 80 or 443) [default=443]: ", default=443)
    timeout = ask_float("TCP connect timeout in seconds [default=2.0]: ", default=2.0)
    batch_size = ask_positive_int("Batch size [default=256]: ", default=256)
    worker_count = ask_positive_int("Worker count [default=128]: ", default=128)
    max_cidr_hosts = ask_positive_int(
        "Max targets to scan per CIDR in all-host mode [default=65536]: ",
        default=65536,
    )
    scan_mode = ask_scan_mode()
    target_mode = ask_target_mode()

    try:
        targets, invalid, stats = load_targets(
            file_path=file_path,
            max_cidr_hosts=max_cidr_hosts,
            target_mode=target_mode,
        )
    except Exception as e:
        print(f"Failed to load targets: {e}")
        return

    if not targets:
        print("No valid IPv4 targets found.")
        if invalid:
            print(f"Invalid/skipped entries: {len(invalid)}")
            print("Examples of invalid entries:")
            for item in invalid[:5]:
                print("  ", item)
        return

    if scan_mode == "randomized":
        random.shuffle(targets)

    print(f"\nValid scan targets: {len(targets)}")
    print(f"Invalid/skipped entries: {len(invalid)}")
    print(f"Single IP entries: {stats['single_ips']}")
    print(f"CIDR entries: {stats['cidr_entries']}")
    print(f"Hosts added from CIDR: {stats['expanded_from_cidr']}")
    print(f"CIDRs sampled once: {stats['sampled_from_cidr']}")
    print(f"CIDRs randomly capped in all-host mode: {stats['cidrs_capped_randomly']}")
    print(f"Duplicates removed: {stats['duplicates_removed']}")
    print(f"Target mode: {target_mode}")
    print(f"Scan order: {scan_mode}")
    print(f"Port: {port}")
    print(f"Timeout: {timeout}s")
    print(f"Batch size: {batch_size}")
    print(f"Worker count: {worker_count}")
    if target_mode == "all":
        print(f"Max targets per CIDR in all-host mode: {max_cidr_hosts}")
    print("-" * 60)

    txt_output = "open_ips.txt"
    csv_output = "open_ips.csv"

    try:
        txt_file, csv_file, csv_writer = init_output_files(txt_output, csv_output)
    except Exception as e:
        print(f"Failed to create output files: {e}")
        return

    total_units = len(targets)
    open_total = 0
    completed_units = 0
    stopped_early = False
    auto_continue_batches = 0

    try:
        for offset in range(0, len(targets), batch_size):
            batch = targets[offset:offset + batch_size]
            batch_number = (offset // batch_size) + 1
            total_batches = (len(targets) + batch_size - 1) // batch_size

            print(f"\nBatch {batch_number}/{total_batches} - targets {len(batch)}")

            batch_results = []
            batch_start = time.perf_counter()

            with ThreadPoolExecutor(max_workers=min(worker_count, len(batch) or 1)) as executor:
                future_map = {
                    executor.submit(tcp_probe, ip, port, timeout): (ip, source)
                    for ip, source in batch
                }

                done = 0
                total = len(batch)
                print_progress(0, total)

                for future in as_completed(future_map):
                    ip, source = future_map[future]
                    result = future.result()
                    done += 1
                    completed_units += 1
                    batch_results.append(result)

                    if result["status"] == "open":
                        open_total += 1
                        append_open_result(
                            txt_file=txt_file,
                            csv_file=csv_file,
                            csv_writer=csv_writer,
                            ip=ip,
                            latency_ms=result["latency_ms"],
                            port=port,
                            source_range=source,
                        )

                        sys.stdout.write("\r" + " " * 140 + "\r")
                        if source == ip:
                            print(f"[OPEN] {ip}:{port} ({result['latency_ms']} ms)")
                        else:
                            print(f"[OPEN] {ip}:{port} ({result['latency_ms']} ms)  from {source}")

                    print_progress(done, total)

            batch_elapsed = time.perf_counter() - batch_start
            open_count = sum(1 for r in batch_results if r["status"] == "open")
            total_count = len(batch_results)
            open_rate = (open_count / total_count * 100) if total_count else 0
            remaining = total_units - completed_units

            print(f"Batch summary: scanned={total_count}, open={open_count}, open_rate={open_rate:.2f}%")
            print(f"Completed targets: {completed_units}/{total_units}, remaining: {remaining}")
            print(f"Batch elapsed: {batch_elapsed:.2f}s")

            if batch_number < total_batches:
                if auto_continue_batches > 0:
                    auto_continue_batches -= 1
                    print(f"Auto-continuing. Remaining auto-continue batches: {auto_continue_batches}")
                else:
                    should_continue, more_batches = ask_continue_batches(batch_number, total_batches)
                    if not should_continue:
                        stopped_early = True
                        break
                    auto_continue_batches = more_batches

    finally:
        txt_file.close()
        csv_file.close()

    print(f"\nFinished. Total open targets: {open_total}")
    print(f"Line-separated open IPs saved to: {txt_output}")
    print(f"Spreadsheet-friendly CSV report saved to: {csv_output}")

    if stopped_early:
        print("Scan stopped early by user.")


if __name__ == "__main__":
    main()
