"""
Network Security Tool - Multithreaded Port Scanner
Course: 605346 - Information & Network Security Programming
Student: abdullahaboob
"""

import socket
import argparse
import os
import threading
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ============================================================
# Global lock for thread-safe file writing
# ============================================================
file_lock = threading.Lock()
print_lock = threading.Lock()


def get_log_filename():
    """Generate a timestamped log filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_results_{timestamp}.txt"


def log_result(log_file: str, message: str):
    """Write a result to the log file in a thread-safe manner."""
    with file_lock:
        with open(log_file, "a") as f:
            f.write(message + "\n")


def print_result(message: str):
    """Print to console in a thread-safe manner."""
    with print_lock:
        print(message)


def scan_port(target: str, port: int, log_file: str, timeout: float = 1.0):
    """
    Scan a single TCP port on the target host.
    Uses socket connect to determine if port is open or closed.
    Thread-safe logging via file_lock.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()

        thread_id = threading.current_thread().name

        if result == 0:
            msg = f"[{datetime.now().strftime('%H:%M:%S')}] [{thread_id}] {target}:{port} --> OPEN"
            print_result(f"\033[92m{msg}\033[0m")  # green
        else:
            msg = f"[{datetime.now().strftime('%H:%M:%S')}] [{thread_id}] {target}:{port} --> CLOSED"
            print_result(f"\033[91m{msg}\033[0m")  # red

        log_result(log_file, msg)

    except socket.gaierror:
        err = f"[ERROR] Could not resolve hostname: {target}"
        print_result(err)
        log_result(log_file, err)
    except socket.error as e:
        err = f"[ERROR] Socket error on {target}:{port} - {e}"
        print_result(err)
        log_result(log_file, err)


def parse_ports(port_arg: str):
    """
    Parse port argument into a list of integers.
    Supports: single port (80), range (1-1024), list (22,80,443)
    """
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def parse_targets(target_arg: str):
    """Parse comma-separated list of target hosts/IPs."""
    return [t.strip() for t in target_arg.split(",")]


def run_scan(targets, ports, log_file, threads, timeout):
    """
    Run the port scan using ThreadPoolExecutor.
    Submits all (target, port) combinations as concurrent tasks.
    """
    print_result(f"\n[*] Starting scan on {len(targets)} target(s), {len(ports)} port(s)")
    print_result(f"[*] Using {threads} threads | Log file: {log_file}\n")

    # Write scan header to log
    log_result(log_file, "=" * 60)
    log_result(log_file, f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_result(log_file, f"Targets: {', '.join(targets)}")
    log_result(log_file, f"Ports: {len(ports)} ports scanned")
    log_result(log_file, f"Threads: {threads}")
    log_result(log_file, "=" * 60)

    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="Scanner") as executor:
        for target in targets:
            for port in ports:
                executor.submit(scan_port, target, port, log_file, timeout)

    # Write scan footer
    log_result(log_file, "=" * 60)
    log_result(log_file, f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_result(log_file, "=" * 60)

    print_result(f"\n[*] Scan complete! Results saved to: {log_file}")

    # Backup log using shutil
    backup_dir = "logs_backup"
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(log_file))
    shutil.copy2(log_file, backup_path)
    print_result(f"[*] Backup saved to: {backup_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded Network Port Scanner - Network Security Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-t", "--targets",
        required=True,
        help="Target host(s) or IP(s). Comma-separated for multiple.\nExample: 192.168.1.1 or scanme.nmap.org,192.168.1.1"
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port(s) to scan.\nExamples: 80  |  22,80,443  |  1-1024\nDefault: 1-1024"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )

    args = parser.parse_args()

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)
    log_file = get_log_filename()

    run_scan(targets, ports, log_file, args.threads, args.timeout)


if __name__ == "__main__":
    main()