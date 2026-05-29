#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SNI Scanner (Python rewrite)
هدف: بازنویسی دقیق رفتار sni-scanner.sh (نسخه bash) در پایتون.

نکته: این ابزار «اسکن TCP پورت» انجام می‌دهد و (اختیاری) صحت IP را با Cloudflare /cdn-cgi/trace چک می‌کند.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Sequence, Tuple

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None  # noqa: N816


DEFAULT_INPUT_FILE = "targets.txt"
DEFAULT_PORTS = "443,2053,2083,2087,2096,8443"
DEFAULT_TIMEOUT = 5
DEFAULT_RETRIES = 3
DEFAULT_LOG_FILE = "log.txt"
CONCURRENCY = 20  # مطابق نسخه bash

USER_IP_API = "http://chabokan.net/ip/"

DONATION_BEP20 = "0x0F4fbAd006DBbA1B589e2A15d72d0a6d2b6d1282"
DONATION_TRC = "TU3gRmn5dw8YbMfxUG5pjzMY7E2BBPCSyg"

_IPV4_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")


class TeeLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._lock = threading.Lock()

        # مشابه "> $LOG_FILE" در bash: پاک‌سازی فایل
        with open(self.log_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("")

    def write_line(self, line: str) -> None:
        # line باید بدون \n یا با \n باشد؛ برای دقیق‌بودن خروجی، مثل tee عمل می‌کنیم.
        if not line.endswith("\n"):
            line = line + "\n"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8", newline="\n") as f:
                f.write(line)
            sys.stdout.write(line)
            sys.stdout.flush()

    def write_block(self, text: str) -> None:
        # برای جایی که bash یک buffer را printf می‌کند
        if not text:
            return
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8", newline="\n") as f:
                f.write(text)
            sys.stdout.write(text)
            sys.stdout.flush()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    # bash در صورت گزینه نامعتبر usage چاپ و exit 1 می‌زند.
    # argparse در حالت پیشفرض exit code 2 می‌دهد؛ اینجا رفتار را نزدیک می‌کنیم.
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", dest="input_file", default=DEFAULT_INPUT_FILE)
    parser.add_argument("-p", dest="ports", default=DEFAULT_PORTS)
    parser.add_argument("-t", dest="timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("-r", dest="retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("-l", dest="log_file", default=DEFAULT_LOG_FILE)
    parser.add_argument(
        "-ip",
        dest="ip_check",
        nargs="?",
        const=True,
        default=False,
        help="Enable IP verification (optional manual IP)",
    )
    parser.add_argument("-h", "--help", action="store_true", dest="help")

    ns, unknown = parser.parse_known_args(argv)
    if ns.help or unknown:
        usage = (
            f"Usage: {os.path.basename(sys.argv[0])} [-f file] [-p ports] [-t timeout] "
            f"[-r retries] [-l log_file] [-ip [IP]]"
        )
        sys.stdout.write(usage + "\n")
        sys.stdout.write("  -f    Input file containing domains/IPs\n")
        sys.stdout.write("  -p    Comma-separated ports\n")
        sys.stdout.write("  -t    Timeout in seconds\n")
        sys.stdout.write("  -r    Number of retries\n")
        sys.stdout.write("  -l    Output log file\n")
        sys.stdout.write("  -ip   Enable IP verification (optional manual IP)\n")
        sys.exit(1)
    return ns


def is_ipv4(s: str) -> bool:
    return bool(_IPV4_RE.match(s))


def resolve_a_records(target: str) -> List[str]:
    if is_ipv4(target):
        return [target]

    if dns is None:
        # بدون dnspython هم تلاش می‌کنیم، ولی ممکن است دقیقاً مثل dig نباشد.
        # فقط IPv4 ها را نگه می‌داریم.
        try:
            infos = socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ips = sorted({info[4][0] for info in infos})
            return ips
        except Exception:
            return []

    try:
        answers = dns.resolver.resolve(target, "A")  # type: ignore[attr-defined]
        ips = [rdata.address for rdata in answers]
        # نسخه bash با dig +short A عملاً می‌تواند ترتیب خاصی بدهد؛ ما ترتیب dnspython را حفظ می‌کنیم.
        return ips
    except Exception:
        return []


def tcp_port_open(ip: str, port: int, timeout_s: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def get_user_public_ip() -> str:
    # معادل تابع bash: 3 تلاش و sleep 1
    import urllib.request

    for _ in range(3):
        try:
            req = urllib.request.Request(USER_IP_API, headers={"User-Agent": "sni-scanner-py"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="ignore")

            # bash: grep -oE '"ip"\s*:\s*"[^"]+"' | cut -d'"' -f4
            m = re.search(r'"ip"\s*:\s*"([^"]+)"', body)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        time.sleep(1)
    return ""


def http_get_cdn_trace(domain: str, ip: str, timeout_s: int = 20) -> str:
    """
    معادل:
      curl -sk --connect-timeout 10 --max-time 20 --resolve "${domain}:443:${ip}" "https://${domain}/cdn-cgi/trace"

    - اتصال TCP به ip:443
    - TLS با SNI = domain
    - verify خاموش (مثل -k)
    """
    request = (
        f"GET /cdn-cgi/trace HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"User-Agent: sni-scanner-py\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # connect-timeout 10 / max-time 20
    connect_timeout = min(10, timeout_s)
    read_timeout = timeout_s

    with socket.create_connection((ip, 443), timeout=connect_timeout) as sock:
        sock.settimeout(read_timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            ssock.sendall(request)
            chunks: List[bytes] = []
            while True:
                try:
                    data = ssock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)

    raw = b"".join(chunks).decode("utf-8", errors="ignore")
    return raw


def check_ip(domain: str, ip: str, user_public_ip: str) -> str:
    detected_ip = ""
    try:
        raw = http_get_cdn_trace(domain=domain, ip=ip, timeout_s=20)
        for line in raw.splitlines():
            # bash: grep '^ip=' | cut -d'=' -f2
            if line.startswith("ip="):
                detected_ip = line.split("=", 1)[1].strip()
                break
    except Exception:
        detected_ip = ""

    if not detected_ip:
        return " IP✖"
    if detected_ip == user_public_ip:
        return " IP✔"
    return f" IP✖({detected_ip})"


def process_target(
    target: str,
    ports: Sequence[int],
    timeout_s: int,
    retries: int,
    enable_ip_check: bool,
    user_public_ip: str,
    logger: TeeLogger,
) -> None:
    ips = resolve_a_records(target)
    if not ips:
        logger.write_line(f"[ERROR] {target} (Could not resolve)")
        return

    domain_buffer = ""

    for ip in ips:
        if ip.startswith("10."):
            domain_buffer += f"[FILTERED] {target} -> {ip} (Blocked/Internal IP)\n"
            continue

        result_str = f"{target} -> {ip} ->"
        open_count = 0

        for port in ports:
            port_status_open = False
            for _ in range(retries):
                if tcp_port_open(ip, port, timeout_s):
                    port_status_open = True
                    break
            if port_status_open:
                result_str += f" {port}✔"
                open_count += 1
            else:
                result_str += f" {port}✖"

        if open_count > 0:
            if enable_ip_check and user_public_ip:
                ip_result = check_ip(target, ip, user_public_ip)
                domain_buffer += f"[OK] {result_str}{ip_result}\n"
            else:
                domain_buffer += f"[OK] {result_str}\n"
        else:
            domain_buffer += f"[FAIL] {result_str}\n"

    logger.write_block(domain_buffer)


def iter_targets_from_file(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            if not raw:
                continue
            # bash: tr -d '\r' | xargs
            line = raw.replace("\r", "").strip()
            if not line or line.startswith("#"):
                continue
            yield line


def format_date_like_bash() -> str:
    """
    bash `date` معمولاً چیزی شبیه این می‌دهد:
      Thu May 29 21:32:06 UTC 2026
    روی بعضی سیستم‌ها %Z ممکن است خالی باشد؛ تلاش می‌کنیم یک timezone قابل نمایش اضافه کنیم.
    """
    # %Z در ویندوز/بعضی محیط‌ها ممکن است خالی باشد
    tz = time.strftime("%Z").strip()
    if not tz:
        try:
            tz = time.tzname[0] or ""
        except Exception:
            tz = ""
    base = time.strftime("%a %b %d %H:%M:%S").strip()
    year = time.strftime("%Y").strip()
    if tz:
        return f"{base} {tz} {year}"
    return f"{base} {year}"


def print_header(logger: TeeLogger, input_file: str, ports_str: str, timeout_s: int, retries: int) -> None:
    logger.write_line("Starting SNI Scanner...")
    logger.write_line(f"Scan started at {format_date_like_bash()}")
    logger.write_line(f"Targets: {input_file} | Ports: {ports_str} | Timeout: {timeout_s}s | Retries: {retries}")
    logger.write_line("---------------------------------------------------")


def print_final_summary(logger: TeeLogger, log_path: str) -> None:
    # معادل بخش FINAL SUMMARY در bash (با grep)
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    ok_lines = [ln for ln in lines if ln.startswith("[OK]")]
    fail_lines = [ln for ln in lines if ln.startswith("[FAIL]")]
    filtered_lines = [ln for ln in lines if ln.startswith("[FILTERED]")]
    error_lines = [ln for ln in lines if ln.startswith("[ERROR]")]

    logger.write_line("---------------------------------------------------")
    logger.write_line("===================================================")
    logger.write_line("                   FINAL SUMMARY                   ")
    logger.write_line("===================================================")
    logger.write_line("")

    if ok_lines:
        logger.write_line(f"=== OK (at least one open port) [{len(ok_lines)}] ===")
        logger.write_line("")
        logger.write_block("\n".join(ok_lines) + "\n\n")

    if fail_lines:
        logger.write_line(f"=== FAIL (all ports closed) [{len(fail_lines)}] ===")
        logger.write_line("")
        logger.write_block("\n".join(fail_lines) + "\n\n")

    if error_lines:
        logger.write_line(f"=== RESOLVE FAILED [{len(error_lines)}] ===")
        logger.write_line("")
        logger.write_block("\n".join(error_lines) + "\n\n")

    if filtered_lines:
        logger.write_line(f"=== FILTERED (Blocked/IP 10.x) [{len(filtered_lines)}] ===")
        logger.write_line("")
        logger.write_block("\n".join(filtered_lines) + "\n\n")

    logger.write_line("---------------------------------------------------")
    logger.write_line(f"Scan fully completed at {format_date_like_bash()}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)

    if not os.path.isfile(args.input_file):
        sys.stdout.write(f"Error: Input file '{args.input_file}' not found!\n")
        return 1

    ports = []
    for p in str(args.ports).split(","):
        p = p.strip()
        if not p:
            continue
        try:
            ports.append(int(p))
        except ValueError:
            # مشابه usage
            sys.stdout.write("Invalid ports list.\n")
            return 1

    logger = TeeLogger(args.log_file)

    # Shown immediately on CLI start (as requested)
    logger.write_line("Support / Donations:")
    logger.write_line(f"BEP20: {DONATION_BEP20}")
    logger.write_line(f"TRC: {DONATION_TRC}")
    logger.write_line("---------------------------------------------------")

    enable_ip_check = bool(args.ip_check)
    manual_ip = ""
    if enable_ip_check and isinstance(args.ip_check, str):
        manual_ip = args.ip_check

    user_public_ip = ""
    if enable_ip_check:
        if manual_ip:
            user_public_ip = manual_ip
            logger.write_line(f"[INFO] Using Manual IP: {user_public_ip}")
        else:
            user_public_ip = get_user_public_ip()
            if user_public_ip:
                logger.write_line(f"[INFO] Auto Detected IP: {user_public_ip}")

        if not user_public_ip:
            logger.write_line("[WARNING] Could not detect your public IP")

    print_header(logger, args.input_file, args.ports, int(args.timeout), int(args.retries))

    targets = list(iter_targets_from_file(args.input_file))

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = [
            ex.submit(
                process_target,
                t,
                ports,
                int(args.timeout),
                int(args.retries),
                enable_ip_check,
                user_public_ip,
                logger,
            )
            for t in targets
        ]
        # صبر می‌کنیم تا مثل bash همه کارها تمام شوند
        for fut in as_completed(futures):
            _ = fut.result()

    print_final_summary(logger, args.log_file)

    sys.stdout.write("\n")
    sys.stdout.write(f"Full scan activity and summary saved to: {args.log_file}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
