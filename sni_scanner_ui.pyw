#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-

"""
SNI Scanner UI (Tkinter)

Features:
- Start scan / Stop / Pause / Resume
- Import IP/domain list from file
- Color-coded, timestamped console log inside the UI
- Writes the same scan output format to a log file (like the CLI version)
- First-launch dependency installation (dnspython) if missing

This UI version aims to match the Bash scanner behavior, while adding interactive controls.
"""

from __future__ import annotations

import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ---------- Constants (match CLI defaults) ----------

DEFAULT_INPUT_FILE = "targets.txt"
DEFAULT_PORTS = "443,2053,2083,2087,2096,8443"
DEFAULT_TIMEOUT = 5
DEFAULT_RETRIES = 3
DEFAULT_LOG_FILE = "log.txt"
CONCURRENCY = 20

USER_IP_API = "http://chabokan.net/ip/"

_IPV4_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")

DONATION_BEP20 = "0x0F4fbAd006DBbA1B589e2A15d72d0a6d2b6d1282"
DONATION_TRC = "TU3gRmn5dw8YbMfxUG5pjzMY7E2BBPCSyg"

def _script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _requirements_path() -> str:
    return os.path.join(_script_dir(), "requirements.txt")


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _safe_int(s: str, default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def _parse_ports(ports_str: str) -> List[int]:
    ports: List[int] = []
    for p in str(ports_str).split(","):
        p = p.strip()
        if not p:
            continue
        ports.append(int(p))
    return ports


# ---------- Dependency bootstrap ----------

def ensure_dependencies_with_ui(parent: tk.Tk, log_cb) -> bool:
    """
    If dnspython is missing, try installing requirements.txt using pip.
    Returns True if ok to continue, False if user should quit.
    """
    try:
        import dns.resolver  # noqa: F401
        return True
    except Exception:
        pass

    req = _requirements_path()
    if not os.path.isfile(req):
        messagebox.showerror(
            "Missing requirements.txt",
            "requirements.txt was not found. Cannot auto-install dependencies.",
            parent=parent,
        )
        return False

    if not messagebox.askyesno(
        "Install dependencies",
        "Required Python libraries are missing (dnspython).\n\nInstall now using pip?",
        parent=parent,
    ):
        return False

    cmd = [sys.executable, "-m", "pip", "install", "-r", req]
    log_cb(f"[{_ts()}] [INFO] Installing dependencies: {' '.join(cmd)}\n", "INFO")

    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=_script_dir(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        messagebox.showerror("pip failed", f"Could not start pip:\n{e}", parent=parent)
        return False

    assert p.stdout is not None
    for line in p.stdout:
        log_cb(f"[{_ts()}] {line}", "INFO")
        parent.update_idletasks()

    rc = p.wait()
    if rc != 0:
        messagebox.showerror("Install failed", f"pip exited with code {rc}", parent=parent)
        return False

    log_cb(f"[{_ts()}] [INFO] Dependencies installed successfully. Restarting...\n", "INFO")
    parent.update_idletasks()

    # Restart the app to ensure imports are available
    try:
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])
    except Exception:
        return True


# ---------- Scanner core (pause/resume/stop aware) ----------

def is_ipv4(s: str) -> bool:
    return bool(_IPV4_RE.match(s))


def resolve_a_records(target: str) -> List[str]:
    if is_ipv4(target):
        return [target]

    # Prefer dnspython (matches dig +short A behavior closely)
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(target, "A")
        return [rdata.address for rdata in answers]
    except Exception:
        # Fallback to socket.getaddrinfo (IPv4 only)
        try:
            infos = socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            return sorted({info[4][0] for info in infos})
        except Exception:
            return []


def tcp_port_open(ip: str, port: int, timeout_s: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def http_get_cdn_trace(domain: str, ip: str, timeout_s: int = 20) -> str:
    request = (
        f"GET /cdn-cgi/trace HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"User-Agent: sni-scanner-ui\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

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

    return b"".join(chunks).decode("utf-8", errors="ignore")


def get_user_public_ip(retries: int = 3) -> str:
    import urllib.request

    for _ in range(retries):
        try:
            req = urllib.request.Request(USER_IP_API, headers={"User-Agent": "sni-scanner-ui"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r'"ip"\s*:\s*"([^"]+)"', body)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        time.sleep(1)
    return ""


def check_ip(domain: str, ip: str, user_public_ip: str) -> str:
    detected_ip = ""
    try:
        raw = http_get_cdn_trace(domain=domain, ip=ip, timeout_s=20)
        for line in raw.splitlines():
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


def iter_targets_from_file(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.replace("\r", "").strip()
            if not line or line.startswith("#"):
                continue
            yield line


@dataclass
class ScanConfig:
    input_file: str
    ports_str: str
    timeout_s: int
    retries: int
    log_file: str
    enable_ip_check: bool
    manual_ip: str


class ScanController:
    def __init__(self, ui_log_cb, on_state_cb):
        self.ui_log_cb = ui_log_cb
        self.on_state_cb = on_state_cb

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._pause.clear()

        self._lock = threading.Lock()
        self._running = False

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def is_paused(self) -> bool:
        return self._pause.is_set()

    def start(self, cfg: ScanConfig) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self._pause.clear()
        self._thread = threading.Thread(target=self._run_scan, args=(cfg,), daemon=True)
        with self._lock:
            self._running = True
        self.on_state_cb()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._pause.clear()
        self.ui_log_cb(f"[{_ts()}] [INFO] Stop requested...\n", "INFO")
        self.on_state_cb()

    def pause(self) -> None:
        if not self.is_running():
            return
        self._pause.set()
        self.ui_log_cb(f"[{_ts()}] [INFO] Paused.\n", "INFO")
        self.on_state_cb()

    def resume(self) -> None:
        if not self.is_running():
            return
        self._pause.clear()
        self.ui_log_cb(f"[{_ts()}] [INFO] Resumed.\n", "INFO")
        self.on_state_cb()

    def _wait_if_paused_or_stopped(self) -> bool:
        # returns False if should abort
        while self._pause.is_set():
            if self._stop.is_set():
                return False
            time.sleep(0.1)
        return not self._stop.is_set()

    def _write_scan_log_line(self, log_path: str, line: str) -> None:
        # append scan output to log file, like tee
        if not line.endswith("\n"):
            line += "\n"
        # ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
        with open(log_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)

    def _run_scan(self, cfg: ScanConfig) -> None:
        # Clear/initialize log file (match CLI)
        try:
            with open(cfg.log_file, "w", encoding="utf-8", newline="\n") as f:
                f.write("")
        except Exception as e:
            self.ui_log_cb(f"[{_ts()}] [ERROR] Could not open log file: {e}\n", "ERROR")
            with self._lock:
                self._running = False
            self.on_state_cb()
            return

        # Header (same structure)
        header_lines = [
            "Starting SNI Scanner...",
            f"Scan started at {time.strftime('%a %b %d %H:%M:%S %Z %Y').strip()}",
            f"Targets: {cfg.input_file} | Ports: {cfg.ports_str} | Timeout: {cfg.timeout_s}s | Retries: {cfg.retries}",
            "---------------------------------------------------",
        ]
        for hl in header_lines:
            self.ui_log_cb(f"[{_ts()}] {hl}\n", "INFO")
            self._write_scan_log_line(cfg.log_file, hl)

        # IP verification setup
        user_public_ip = ""
        if cfg.enable_ip_check:
            if cfg.manual_ip:
                user_public_ip = cfg.manual_ip
                line = f"[INFO] Using Manual IP: {user_public_ip}"
                self.ui_log_cb(f"[{_ts()}] {line}\n", "INFO")
                self._write_scan_log_line(cfg.log_file, line)
            else:
                user_public_ip = get_user_public_ip()
                if user_public_ip:
                    line = f"[INFO] Auto Detected IP: {user_public_ip}"
                    self.ui_log_cb(f"[{_ts()}] {line}\n", "INFO")
                    self._write_scan_log_line(cfg.log_file, line)

            if not user_public_ip:
                line = "[WARNING] Could not detect your public IP"
                self.ui_log_cb(f"[{_ts()}] {line}\n", "WARNING")
                self._write_scan_log_line(cfg.log_file, line)

        # Read targets
        try:
            targets = list(iter_targets_from_file(cfg.input_file))
        except Exception as e:
            line = f"[ERROR] Failed to read targets: {e}"
            self.ui_log_cb(f"[{_ts()}] {line}\n", "ERROR")
            self._write_scan_log_line(cfg.log_file, line)
            with self._lock:
                self._running = False
            self.on_state_cb()
            return

        try:
            ports = _parse_ports(cfg.ports_str)
        except Exception:
            line = "[ERROR] Invalid ports list."
            self.ui_log_cb(f"[{_ts()}] {line}\n", "ERROR")
            self._write_scan_log_line(cfg.log_file, line)
            with self._lock:
                self._running = False
            self.on_state_cb()
            return

        # Scan workers (target-level parallelism like CLI)
        def process_target(target: str) -> List[str]:
            out_lines: List[str] = []
            if not self._wait_if_paused_or_stopped():
                return out_lines

            ips = resolve_a_records(target)
            if not ips:
                out_lines.append(f"[ERROR] {target} (Could not resolve)")
                return out_lines

            for ip in ips:
                if not self._wait_if_paused_or_stopped():
                    return out_lines

                if ip.startswith("10."):
                    out_lines.append(f"[FILTERED] {target} -> {ip} (Blocked/Internal IP)")
                    continue

                result_str = f"{target} -> {ip} ->"
                open_count = 0

                for port in ports:
                    if not self._wait_if_paused_or_stopped():
                        return out_lines

                    is_open = False
                    for _ in range(cfg.retries):
                        if not self._wait_if_paused_or_stopped():
                            return out_lines
                        if tcp_port_open(ip, port, cfg.timeout_s):
                            is_open = True
                            break
                    if is_open:
                        result_str += f" {port}✔"
                        open_count += 1
                    else:
                        result_str += f" {port}✖"

                if open_count > 0:
                    if cfg.enable_ip_check and user_public_ip and not is_ipv4(target):
                        # In bash, check_ip is called even for IP targets (domain=ip) which will fail;
                        # here we keep it closer by only running check for domain-like targets.
                        # If you want exact bash behavior, remove `and not is_ipv4(target)`.
                        ip_result = check_ip(target, ip, user_public_ip)
                        out_lines.append(f"[OK] {result_str}{ip_result}")
                    elif cfg.enable_ip_check and user_public_ip and is_ipv4(target):
                        # Match bash more closely: it will try and likely return IP✖ for pure IP target.
                        ip_result = check_ip(target, ip, user_public_ip)
                        out_lines.append(f"[OK] {result_str}{ip_result}")
                    else:
                        out_lines.append(f"[OK] {result_str}")
                else:
                    out_lines.append(f"[FAIL] {result_str}")

            return out_lines

        # Execute
        all_lines: List[str] = []
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            futures = [ex.submit(process_target, t) for t in targets]
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                try:
                    lines = fut.result()
                except Exception as e:
                    lines = [f"[ERROR] Worker exception: {e}"]
                for ln in lines:
                    all_lines.append(ln)
                    tag = "INFO"
                    if ln.startswith("[OK]"):
                        tag = "OK"
                    elif ln.startswith("[FAIL]"):
                        tag = "FAIL"
                    elif ln.startswith("[ERROR]"):
                        tag = "ERROR"
                    elif ln.startswith("[FILTERED]"):
                        tag = "FILTERED"

                    self.ui_log_cb(f"[{_ts()}] {ln}\n", tag)
                    self._write_scan_log_line(cfg.log_file, ln)

        # Final summary (same categories)
        self._write_scan_log_line(cfg.log_file, "---------------------------------------------------")
        self._write_scan_log_line(cfg.log_file, "===================================================")
        self._write_scan_log_line(cfg.log_file, "                   FINAL SUMMARY                   ")
        self._write_scan_log_line(cfg.log_file, "===================================================")
        self._write_scan_log_line(cfg.log_file, "")

        ok_lines = [ln for ln in all_lines if ln.startswith("[OK]")]
        fail_lines = [ln for ln in all_lines if ln.startswith("[FAIL]")]
        err_lines = [ln for ln in all_lines if ln.startswith("[ERROR]")]
        filt_lines = [ln for ln in all_lines if ln.startswith("[FILTERED]")]

        def emit_summary_block(title: str, lines: Sequence[str], tag: str) -> None:
            self.ui_log_cb(f"[{_ts()}] {title}\n", tag)
            self._write_scan_log_line(cfg.log_file, title)
            self.ui_log_cb(f"[{_ts()}]\n", "INFO")
            self._write_scan_log_line(cfg.log_file, "")
            for ln in lines:
                self.ui_log_cb(f"[{_ts()}] {ln}\n", tag)
                self._write_scan_log_line(cfg.log_file, ln)
            self.ui_log_cb(f"[{_ts()}]\n", "INFO")
            self._write_scan_log_line(cfg.log_file, "")

        self.ui_log_cb(f"[{_ts()}] ---------------------------------------------------\n", "INFO")
        self.ui_log_cb(f"[{_ts()}] ===================================================\n", "INFO")
        self.ui_log_cb(f"[{_ts()}]                    FINAL SUMMARY                   \n", "INFO")
        self.ui_log_cb(f"[{_ts()}] ===================================================\n", "INFO")
        self.ui_log_cb(f"[{_ts()}]\n", "INFO")

        if ok_lines:
            emit_summary_block(f"=== OK (at least one open port) [{len(ok_lines)}] ===", ok_lines, "OK")
        if fail_lines:
            emit_summary_block(f"=== FAIL (all ports closed) [{len(fail_lines)}] ===", fail_lines, "FAIL")
        if err_lines:
            emit_summary_block(f"=== RESOLVE FAILED [{len(err_lines)}] ===", err_lines, "ERROR")
        if filt_lines:
            emit_summary_block(f"=== FILTERED (Blocked/IP 10.x) [{len(filt_lines)}] ===", filt_lines, "FILTERED")

        done_line = f"Scan fully completed at {time.strftime('%a %b %d %H:%M:%S %Z %Y').strip()}"
        self.ui_log_cb(f"[{_ts()}] ---------------------------------------------------\n", "INFO")
        self.ui_log_cb(f"[{_ts()}] {done_line}\n", "INFO")
        self._write_scan_log_line(cfg.log_file, "---------------------------------------------------")
        self._write_scan_log_line(cfg.log_file, done_line)

        if self._stop.is_set():
            self.ui_log_cb(f"[{_ts()}] [WARNING] Scan stopped by user.\n", "WARNING")
            self._write_scan_log_line(cfg.log_file, "[WARNING] Scan stopped by user.")

        self.ui_log_cb(f"[{_ts()}] Full scan activity and summary saved to: {cfg.log_file}\n", "INFO")

        with self._lock:
            self._running = False
        self.on_state_cb()


# ---------- UI ----------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SNI Scanner (PyVersion UI)")
        self.geometry("920x620")
        self.minsize(860, 560)

        self._log_queue: "queue.Queue[tuple[str,str]]" = queue.Queue()

        self.cfg_input_file = tk.StringVar(value=os.path.join(os.path.dirname(_script_dir()), DEFAULT_INPUT_FILE))
        self.cfg_ports = tk.StringVar(value=DEFAULT_PORTS)
        self.cfg_timeout = tk.StringVar(value=str(DEFAULT_TIMEOUT))
        self.cfg_retries = tk.StringVar(value=str(DEFAULT_RETRIES))
        self.cfg_log_file = tk.StringVar(value=os.path.join(_script_dir(), DEFAULT_LOG_FILE))
        self.cfg_ip_check = tk.BooleanVar(value=False)
        self.cfg_manual_ip = tk.StringVar(value="")

        self.controller = ScanController(self.enqueue_log, self._sync_buttons_state)

        self._build_ui()
        self.after(50, self._drain_log_queue)

        # First-launch dependency install prompt (dnspython)
        ok = ensure_dependencies_with_ui(self, self.enqueue_log)
        if not ok:
            self.after(100, self.destroy)
            return

        # Shown immediately on UI start (as requested)
        self.enqueue_log(f"[{_ts()}] [INFO] Support / Donations:\n", "INFO")
        self.enqueue_log(f"[{_ts()}] [INFO] BEP20: {DONATION_BEP20}\n", "INFO")
        self.enqueue_log(f"[{_ts()}] [INFO] TRC: {DONATION_TRC}\n", "INFO")
        self.enqueue_log(f"[{_ts()}] ---------------------------------------------------\n", "INFO")

    def enqueue_log(self, text: str, tag: str = "INFO") -> None:
        self._log_queue.put((text, tag))

    def _drain_log_queue(self) -> None:
        while True:
            try:
                text, tag = self._log_queue.get_nowait()
            except queue.Empty:
                break
            self._append_console(text, tag)
        self.after(50, self._drain_log_queue)

    def _append_console(self, text: str, tag: str) -> None:
        self.console.configure(state="normal")
        self.console.insert("end", text, tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(side="top", fill="x")

        # Row 1: input file + browse
        r1 = ttk.Frame(top)
        r1.pack(fill="x", pady=(0, 6))
        ttk.Label(r1, text="Targets file:").pack(side="left")
        ttk.Entry(r1, textvariable=self.cfg_input_file).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(r1, text="Browse...", command=self._browse_targets).pack(side="left")

        # Row 2: ports, timeout, retries, log file
        r2 = ttk.Frame(top)
        r2.pack(fill="x", pady=(0, 6))

        ttk.Label(r2, text="Ports:").pack(side="left")
        ttk.Entry(r2, textvariable=self.cfg_ports, width=30).pack(side="left", padx=(6, 12))

        ttk.Label(r2, text="Timeout(s):").pack(side="left")
        ttk.Entry(r2, textvariable=self.cfg_timeout, width=6).pack(side="left", padx=(6, 12))

        ttk.Label(r2, text="Retries:").pack(side="left")
        ttk.Entry(r2, textvariable=self.cfg_retries, width=6).pack(side="left", padx=(6, 12))

        ttk.Label(r2, text="Log file:").pack(side="left")
        ttk.Entry(r2, textvariable=self.cfg_log_file).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(r2, text="Browse...", command=self._browse_log).pack(side="left")

        # Row 3: IP check
        r3 = ttk.Frame(top)
        r3.pack(fill="x", pady=(0, 6))
        ttk.Checkbutton(r3, text="Enable IP verification (-ip)", variable=self.cfg_ip_check).pack(side="left")
        ttk.Label(r3, text="Manual IP (optional):").pack(side="left", padx=(18, 6))
        ttk.Entry(r3, textvariable=self.cfg_manual_ip, width=18).pack(side="left")

        # Row 4: buttons
        r4 = ttk.Frame(top)
        r4.pack(fill="x", pady=(4, 0))

        self.btn_start = ttk.Button(r4, text="Start scan", command=self._start_scan)
        self.btn_pause = ttk.Button(r4, text="Pause", command=self._toggle_pause)
        self.btn_stop = ttk.Button(r4, text="Stop", command=self._stop_scan)
        self.btn_clear = ttk.Button(r4, text="Clear console", command=self._clear_console)

        self.btn_start.pack(side="left")
        self.btn_pause.pack(side="left", padx=8)
        self.btn_stop.pack(side="left")
        self.btn_clear.pack(side="left", padx=8)

        # Donations row (visible in the UI)
        r5 = ttk.Frame(top)
        r5.pack(fill="x", pady=(8, 0))
        ttk.Label(r5, text="Support / Donations:").pack(side="left")

        ttk.Label(r5, text="BEP20:").pack(side="left", padx=(10, 4))
        self._don_bep20 = tk.StringVar(value=DONATION_BEP20)
        e1 = ttk.Entry(r5, textvariable=self._don_bep20, width=48, state="readonly")
        e1.pack(side="left", padx=(0, 6))
        ttk.Button(r5, text="Copy", command=lambda: self._copy_to_clipboard(DONATION_BEP20)).pack(side="left")

        ttk.Label(r5, text="TRC:").pack(side="left", padx=(12, 4))
        self._don_trc = tk.StringVar(value=DONATION_TRC)
        e2 = ttk.Entry(r5, textvariable=self._don_trc, width=34, state="readonly")
        e2.pack(side="left", padx=(0, 6))
        ttk.Button(r5, text="Copy", command=lambda: self._copy_to_clipboard(DONATION_TRC)).pack(side="left")

        # Console
        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(side="top", fill="both", expand=True)

        ttk.Label(mid, text="Console:").pack(anchor="w")
        self.console = tk.Text(mid, wrap="word", height=20, state="disabled")
        self.console.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(mid, orient="vertical", command=self.console.yview)
        sb.pack(side="right", fill="y")
        self.console.configure(yscrollcommand=sb.set)

        # Color tags
        self.console.tag_configure("INFO", foreground="#D0D0D0")
        self.console.tag_configure("OK", foreground="#26C281")          # green
        self.console.tag_configure("FAIL", foreground="#FF5C5C")        # red
        self.console.tag_configure("ERROR", foreground="#FFB347")       # orange
        self.console.tag_configure("FILTERED", foreground="#9E9E9E")    # gray
        self.console.tag_configure("WARNING", foreground="#FFD166")     # yellow

        # Dark-ish background for console
        self.console.configure(background="#111111", insertbackground="#FFFFFF")

        self._sync_buttons_state()

    def _copy_to_clipboard(self, text: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.enqueue_log(f"[{_ts()}] [INFO] Copied to clipboard.\n", "INFO")
        except Exception as e:
            messagebox.showerror("Copy failed", str(e), parent=self)

    def _sync_buttons_state(self) -> None:
        running = self.controller.is_running()
        paused = self.controller.is_paused()

        self.btn_start.configure(state=("disabled" if running else "normal"))
        self.btn_stop.configure(state=("normal" if running else "disabled"))
        self.btn_pause.configure(state=("normal" if running else "disabled"))
        self.btn_pause.configure(text=("Resume" if paused else "Pause"))

    def _browse_targets(self) -> None:
        p = filedialog.askopenfilename(
            title="Select targets file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if p:
            self.cfg_input_file.set(p)

    def _browse_log(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Select log file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if p:
            self.cfg_log_file.set(p)

    def _clear_console(self) -> None:
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    def _validate_inputs(self) -> Optional[ScanConfig]:
        input_file = self.cfg_input_file.get().strip()
        if not input_file:
            messagebox.showerror("Invalid input", "Targets file is required.", parent=self)
            return None
        if not os.path.isfile(input_file):
            messagebox.showerror("Invalid input", f"Targets file not found:\n{input_file}", parent=self)
            return None

        ports_str = self.cfg_ports.get().strip() or DEFAULT_PORTS
        try:
            _ = _parse_ports(ports_str)
        except Exception:
            messagebox.showerror("Invalid input", "Ports must be comma-separated integers.", parent=self)
            return None

        timeout_s = _safe_int(self.cfg_timeout.get(), DEFAULT_TIMEOUT)
        retries = _safe_int(self.cfg_retries.get(), DEFAULT_RETRIES)
        log_file = self.cfg_log_file.get().strip() or DEFAULT_LOG_FILE

        enable_ip_check = bool(self.cfg_ip_check.get())
        manual_ip = self.cfg_manual_ip.get().strip()
        if manual_ip and not is_ipv4(manual_ip):
            messagebox.showerror("Invalid input", "Manual IP must be a valid IPv4 address.", parent=self)
            return None

        return ScanConfig(
            input_file=input_file,
            ports_str=ports_str,
            timeout_s=timeout_s,
            retries=retries,
            log_file=log_file,
            enable_ip_check=enable_ip_check,
            manual_ip=manual_ip,
        )

    def _start_scan(self) -> None:
        cfg = self._validate_inputs()
        if not cfg:
            return
        self.enqueue_log(f"[{_ts()}] [INFO] Starting scan...\n", "INFO")
        self.controller.start(cfg)
        self._sync_buttons_state()

    def _stop_scan(self) -> None:
        self.controller.stop()
        self._sync_buttons_state()

    def _toggle_pause(self) -> None:
        if not self.controller.is_running():
            return
        if self.controller.is_paused():
            self.controller.resume()
        else:
            self.controller.pause()
        self._sync_buttons_state()


def main() -> int:
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
