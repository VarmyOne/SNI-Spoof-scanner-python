# PyVersion — SNI Scanner (Python)

## Support / Donations

- **BEP20:** `0x0F4fbAd006DBbA1B589e2A15d72d0a6d2b6d1282`
- **TRC:** `TU3gRmn5dw8YbMfxUG5pjzMY7E2BBPCSyg`

A Python rewrite of the original Bash `sni-scanner.sh`, designed to behave the same:
DNS A-record resolution, concurrent TCP port checks (with retries), optional Cloudflare IP verification, logging, and a final categorized summary.

> Note: This tool does **TCP port checks** and optional Cloudflare `/cdn-cgi/trace` verification. It does **not** perform TLS fingerprint spoofing.

## Requirements

- Python 3.10+ (tested)
- Internet access (for DNS resolution and optional IP verification)

Python dependencies:
- `dnspython` (for `A` record resolution; fallback exists but `dnspython` is recommended)

## Installation

```bash
python -m pip install -r requirements.txt
```

## Usage

Default (reads `targets.txt`, scans default ports, writes `log.txt`):

```bash
python sni_scanner.py
```

Custom example:

```bash
python sni_scanner.py -f my-targets.txt -p 80,443,8443 -t 3 -r 2 -l result.log
```

IP verification (auto detect):

```bash
python sni_scanner.py -ip
```

IP verification (manual IP):

```bash
python sni_scanner.py -ip 1.2.3.4
```

### CLI Options

| Option | Default | Description |
|---|---:|---|
| `-f` | `targets.txt` | Input file containing domains/IPs |
| `-p` | `443,2053,2083,2087,2096,8443` | Comma-separated ports to scan |
| `-t` | `5` | Connection timeout (seconds) |
| `-r` | `3` | Retry count for closed ports |
| `-l` | `log.txt` | Output log file |
| `-ip` | - | Enable IP verification (optional manual IP) |
| `-h` | - | Show help |

## Input format

Create a text file (default: `targets.txt`) with one target per line:

```txt
104.19.229.21
example.com
google.com
```

- Blank lines are ignored
- Lines starting with `#` are treated as comments

## Output

Example lines:

```txt
[OK] example.com -> 104.19.229.21 -> 443✔ 2053✔ 2083✖ 2087✖ 2096✖ 8443✔ IP✔
[FAIL] 8.8.8.8 -> 8.8.8.8 -> 443✖ 2053✖ 2083✖ 2087✖ 2096✖ 8443✖
[ERROR] bad-domain.test (Could not resolve)
[FILTERED] internal.test -> 10.0.0.1 (Blocked/Internal IP)
```

At the end, the tool prints a **FINAL SUMMARY** section and saves everything to the log file.

## Project tree

```text
PyVersion/
  README.md
  README.fa.md
  requirements.txt
  sni_scanner.py
  sni_scanner_ui.pyw
```

## Technical details (brief)

- **Concurrency:** uses a thread pool (default 20 workers), similar to background jobs in the Bash version.
- **DNS:** resolves `A` records only (IPv4), matching the original `dig +short A`.
- **Port scan:** TCP connect checks using `socket.create_connection`, with `-t` timeout and `-r` retries per port.
- **IP verification (`-ip`):**
  - Auto-detects your public IP via `http://chabokan.net/ip/` (same as Bash version), or uses a manual IP.
  - Fetches `https://<domain>/cdn-cgi/trace` **through a specific IP** by connecting to `<ip>:443` and sending TLS SNI=`<domain>`.
  - Compares the returned `ip=` value to your public IP and prints `IP✔` or `IP✖(...)`.

## UI version (Windows-friendly)

There is also a Tkinter UI script:

```bash
python sni_scanner_ui.pyw
```

UI features:
- Start scan / Stop / Pause / Resume
- Import a custom targets file
- Color-coded, timestamped in-app console
- Saves scan output to the selected log file

### First launch auto-install

If `dnspython` is not installed, the UI will prompt you to install dependencies from `requirements.txt` on first launch.


