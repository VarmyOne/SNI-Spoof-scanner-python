# PyVersion — اسکنر SNI (پایتون)

## حمایت / دونیت

- **BEP20:** `0x0F4fbAd006DBbA1B589e2A15d72d0a6d2b6d1282`
- **TRC:** `TU3gRmn5dw8YbMfxUG5pjzMY7E2BBPCSyg`

این پوشه نسخهٔ پایتونِ ابزار Bash (`sni-scanner.sh`) است و سعی می‌کند **رفتار و خروجی را مشابه نسخهٔ اصلی** نگه دارد: رزولوشن DNS، اسکن همزمان پورت‌ها با TCP (به همراه retry)، بررسی اختیاری IP از طریق Cloudflare، لاگ‌گیری و در پایان گزارش خلاصهٔ دسته‌بندی‌شده.

> نکته: این ابزار فقط **چک TCP پورت** انجام می‌دهد و (اختیاری) صحت IP را با مسیر `/cdn-cgi/trace` بررسی می‌کند؛ «TLS fingerprint spoofing» انجام نمی‌دهد.

## پیش‌نیازها

- Python 3.10+ (تست‌شده)
- دسترسی به اینترنت (برای DNS و بررسی IP)

وابستگی پایتون:
- `dnspython` (برای رزولوشن رکوردهای `A`؛ یک fallback هم وجود دارد ولی پیشنهاد می‌شود نصب باشد)

## نصب

```bash
python -m pip install -r requirements.txt
```

## نحوهٔ استفاده

حالت پیش‌فرض (خواندن `targets.txt`، اسکن پورت‌های پیش‌فرض، خروجی در `log.txt`):

```bash
python sni_scanner.py
```

نمونهٔ سفارشی:

```bash
python sni_scanner.py -f my-targets.txt -p 80,443,8443 -t 3 -r 2 -l result.log
```

بررسی IP (تشخیص خودکار):

```bash
python sni_scanner.py -ip
```

بررسی IP (ورود دستی IP):

```bash
python sni_scanner.py -ip 1.2.3.4
```

### گزینه‌های CLI

| گزینه | مقدار پیش‌فرض | توضیح |
|---|---:|---|
| `-f` | `targets.txt` | فایل ورودی شامل دامنه/IP |
| `-p` | `443,2053,2083,2087,2096,8443` | پورت‌ها (جداشده با کاما) |
| `-t` | `5` | timeout اتصال (ثانیه) |
| `-r` | `3` | تعداد retry برای پورت‌های بسته |
| `-l` | `log.txt` | فایل لاگ خروجی |
| `-ip` | - | فعال‌سازی بررسی IP (اختیاری: IP دستی) |
| `-h` | - | نمایش راهنما |

## فرمت ورودی

یک فایل متنی بسازید (پیش‌فرض: `targets.txt`) و هر خط یک target:

```txt
104.19.229.21
example.com
google.com
```

- خطوط خالی نادیده گرفته می‌شوند
- خطوطی که با `#` شروع شوند کامنت هستند

## خروجی

نمونه:

```txt
[OK] example.com -> 104.19.229.21 -> 443✔ 2053✔ 2083✖ 2087✖ 2096✖ 8443✔ IP✔
[FAIL] 8.8.8.8 -> 8.8.8.8 -> 443✖ 2053✖ 2083✖ 2087✖ 2096✖ 8443✖
[ERROR] bad-domain.test (Could not resolve)
[FILTERED] internal.test -> 10.0.0.1 (Blocked/Internal IP)
```

در پایان، بخش **FINAL SUMMARY** چاپ می‌شود و کل خروجی در فایل لاگ هم ذخیره می‌گردد.

## ساختار پروژه

```text
PyVersion/
  README.md
  README.fa.md
  requirements.txt
  sni_scanner.py
  sni_scanner_ui.pyw
```

## جزئیات فنی (خلاصه)

- **همزمانی:** استفاده از ThreadPool با ۲۰ worker (مشابه background job ها در Bash).
- **DNS:** فقط رکوردهای `A` (IPv4) را می‌گیرد (مشابه `dig +short A`).
- **اسکن پورت:** TCP connect با `socket.create_connection` و پارامترهای `-t` و `-r`.
- **بررسی IP (`-ip`):**
  - IP عمومی را از `http://chabokan.net/ip/` می‌گیرد (یا IP دستی).
  - به `https://<domain>/cdn-cgi/trace` از طریق IP مشخص وصل می‌شود (اتصال به `<ip>:443` با SNI=`<domain>`).
  - مقدار `ip=` را با IP عمومی مقایسه می‌کند و `IP✔` یا `IP✖(...)` چاپ می‌کند.

## نسخهٔ UI (مناسب ویندوز)

یک نسخهٔ رابط کاربری (Tkinter) هم وجود دارد:

```bash
python sni_scanner_ui.pyw
```

امکانات:
- شروع اسکن / توقف / مکث / ادامه
- انتخاب فایل targets دلخواه
- کنسول داخلی با رنگ‌بندی و timestamp
- ذخیرهٔ خروجی اسکن در فایل لاگ انتخاب‌شده

### نصب خودکار در اولین اجرا

اگر `dnspython` نصب نباشد، برنامه در اولین اجرا پیشنهاد می‌دهد که وابستگی‌ها را از `requirements.txt` نصب کند.


