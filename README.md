# Multi-Threaded TCP Port Scanner & Banner Grabber (`py-netscan-banner`)

A fast, lightweight TCP network reconnaissance utility written in Python using raw `socket` connections and `concurrent.futures.ThreadPoolExecutor`.

## Key Features
- **High-Speed Multi-Threaded Scanning:** Scans well-known TCP ports (`1–1024`) concurrently across 50 worker threads with non-blocking socket timeouts.
- **Live Service Banner Grabbing:** Sends protocol probes and captures raw service banners (`OpenSSH`, `Apache/HTTP`, `FTP`, `SMTP`) directly over TCP sockets.
- **High-Risk Service Flagging:** Automatically highlights sensitive exposed ports (`21/FTP`, `22/SSH`, `23/Telnet`, `445/SMB`, `3389/RDP`).
- **Automated Reporting:** Exports timestamped scan findings directly to a clean text report.

## Usage
```bash
python3 port_scanner.py
```

## Disclaimer
Intended strictly for authorized penetration testing, lab networks, and permitted targets such as `scanme.nmap.org`.
