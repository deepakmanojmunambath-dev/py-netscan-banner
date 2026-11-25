import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    22: "SSH (Remote Access)",
    23: "Telnet (Unencrypted Remote Shell)",
    445: "SMB (Windows File Sharing)",
    3389: "RDP (Remote Desktop)"
}

open_results = []

def scan_port(target_ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        if s.connect_ex((target_ip, port)) == 0:
            banner = "No immediate banner"
            try:
                if port in (80, 443, 800, 8000, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(1024)
                banner = next(iter(raw.decode(errors="ignore").splitlines()), "Empty").strip()
            except Exception:
                pass

            risk_note = f" [!] {HIGH_RISK_PORTS[port]}" if port in HIGH_RISK_PORTS else ""
            finding = f"  [OPEN] Port {port:<5} | Banner: {banner}{risk_note}"
            print(finding)
            open_results.append(finding)
    except Exception:
        pass
    finally:
        s.close()

target_input = input("Enter target IP or hostname (e.g., 127.0.0.1 or scanme.nmap.org): ").strip()

try:
    target_ip = socket.gethostbyname(target_input)
except socket.gaierror:
    print("[-] Could not resolve hostname.")
    exit()

print("=" * 60)
print("MULTI-THREADED TCP SCANNER & BANNER GRABBER")
print(f"Target: {target_input} ({target_ip}) | Ports: 1-1024 | Threads: 50")
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

with ThreadPoolExecutor(max_workers=50) as executor:
    for port in range(1, 1025):
        executor.submit(scan_port, target_ip, port)

print("=" * 60)
print(f"[+] Scan complete! Total open ports found: {len(open_results)}")

with open("../notes/tcp_scan_report.txt", "w") as f:
    f.write(f"TCP Scan Report for {target_input} ({target_ip})\n")
    f.write("\n".join(open_results) + "\n")

print("[+] Report saved to /home/kali/vapt_workspace/notes/tcp_scan_report.txt")
