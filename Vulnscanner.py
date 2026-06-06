import socket
import json
import time
import os
from datetime import datetime

# ==========================
# VULNERABILITY DATABASE
# ==========================
VULNERABILITIES = {
    "Apache/2.2": "Outdated Apache version detected.",
    "OpenSSH_5": "Old SSH version detected.",
    "vsFTPd 2.3.4": "Known vulnerable FTP version."
}

PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

# ==========================
# BANNER
# ==========================
def banner():
    os.system("clear")

    print(r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██╗██╗     ██╗████████╗██╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██║     ██║╚══██╔══╝╚██╗ ██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██║██║     ██║   ██║    ╚████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║██║     ██║   ██║     ╚██╔╝
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║██████╔╝██║███████╗██║   ██║      ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝

                               SCANNER
""")
    print("=" * 90)
    print("          Python Based Vulnerability Assessment Tool")
    print("=" * 90)

# ==========================
# LOADING ANIMATION
# ==========================
def loading():
    print("\nInitializing Scanner", end="")
    for _ in range(10):
        print(".", end="", flush=True)
        time.sleep(0.2)
    print("\n")

# ==========================
# PORT SCAN
# ==========================
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        if result == 0:
            banner = "Unknown"

            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore")
            except:
                pass

            sock.close()
            return True, banner

        sock.close()
        return False, None

    except:
        return False, None

# ==========================
# REPORT GENERATION
# ==========================
def generate_report(host, findings):
    filename = "vulnerability_report.txt"

    with open(filename, "w") as report:
        report.write("=== VULNERABILITY SCAN REPORT ===\n")
        report.write(f"Target: {host}\n")
        report.write(f"Date: {datetime.now()}\n\n")

        for item in findings:
            report.write(f"Port: {item['port']}\n")
            report.write(f"Banner: {item['banner']}\n")

            if item['vulnerability']:
                report.write(
                    f"Vulnerability: {item['vulnerability']}\n"
                )

            report.write("-" * 50 + "\n")

    print(f"\n[+] Report saved as {filename}")

# ==========================
# MAIN
# ==========================
def main():
    banner()
    loading()

    host = input("Enter Target IP or Hostname: ")

    print(f"\nScanning {host}...\n")

    findings = []

    for port in PORTS:
        print(f"[*] Checking Port {port}...", end="\r")

        open_port, service_banner = scan_port(host, port)

        if open_port:
            print(f"[+] Port {port} OPEN")

            vulnerability = None

            for signature, description in VULNERABILITIES.items():
                if signature.lower() in service_banner.lower():
                    vulnerability = description

            findings.append({
                "port": port,
                "banner": service_banner.strip(),
                "vulnerability": vulnerability
            })

    if findings:
        generate_report(host, findings)
    else:
        print("\n[-] No open ports found.")

    print("\nScan Complete!")

if __name__ == "__main__":
    main()
