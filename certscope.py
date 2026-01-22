#!/usr/bin/env python3
"""
CertScope – Scoped TLS Certificate Reconnaissance Tool
"""

import sys
import ssl
import socket
import time
import random
import json
import csv
import argparse
import ipaddress
from datetime import datetime
from typing import List

import masscan
from OpenSSL import SSL

# ==========================================================
# METADATA
# ==========================================================

TOOL_NAME = "CertScope"
VERSION = "1.1.0"

# ==========================================================
# DEFAULT CONFIG
# ==========================================================

DEFAULT_PORT = 443
DEFAULT_RATE = 500
CONNECT_TIMEOUT = 1.5
STEALTH_DELAY_RANGE = (0.05, 0.25)

TLS_CIPHER_PROFILES = [
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "HIGH:!aNULL:!MD5",
    "DEFAULT"
]

RESULTS = []
ALLOWED_SCOPES = []

# ==========================================================
# BANNER
# ==========================================================

def banner():
    print("-" * 72)
    print(f"""
_________                __   _________                           
\\_   ___ \\  ____________/  |_/   _____/ ____  ____ ______   ____  
/    \\  \\/_/ __ \\_  __ \\   __\\_____  \\_/ ___\\/  _ \\____ \\_/ __ \\ 
\\     \\___\\  ___/|  | \\/|  | /        \\  \\__(  <_> )  |_> >  ___/ 
 \\______  /\\___  >__|   |__|/_______  /\\___  >____/|   __/ \\___  >
        \\/     \\/                   \\/     \\/      |__|        \\/ 

{TOOL_NAME} v{VERSION}
Scoped TLS Certificate Reconnaissance Tool
""")
    print("-" * 72)


# ==========================================================
# ARGUMENT PARSING
# ==========================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumerate hostnames via TLS certificates (scoped)."
    )

    parser.add_argument("cidr", help="Target CIDR range")
    parser.add_argument("--json", metavar="FILE", help="Write JSON output to file")
    parser.add_argument("--csv", metavar="FILE", help="Write CSV output to file")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE,
                        help=f"masscan rate (default: {DEFAULT_RATE})")
    parser.add_argument("--scope-file", metavar="FILE",
                        help="File containing allowed CIDRs (one per line)")

    return parser.parse_args()


# ==========================================================
# SCOPE HANDLING
# ==========================================================

def load_scope(scope_file: str):
    scopes = []
    with open(scope_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                scopes.append(ipaddress.ip_network(line))
    return scopes


def is_in_scope(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWED_SCOPES)


# ==========================================================
# TLS CONTEXT (Fingerprint Rotation)
# ==========================================================

def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.set_ciphers(random.choice(TLS_CIPHER_PROFILES))
    except ssl.SSLError:
        pass

    return ctx


# ==========================================================
# SSL BACKENDS
# ==========================================================

def get_domains_stdlib(ip: str, port: int = DEFAULT_PORT) -> List[str]:
    ctx = build_ssl_context()

    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()

        domains = []

        for field in cert.get("subject", []):
            if field[0][0] == "commonName":
                domains.append(field[0][1])

        for k, v in cert.get("subjectAltName", []):
            if k == "DNS":
                domains.append(v)

        return sorted(set(domains))

    except Exception:
        return []


def get_domains_openssl(ip: str, port: int = DEFAULT_PORT) -> List[str]:
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *x: True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)

    try:
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(ip.encode())
        conn.connect((ip, port))
        conn.do_handshake()

        cert = conn.get_peer_certificate()
        domains = []

        if cert:
            subj = cert.get_subject()
            if subj.commonName:
                domains.append(subj.commonName)

            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"subjectAltName":
                    for part in str(ext).split(","):
                        if "DNS:" in part:
                            domains.append(part.replace("DNS:", "").strip())

        conn.close()
        return sorted(set(domains))

    except Exception:
        return []
    finally:
        sock.close()


def get_domains(ip: str) -> List[str]:
    domains = get_domains_stdlib(ip)
    return domains if domains else get_domains_openssl(ip)


# ==========================================================
# MASSCAN API COMPAT
# ==========================================================

def iter_masscan_hosts(scanner):
    attr = getattr(scanner, "all_hosts", None)
    return attr() if callable(attr) else attr


# ==========================================================
# OUTPUT HANDLING
# ==========================================================

def record_result(ip: str, domains: List[str]):
    entry = {
        "ip": ip,
        "domains": domains,
        "domain_count": len(domains),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    RESULTS.append(entry)

    # PRIMARY OUTPUT → STDOUT
    if domains:
        print(f"{ip}:{','.join(domains)}")
    else:
        print(f"{ip}:no-cert")


def write_json(path: str):
    with open(path, "w") as f:
        json.dump(RESULTS, f, indent=2)


def write_csv(path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "domains", "domain_count", "timestamp"])
        for r in RESULTS:
            writer.writerow([
                r["ip"],
                ";".join(r["domains"]),
                r["domain_count"],
                r["timestamp"]
            ])


# ==========================================================
# SCANNER
# ==========================================================

def scan_cidr(cidr: str, rate: int):
    mas = masscan.PortScanner()
    mas.scan(
        hosts=cidr,
        ports=str(DEFAULT_PORT),
        arguments=f"--rate {rate}"
    )

    for ip in iter_masscan_hosts(mas):
        if not is_in_scope(ip):
            continue

        time.sleep(random.uniform(*STEALTH_DELAY_RANGE))
        record_result(ip, get_domains(ip))


# ==========================================================
# MAIN
# ==========================================================

def main():
    banner()
    args = parse_args()

    try:
        ipaddress.ip_network(args.cidr)
    except ValueError:
        print("Invalid CIDR range")
        sys.exit(1)

    global ALLOWED_SCOPES
    if args.scope_file:
        ALLOWED_SCOPES = load_scope(args.scope_file)
    else:
        print("[!] No --scope-file provided, refusing to run")
        sys.exit(1)

    scan_cidr(args.cidr, args.rate)

    if args.json:
        write_json(args.json)
        print(f"[+] JSON written to {args.json}")

    if args.csv:
        write_csv(args.csv)
        print(f"[+] CSV written to {args.csv}")


if __name__ == "__main__":
    main()

