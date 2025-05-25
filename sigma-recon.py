#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import socket
import ssl
import dns.resolver
import whois
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from urllib.parse import urlparse
import random
import string
import subprocess
from bs4 import BeautifulSoup
import json
import re
import webbrowser

console = Console()

# Social Media Configuration
SOCIAL_LINKS = {
    "GitHub": "https://github.com/sigma-cyber-ghost",
    "YouTube": "https://www.youtube.com/@sigma_ghost_hacking",
    "Telegram": "https://web.telegram.org/k/#@Sigma_Ghost"
}

BANNER = r"""
  /$$$$$$  /$$$$$$  /$$$$$$  /$$      /$$  /$$$$$$         /$$$$$$  /$$   /$$  /$$$$$$   /$$$$$$  /$$$$$$$$
 /$$__  $$|_  $$_/ /$$__  $$| $$$    /$$$ /$$__  $$       /$$__  $$| $$  | $$ /$$__  $$ /$$__  $$|__  $$__/
| $$  \__/  | $$  | $$  \__/| $$$$  /$$$$| $$  \ $$      | $$  \__/| $$  | $$| $$  \ $$| $$  \__/   | $$   
|  $$$$$$   | $$  | $$ /$$$$| $$ $$/$$ $$| $$$$$$$$      | $$ /$$$$| $$$$$$$$| $$  | $$|  $$$$$$    | $$   
 \____  $$  | $$  | $$|_  $$| $$  $$$| $$| $$__  $$      | $$|_  $$| $$__  $$| $$  | $$ \____  $$   | $$   
 /$$  \ $$  | $$  | $$  \ $$| $$\  $ | $$| $$  | $$      | $$  \ $$| $$  | $$| $$  | $$ /$$  \ $$   | $$   
|  $$$$$$/ /$$$$$$|  $$$$$$/| $$ \/  | $$| $$  | $$      |  $$$$$$/| $$  | $$|  $$$$$$/|  $$$$$$/   | $$   
 \______/ |______/ \______/ |__/     |__/|__/  |__/      \______/ |__/  |__/ \______/  \______/    |__/   
                                                                                                          
"""

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443, 9200, 27017, 5000, 8888, 12345]
COMMON_PATHS = ["admin", "login", "dashboard", "config", ".git", "phpmyadmin", ".env", "robots.txt", "api", "shell", "uploads"]
SENSITIVE_FILES = [".git/config", "wp-config.php", "config.php", ".htaccess", ".htpasswd", "web.config", "docker-compose.yml"]
HEADERS = {
    "User-Agent": f"BlackHatScanner/{random.randint(1000,9999)} ({random.choice(['Windows NT 10.0', 'Linux x86_64'])})"
}

# ======================
# UTILITY FUNCTIONS
# ======================

def section(title):
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]", style="bold red"))

def info_table(title, columns, rows):
    table = Table(title=title, box=box.SQUARE, style="dim")
    for col in columns:
        table.add_column(col, style="cyan")
    for row in rows:
        table.add_row(*row)
    console.print(table)

def display_social_links():
    """Display and open social media links with Rich formatting"""
    try:
        social_panel = Panel(
            f"[bold cyan]Connect with SIGMA_GHOST:[/]\n\n"
            f"[yellow]• GitHub:[/] [link={SOCIAL_LINKS['GitHub']}]{SOCIAL_LINKS['GitHub']}[/]\n"
            f"[yellow]• YouTube:[/] [link={SOCIAL_LINKS['YouTube']}]{SOCIAL_LINKS['YouTube']}[/]\n"
            f"[yellow]• Telegram:[/] [link={SOCIAL_LINKS['Telegram']}]{SOCIAL_LINKS['Telegram']}[/]",
            title="Social Media",
            style="bold magenta",
            padding=(1, 2)
        )
        console.print(social_panel)
        
        for service, url in SOCIAL_LINKS.items():
            try:
                webbrowser.open_new_tab(url)
                console.print(f"[green]✓[/] Opened {service} in browser", style="dim")
            except Exception as e:
                console.print(f"[red]✗[/] Failed to open {service}: {str(e)}", style="dim")
    except Exception as e:
        console.print(f"[bold red]Social links error:[/] {str(e)}")

# ======================
# CORE FUNCTIONALITY
# ======================

async def fetch(session, url):
    try:
        async with session.get(url, timeout=10, ssl=False, headers=HEADERS) as response:
            return url, response.status, await response.text(), response.headers
    except Exception as e:
        return url, None, str(e), {}

async def domain_analysis(target):
    section("WHOIS INTELLIGENCE")
    try:
        data = whois.whois(target)
        rows = [
            ("Registrar", str(data.registrar or "N/A")),
            ("Creation", str(data.creation_date or "N/A")),
            ("Expiry", str(data.expiration_date or "N/A")),
            ("Name Servers", "\n".join(data.name_servers or []))
        ]
        info_table("WHOIS Lookup", ["Field", "Value"], rows)
    except Exception as e:
        console.print(f"[red]WHOIS failed:[/red] {e}")

async def dns_recon(target):
    section("DNS RECON")
    rows = []
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            records = dns.resolver.resolve(target, rtype)
            for r in records:
                rows.append((rtype, str(r)))
        except:
            continue
    info_table("DNS Records", ["Type", "Value"], rows)

async def port_scan(target):
    section("PORT SCAN")
    ip = socket.gethostbyname(target)
    rows = []
    
    async def scan(port):
        s = socket.socket()
        s.settimeout(1)
        try:
            await asyncio.get_event_loop().sock_connect(s, (ip, port))
            rows.append((str(port), "Open"))
        except:
            pass
        finally:
            s.close()
    
    await asyncio.gather(*(scan(p) for p in COMMON_PORTS))
    info_table("Open Ports", ["Port", "Status"], rows)

async def dir_enum(target):
    section("DIRECTORY ENUMERATION")
    base = f"http://{target}"
    rows = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, f"{base}/{p}") for p in COMMON_PATHS + SENSITIVE_FILES]
        results = await asyncio.gather(*tasks)
        for url, status, content, _ in results:
            if status and status < 400:
                rows.append((url, str(status), str(len(content))))
    info_table("Directories Found", ["URL", "Status", "Length"], rows)

async def ssl_info(target):
    section("SSL/TLS INSPECTION")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                rows = [
                    ("Issuer", cert.get('issuer', [[('commonName', 'N/A')]])[0][0][1]),
                    ("Valid From", cert.get('notBefore', 'N/A')),
                    ("Valid Until", cert.get('notAfter', 'N/A'))
                ]
                info_table("SSL Certificate", ["Field", "Value"], rows)
    except Exception as e:
        console.print(f"[red]SSL extraction failed:[/red] {e}")

async def traceroute(target):
    section("NETWORK TRACEROUTE")
    try:
        result = subprocess.run(["traceroute", target], capture_output=True, text=True)
        hops = result.stdout.strip().split("\n")
        rows = [(str(i+1), hop) for i, hop in enumerate(hops) if hop.strip()]
        info_table("Traceroute Path", ["Hop", "Response"], rows)
    except Exception as e:
        console.print(f"[red]Traceroute failed:[/red] {e}")

async def http_headers(target):
    section("HTTP HEADERS ANALYSIS")
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://{target}"
            async with session.get(url, headers=HEADERS) as resp:
                rows = [(k, v) for k, v in resp.headers.items()]
                info_table("HTTP Response Headers", ["Header", "Value"], rows)
    except Exception as e:
        console.print(f"[red]HTTP Header fetch failed:[/red] {e}")

async def forms_and_inputs(target):
    section("WEB FORMS & INPUT FIELDS")
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://{target}"
            async with session.get(url, headers=HEADERS) as resp:
                html = await resp.text()
                soup = BeautifulSoup(html, "html.parser")
                forms = soup.find_all("form")
                rows = []
                for i, form in enumerate(forms):
                    action = form.get("action", "N/A")
                    method = form.get("method", "GET").upper()
                    inputs = [i.get("name", "") for i in form.find_all("input")]
                    rows.append((f"Form #{i+1}", f"Action: {action} | Method: {method} | Inputs: {', '.join(inputs)}"))
                info_table("Detected Forms", ["ID", "Details"], rows)
    except Exception as e:
        console.print(f"[red]Form parsing failed:[/red] {e}")

async def vuln_scan(target):
    section("VULNERABILITY FINGERPRINTING")
    base_url = f"http://{target}"
    patterns = {
        "WordPress": r"wp-content|wp-includes",
        "phpMyAdmin": r"phpMyAdmin",
        "Joomla": r"/media/system/js",
        "Drupal": r"sites/all|misc/drupal.js",
        "Laravel": r"\.env",
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(base_url, headers=HEADERS) as resp:
                html = await resp.text()
                matches = [(name, "Detected") for name, pattern in patterns.items() if re.search(pattern, html)]
                if matches:
                    info_table("Potential Technologies", ["Tech", "Status"], matches)
                else:
                    console.print("[yellow]No known fingerprints detected.[/yellow]")
        except Exception as e:
            console.print(f"[red]Scan failed:[/red] {e}")

# ======================
# MAIN FUNCTION
# ======================

async def main():
    parser = argparse.ArgumentParser(description="Sigma Ghost - Black Hat Recon")
    parser.add_argument("--target", required=True, help="Target domain")
    args = parser.parse_args()

    console.print(Panel(BANNER, style="bold green"))
    display_social_links()
    console.print(f"\n[bold red]Target:[/] {args.target}\n")

    await domain_analysis(args.target)
    await dns_recon(args.target)
    await port_scan(args.target)
    await dir_enum(args.target)
    await ssl_info(args.target)
    await traceroute(args.target)
    await http_headers(args.target)
    await forms_and_inputs(args.target)
    await vuln_scan(args.target)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[bold red]Interrupted. Exit initiated.[/bold red]")
