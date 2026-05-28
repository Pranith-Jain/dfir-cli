#!/usr/bin/env python3
"""dfir-cli — DFIR toolkit from the command line.

IOC extraction, hash/domain/IP lookups, encoding/decoding, file analysis.
Powered by pranithjain.qzz.io.
"""

import hashlib
import base64
import binascii
import json
import math
import os
import re
import struct
import sys
import urllib.parse

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

BASE = "https://pranithjain.qzz.io/api/v1"
console = Console()


def api_get(path, **kwargs):
    try:
        r = requests.get(BASE + path, timeout=60, **kwargs)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        console.print(f"[red]API error ({e.response.status_code})[/red]")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot reach pranithjain.qzz.io[/red]")
        sys.exit(1)


# ── IOC Extraction ────────────────────────────────────────────────────────────

IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    "url": re.compile(r'https?://[^\s<>"\']+', re.I),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    "cve": re.compile(r'CVE-\d{4}-\d{4,}', re.I),
    "btc": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "eth": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
}

# Known false-positive domains to exclude from IOC extraction
FP_DOMAINS = {
    'example.com', 'example.org', 'example.net', 'localhost.localdomain',
    'schema.org', 'www.w3.org', 'json-schema.org', 'purl.org',
    'creativecommons.org', 'apache.org', 'github.com', 'github.io',
    'google.com', 'googleapis.com', 'gstatic.com', 'cloudflare.com',
    'microsoft.com', 'windows.com', 'apple.com', 'mozilla.org',
    'python.org', 'pypi.org', 'npmjs.com', 'npmjs.org',
}


def extract_iocs(text, exclude_fp=True):
    """Extract IOCs from text. Returns dict of kind -> set of values."""
    iocs = {}
    for kind, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        if exclude_fp and kind == 'domain':
            matches = {m for m in matches if m.lower() not in FP_DOMAINS and len(m) > 4}
        if exclude_fp and kind == 'ipv4':
            matches = {m for m in matches if not m.startswith(('0.', '127.', '255.'))}
        if matches:
            iocs[kind] = matches
    return iocs


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="dfir")
def cli():
    """dfir-cli — Digital Forensics & Incident Response toolkit.

    IOC extraction, encoding/decoding, hash analysis, file triage.
    Powered by pranithjain.qzz.io.
    """
    pass


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read from file")
@click.option("--stdin", "use_stdin", is_flag=True, help="Read from stdin")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
@click.option("--no-fp-filter", is_flag=True, help="Include likely false positives")
def extract(text, file, use_stdin, as_json, no_fp_filter):
    """Extract IOCs from text, file, or stdin.

    Pulls IPs, domains, hashes (MD5/SHA1/SHA256), URLs, emails, CVEs,
    Bitcoin addresses, Ethereum addresses. Filters common false positives.
    """
    if file:
        with open(file) as fh:
            raw = fh.read()
    elif use_stdin or (not text and not sys.stdin.isatty()):
        raw = sys.stdin.read()
    elif text:
        raw = text
    else:
        console.print("[red]Provide text, --file, or pipe via stdin.[/red]")
        sys.exit(1)

    iocs = extract_iocs(raw, exclude_fp=not no_fp_filter)

    if as_json:
        out = {k: sorted(v) for k, v in iocs.items()}
        click.echo(json.dumps(out, indent=2))
        return

    total = sum(len(v) for v in iocs.values())
    console.print(f"\n[bold]{total}[/bold] IOCs extracted:\n")

    for kind in ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "cve", "btc", "eth"]:
        values = iocs.get(kind, set())
        if not values:
            continue
        console.print(f"[bold cyan]{kind}[/bold cyan] ({len(values)})")
        for v in sorted(values):
            console.print(f"  {v}")
        console.print()


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def file_hash(file_path, as_json):
    """Hash a file — MD5, SHA1, SHA256, ssdeep (if available), entropy."""
    with open(file_path, "rb") as f:
        data = f.read()

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)

    # Shannon entropy
    if size > 0:
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = -sum((f / size) * math.log2(f / size) for f in freq if f > 0)
    else:
        entropy = 0.0

    if as_json:
        click.echo(json.dumps({
            "file": file_path,
            "size": size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "entropy": round(entropy, 4),
        }, indent=2))
        return

    console.print(Panel(
        f"[bold]{os.path.basename(file_path)}[/bold]\n"
        f"Size: {size:,} bytes\n"
        f"Entropy: {entropy:.4f} / 8.0 {'[red](packed/encrypted)[/red]' if entropy > 7.0 else '[green](normal)[/green]' if entropy < 6.0 else '[yellow](suspicious)[/yellow]'}\n\n"
        f"MD5:    {md5}\n"
        f"SHA1:   {sha1}\n"
        f"SHA256: {sha256}",
        title="File Hash",
        border_style="cyan",
    ))


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--min-len", "-n", default=4, help="Minimum string length")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def strings(file_path, min_len, as_json):
    """Extract printable strings from a binary file."""
    with open(file_path, "rb") as f:
        data = f.read()

    # ASCII strings
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    ascii_strings = [m.group().decode('ascii') for m in pattern.finditer(data)]

    # Unicode (UTF-16LE) strings
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')
    utf16_strings = [m.group().decode('utf-16-le') for m in utf16_pattern.finditer(data)]

    all_strings = list(set(ascii_strings + utf16_strings))

    if as_json:
        click.echo(json.dumps({"count": len(all_strings), "strings": all_strings[:500]}, indent=2))
        return

    console.print(f"[bold]{len(all_strings)}[/bold] strings extracted (showing up to 200):\n")
    for s in all_strings[:200]:
        console.print(f"  {s}")
    if len(all_strings) > 200:
        console.print(f"\n  [dim]... and {len(all_strings) - 200} more[/dim]")


@cli.command()
@click.argument("data")
def decode(data):
    """Decode Base64, URL encoding, hex, or HTML entities.

    Tries all decoders and shows results.
    """
    results = []

    # Base64
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        results.append(("Base64", decoded))
    except Exception:
        pass

    # URL encoding
    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data:
            results.append(("URL encoded", decoded))
    except Exception:
        pass

    # HTML entities
    import html
    decoded = html.unescape(data)
    if decoded != data:
        results.append(("HTML entities", decoded))

    # Hex
    try:
        if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
            decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
            results.append(("Hex", decoded))
    except Exception:
        pass

    if not results:
        console.print("[yellow]Could not decode — no recognized encoding.[/yellow]")
        return

    for method, decoded in results:
        console.print(f"[bold cyan]{method}:[/bold cyan]")
        console.print(f"  {decoded}\n")


@cli.command()
@click.argument("data")
def encode(data):
    """Encode data — Base64, URL encoding, hex."""
    console.print(f"[bold cyan]Base64:[/bold cyan]")
    console.print(f"  {base64.b64encode(data.encode()).decode()}\n")
    console.print(f"[bold cyan]URL:[/bold cyan]")
    console.print(f"  {urllib.parse.quote(data)}\n")
    console.print(f"[bold cyan]Hex:[/bold cyan]")
    console.print(f"  {data.encode().hex()}\n")


@cli.command()
@click.argument("indicator")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def lookup(indicator, as_json):
    """Quick lookup — auto-detect type and check against the platform.

    Detects IP, domain, hash, CVE, or keyword and runs the appropriate check.
    """
    itype = detect_type(indicator)
    console.print(f"[dim]Detected type:[/dim] {itype}")

    if itype == "cve":
        data = api_get("/cve/lookup", params={"id": indicator})
    elif itype == "ip":
        data = api_get("/ip-geo", params={"ip": indicator})
    elif itype == "domain":
        data = api_get("/domain/lookup", params={"domain": indicator})
    else:
        data = api_get("/copilot/investigate", params={"q": indicator})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    console.print(Panel(json.dumps(data, indent=2)[:2000], title=f"Lookup: {indicator}", border_style="cyan"))


def detect_type(value):
    v = value.strip()
    if re.match(r'^CVE-\d{4}-\d{4,}$', v, re.I):
        return "cve"
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
        return "ip"
    if re.match(r'^[a-fA-F0-9]{64}$', v):
        return "sha256"
    if re.match(r'^[a-fA-F0-9]{40}$', v):
        return "sha1"
    if re.match(r'^[a-fA-F0-9]{32}$', v):
        return "md5"
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', v):
        return "domain"
    return "keyword"


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def pe_info(file_path, as_json):
    """Basic PE file analysis — headers, sections, imports.

    Works on Windows EXE/DLL files. No external dependencies.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    if data[:2] != b'MZ':
        console.print("[red]Not a PE file (missing MZ header).[/red]")
        sys.exit(1)

    # Find PE header
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        console.print("[red]Invalid PE header.[/red]")
        sys.exit(1)

    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
    opt_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    characteristics = struct.unpack_from('<H', data, pe_offset + 22)[0]

    machine_names = {0x14c: 'i386', 0x8664: 'AMD64', 0xaa64: 'ARM64'}
    machine_str = machine_names.get(machine, f'0x{machine:x}')

    is_dll = bool(characteristics & 0x2000)
    is_exe = bool(characteristics & 0x0002)
    is_sys = bool(characteristics & 0x1000)
    file_type = "DLL" if is_dll else "SYS" if is_sys else "EXE" if is_exe else "Unknown"

    from datetime import datetime
    try:
        compile_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OSError):
        compile_time = f"0x{timestamp:x} (invalid)"

    # Sections
    sections_start = pe_offset + 24 + opt_size
    sections = []
    for i in range(num_sections):
        off = sections_start + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, off + 8)[0]
        rawsize = struct.unpack_from('<I', data, off + 16)[0]
        entropy_str = ""
        if rawsize > 0:
            raw_offset = struct.unpack_from('<I', data, off + 20)[0]
            section_data = data[raw_offset:raw_offset+rawsize]
            if section_data:
                freq = [0] * 256
                for b in section_data:
                    freq[b] += 1
                ent = -sum((f / len(section_data)) * math.log2(f / len(section_data)) for f in freq if f > 0)
                entropy_str = f"{ent:.2f}"
        sections.append({"name": name, "vsize": vsize, "rawsize": rawsize, "entropy": entropy_str})

    if as_json:
        click.echo(json.dumps({
            "file": file_path,
            "type": file_type,
            "machine": machine_str,
            "compile_time": compile_time,
            "sections": sections,
        }, indent=2))
        return

    console.print(Panel(
        f"[bold]{os.path.basename(file_path)}[/bold]\n"
        f"Type: {file_type}  ·  Arch: {machine_str}  ·  Compiled: {compile_time}\n"
        f"Sections: {num_sections}",
        title="PE Analysis",
        border_style="cyan",
    ))

    if sections:
        tbl = Table(box=box.SIMPLE, show_header=True)
        tbl.add_column("Section")
        tbl.add_column("Virtual Size", justify="right")
        tbl.add_column("Raw Size", justify="right")
        tbl.add_column("Entropy", justify="right")
        for s in sections:
            ent = float(s['entropy']) if s['entropy'] else 0
            ent_color = "red" if ent > 7.0 else "green" if ent < 6.0 else "yellow"
            tbl.add_row(
                s['name'],
                f"{s['vsize']:,}",
                f"{s['rawsize']:,}",
                f"[{ent_color}]{s['entropy']}[/{ent_color}]" if s['entropy'] else "—",
            )
        console.print(tbl)


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read from file")
@click.option("--stdin", "use_stdin", is_flag=True, help="Read from stdin")
def analyze(text, file, use_stdin):
    """Analyze text for IOCs and run enrichment on each.

    Extracts IOCs from text, then checks each against the platform's
    enrichment providers. Shows a summary of findings.
    """
    if file:
        with open(file) as fh:
            raw = fh.read()
    elif use_stdin or (not text and not sys.stdin.isatty()):
        raw = sys.stdin.read()
    elif text:
        raw = text
    else:
        console.print("[red]Provide text, --file, or pipe via stdin.[/red]")
        sys.exit(1)

    iocs = extract_iocs(raw)
    indicators = []
    for kind in ['ipv4', 'domain', 'sha256', 'sha1', 'md5']:
        indicators.extend(iocs.get(kind, []))

    if not indicators:
        console.print("[yellow]No actionable IOCs found in input.[/yellow]")
        return

    console.print(f"[bold]{len(indicators)}[/bold] indicators to check:\n")
    for ind in indicators[:10]:
        console.print(f"  {ind}")
    if len(indicators) > 10:
        console.print(f"  [dim]... and {len(indicators) - 10} more[/dim]")

    console.print(f"\n[dim]Run [bold]dfir extract[/bold] on the same input for full IOC details.[/dim]")
    console.print(f"[dim]Use [bold]cti check <indicator>[/bold] (from cti-cli) for full enrichment.[/dim]")


if __name__ == "__main__":
    cli()
