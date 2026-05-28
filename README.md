# dfir-cli

DFIR toolkit from the command line — IOC extraction, encoding/decoding, file analysis, hash triage.

Powered by [pranithjain.qzz.io](https://pranithjain.qzz.io).

## Install

```bash
pip install git+https://github.com/Pranith-Jain/dfir-cli.git
```

Or clone and install:

```bash
git clone https://github.com/Pranith-Jain/dfir-cli.git
cd dfir-cli
pip install .
```

## Usage

```bash
# Extract IOCs from text
echo "Suspicious traffic to 185.234.72.0 and CVE-2024-1709" | dfir extract

# Extract IOCs from a file
dfir extract --file report.txt

# Hash a file — MD5, SHA1, SHA256, entropy
dfir file-hash suspicious.exe

# Extract printable strings from a binary
dfir strings malware.bin
dfir strings malware.bin --min-len 8

# Decode Base64, URL encoding, hex, HTML entities
dfir decode "aHR0cHM6Ly9leGFtcGxlLmNvbQ=="
dfir decode "https%3A%2F%2Fexample.com"

# Encode data
dfir encode "https://example.com"

# Quick lookup — auto-detect type
dfir lookup 8.8.8.8
dfir lookup CVE-2024-1709
dfir lookup evil.example.com

# PE file analysis — headers, sections, entropy
dfir pe-info suspicious.exe

# Analyze text and suggest next steps
dfir analyze --file iocs.txt
```

All commands support `--json` for raw JSON output.

## Commands

| Command | Description |
|---------|-------------|
| `extract` | Extract IOCs from text/file/stdin (IPs, domains, hashes, URLs, emails, CVEs, crypto addresses) |
| `file-hash` | Hash a file — MD5, SHA1, SHA256, Shannon entropy |
| `strings` | Extract printable strings from a binary file |
| `decode` | Decode Base64, URL encoding, hex, HTML entities |
| `encode` | Encode data — Base64, URL, hex |
| `lookup` | Quick lookup — auto-detect type and query platform |
| `pe-info` | Basic PE file analysis — headers, sections, entropy |
| `analyze` | Analyze text for IOCs and suggest next steps |

## IOC Types Extracted

- IPv4 addresses
- IPv6 addresses
- Domains (with false-positive filtering)
- URLs (http/https)
- SHA256, SHA1, MD5 hashes
- Email addresses
- CVE identifiers
- Bitcoin addresses
- Ethereum addresses

## False Positive Filtering

The `extract` command filters common false-positive domains by default:
- `example.com`, `schema.org`, `github.com`, `google.com`, etc.
- Localhost/private IPs (`127.x.x.x`, `0.x.x.x`, `255.x.x.x`)

Disable with `--no-fp-filter`.

## API

Some commands call the public API at `https://pranithjain.qzz.io/api/v1/`. No API key required. Rate-limited to 30 req/min.

## License

MIT
