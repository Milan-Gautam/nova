# NOVA — JS Enumerator

JavaScript enumeration and endpoint-discovery tool. Crawls a target, pulls JS files from HTML/JS content, follows JS-to-JS chains, brute-forces common paths, checks passive sources (Wayback, urlscan), and extracts endpoints and likely secrets — across single or multiple targets.

## Install

```bash
curl -O https://raw.githubusercontent.com/Milan-Gautam/astra/main/nova.py
chmod +x nova.py
```

## Usage

```bash
# Single target
python nova.py -u https://example.com

# From a file of subdomains
python nova.py -f domains.txt

# Pipe from other recon tools
subfinder -d example.com -silent | python nova.py --mode aggressive

# Quiet mode for piping JS URLs onward
cat urls.txt | python nova.py --quiet | tee all_js.txt
```

## Scan Modes

| Mode | Threads | Depth | Rate Limit | Brute Force | Passive |
|---|---|---|---|---|---|
| `stealth` | 3 | 1 | 2.0s | off | off |
| `normal` | 10 | 3 | 0.1s | on | on |
| `aggressive` | 20+ | 5+ | 0.01s | on | on |
| `insane` | 50+ | 10+ | 0s | on | on |

## Key Flags

- `-u/-f` — single URL or file of targets (also accepts stdin)
- `--mode` — stealth / normal / aggressive / insane
- `-t`, `--concurrent`, `-d`, `--rate` — tune threads, concurrent targets, crawl depth, rate limit
- `--no-passive`, `--no-brute`, `--no-deep`, `--no-endpoints`, `--no-secrets`, `--no-chain` — disable individual features
- `--merge` — combine all targets' results into single output files
- `--quiet` — minimal console output, prints discovered JS URLs for piping
- `-o` — output directory (default `nova_output`)

## Output

Per target, under `nova_output/nova_scan_<timestamp>/<domain>/`:
- `js_files.txt`
- `endpoints.txt`
- `secrets.txt`
- `report.json`

Plus a global `summary.json`, and `all_js_files.txt` / `all_endpoints.txt` / `all_secrets.txt` if `--merge` is used.

