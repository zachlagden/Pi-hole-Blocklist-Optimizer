# Pi-hole Blocklist Optimizer

<div align="center">

![GitHub release (latest by date)](https://img.shields.io/github/v/release/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![GitHub](https://img.shields.io/github/license/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![Stars](https://img.shields.io/github/stars/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)

**A fast, single-binary tool for downloading, optimizing, and organizing
blocklists for [Pi-hole](https://pi-hole.net/)**

[Features](#features) • [Installation](#installation) •
[Quick Start](#quick-start) • [Whitelist](#whitelist-support) •
[Configuration](#configuration) • [Usage](#usage)

</div>

## What Does This Tool Do?

1. **Downloads** blocklists from multiple sources (async concurrent)
2. **Validates** domains and removes invalid entries
3. **Optimizes** by removing duplicates across all lists
4. **Filters** domains using your whitelist (exact, wildcard, regex)
5. **Organizes** into categories (advertising, tracking, malicious, etc.)
6. **Combines** into production-ready lists

## Features

- **Async concurrent downloads** — configurable 1-16 concurrent connections
- **Whitelist support** — filter domains with exact matches, wildcards, or regex
  patterns
- **Incremental updates** — only re-download changed lists (ETag/Last-Modified
  support)
- **Multi-format support** — handles hosts files, AdBlock, and plain domain
  formats
- **Progress tracking** — resume interrupted downloads
- **Detailed reporting** — statistics and whitelist match reports
- **Error recovery** — automatic retry with exponential backoff
- **Single binary** — no runtime dependencies, statically linked TLS

## Installation

### From GitHub Releases (Recommended)

Download the latest binary for your platform from
[Releases](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer/releases):

```bash
# Linux x86_64
curl -LO https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer/releases/latest/download/pihole-optimizer-linux-x86_64
chmod +x pihole-optimizer-linux-x86_64
sudo mv pihole-optimizer-linux-x86_64 /usr/local/bin/pihole-optimizer

# Linux ARM (Raspberry Pi)
curl -LO https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer/releases/latest/download/pihole-optimizer-linux-aarch64
chmod +x pihole-optimizer-linux-aarch64
sudo mv pihole-optimizer-linux-aarch64 /usr/local/bin/pihole-optimizer
```

### From Source

Requires [Rust](https://rustup.rs/) (stable).

```bash
git clone https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer
cd Pi-hole-Blocklist-Optimizer
cargo build --release
# Binary at target/release/pihole-optimizer
```

## Quick Start

```bash
pihole-optimizer
```

That's it! The tool will:

1. Download blocklists from `blocklists.conf`
2. Validate and optimize domains
3. Apply whitelist filtering
4. Create production lists in `pihole_blocklists_prod/`

## Whitelist Support

Create a `whitelist.txt` file to exclude domains from the final output. Three
matching types are supported:

### Exact Domains

```
example.com           # Matches example.com and *.example.com (subdomains)
google.com
```

### Wildcard Patterns

```
*.tracking.com        # Matches any.tracking.com
ads.*                 # Matches ads.example.com, ads.site.net
*analytics*           # Matches myanalytics.com, analytics.site.net
```

### Regex Patterns

```
/^track.*\.com$/      # Matches tracker.com, tracking.com
/.*\.ads\..*$/        # Matches sub.ads.example.com
```

### Example whitelist.txt

```
# Exact domains (with subdomain matching)
github.com
googleapis.com

# Wildcards
*.cdn.example.com
*cloudfront*

# Regex patterns
/^api\..*\.com$/
```

Run with `--whitelist-report` to see which domains were filtered and by which
patterns.

## Configuration

### blocklists.conf

Define blocklist sources in `blocklists.conf`:

```
url|name|category
```

Example:

```
https://adaway.org/hosts.txt|adaway|advertising
https://someonewhocares.org/hosts/hosts|someonewhocares|comprehensive
```

Categories: `advertising`, `tracking`, `malicious`, `suspicious`, `nsfw`,
`comprehensive`

Lines starting with `#` are ignored.

## Usage

### Basic

```bash
pihole-optimizer
```

### With Options

```bash
# Fast download with 8 threads and whitelist report
pihole-optimizer -t 8 --whitelist-report

# Custom config and output directory
pihole-optimizer -c myconfig.conf -p /var/blocklists

# Verbose logging
pihole-optimizer -v

# Dry run
pihole-optimizer --dry-run
```

### All Options

```
Usage: pihole-optimizer [OPTIONS]

Options:
  -c, --config <CONFIG>         Configuration file path [default: blocklists.conf]
  -w, --whitelist <WHITELIST>   Whitelist file path [default: whitelist.txt]
  -b, --base-dir <BASE_DIR>    Base output directory [default: pihole_blocklists]
  -p, --prod-dir <PROD_DIR>    Production output directory [default: pihole_blocklists_prod]
  -t, --threads <THREADS>      Concurrent downloads 1-16 [default: 4]
      --timeout <TIMEOUT>      HTTP timeout in seconds [default: 30]
      --skip-download          Use existing local files
      --skip-optimize          Skip creating production lists
      --no-incremental         Force re-download all lists
      --dry-run                Show what would happen without doing it
      --no-whitelist-subdomain Disable subdomain matching in whitelist
      --whitelist-report       Generate detailed whitelist match report
  -v, --verbose                Debug logging
  -q, --quiet                  Errors only
  -h, --help                   Print help
  -V, --version                Print version
```

## Output Structure

```
pihole_blocklists/              # Individual optimized lists
├── advertising/
├── tracking/
├── malicious/
├── suspicious/
├── nsfw/
└── comprehensive/

pihole_blocklists_prod/         # Combined production lists
├── all_domains.txt             # All unique domains (excludes NSFW)
├── advertising.txt
├── tracking.txt
├── malicious.txt
├── suspicious.txt
├── nsfw.txt                    # Separate — not included in all_domains.txt
├── comprehensive.txt
└── whitelist_report.txt        # (if --whitelist-report used)
```

## Using with Pi-hole

### Option 1: Use Pre-built Lists (Recommended)

Use the companion repository
[Pi-hole-Optimized-Blocklists](https://github.com/zachlagden/Pi-hole-Optimized-Blocklists)
which runs this optimizer weekly and hosts the results.

Add these URLs to Pi-hole's Adlists:

```
https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt
```

### Option 2: Self-Host

Run the optimizer and host the files on your own server, then add the URLs to
Pi-hole.

### Option 3: Local Files

```bash
sudo cp pihole_blocklists_prod/*.txt /etc/pihole/
pihole -g
```

## Performance

- 30+ blocklists, 1.6M+ unique domains processed in ~20 seconds
- Async I/O with configurable concurrency
- ~5MB self-contained binary, no runtime dependencies

## Troubleshooting

| Issue             | Solution                                   |
| ----------------- | ------------------------------------------ |
| Connection errors | Check internet, try fewer threads (`-t 2`) |
| Slow downloads    | Increase threads (`-t 8`)                  |
| Missing domains   | Check whitelist isn't too broad            |

## Contributing

Contributions welcome! Open an issue or submit a PR.

```bash
git clone https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer
cd Pi-hole-Blocklist-Optimizer
cargo build
cargo test
cargo fmt --check

# Enable pre-commit hooks
git config core.hooksPath .githooks
```

## License

This project is licensed under the MIT License — see the [LICENCE](LICENCE) file
for details.

## Acknowledgements

- Blocklist maintainers listed in the configuration file
- [Pi-hole](https://pi-hole.net/) team
