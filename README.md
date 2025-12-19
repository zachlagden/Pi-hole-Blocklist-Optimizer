# Pi-hole Blocklist Downloader and Optimizer

<div align="center">

![GitHub release (latest by date)](https://img.shields.io/github/v/release/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![GitHub](https://img.shields.io/github/license/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)
![Stars](https://img.shields.io/github/stars/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)

**A powerful tool for downloading, optimizing, and organizing blocklists for [Pi-hole](https://pi-hole.net/)**

[Features](#features) •
[Installation](#installation) •
[Quick Start](#quick-start) •
[Whitelist](#whitelist-support) •
[Configuration](#configuration) •
[Usage](#usage)

</div>

## What Does This Tool Do?

1. **Downloads** blocklists from multiple sources (multi-threaded)
2. **Validates** domains and removes invalid entries
3. **Optimizes** by removing duplicates across all lists
4. **Filters** domains using your whitelist (exact, wildcard, regex)
5. **Organizes** into categories (advertising, tracking, malicious, etc.)
6. **Combines** into production-ready lists

## Features

- **Multi-threaded downloads** - Fast parallel downloading (configurable 1-16 threads)
- **Whitelist support** - Filter domains with exact matches, wildcards, or regex patterns
- **Incremental updates** - Only re-download changed lists (ETag/Last-Modified support)
- **Multi-format support** - Handles hosts, AdBlock, and plain domain formats
- **Progress tracking** - Resume interrupted downloads
- **Detailed reporting** - Statistics and whitelist match reports
- **Error recovery** - Automatic retry with exponential backoff

## Installation

### Requirements

- Python 3.8+
- `requests` and `tqdm` packages

### Setup

```bash
# Clone the repository
git clone https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer
cd Pi-hole-Blocklist-Optimizer

# Install dependencies
pip install requests tqdm
```

## Quick Start

```bash
python pihole_downloader.py
```

That's it! The script will:
1. Download blocklists from `blocklists.conf`
2. Validate and optimize domains
3. Apply whitelist filtering
4. Create production lists in `pihole_blocklists_prod/`

## Whitelist Support

Create a `whitelist.txt` file to exclude domains from the final output. Three matching types are supported:

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

Run with `--whitelist-report` to see which domains were filtered and by which patterns.

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

Categories: `advertising`, `tracking`, `malicious`, `suspicious`, `nsfw`, `comprehensive`

Lines starting with `#` are ignored. Failed lists are auto-commented with `#DISABLED:`.

## Usage

### Basic

```bash
python pihole_downloader.py
```

### With Options

```bash
# Fast download with 8 threads and whitelist report
python pihole_downloader.py -t 8 --whitelist-report

# Custom config and output directory
python pihole_downloader.py -c myconfig.conf -p /var/blocklists

# Verbose logging
python pihole_downloader.py -v
```

### All Options

```
usage: pihole_downloader.py [-h] [-c CONFIG] [-w WHITELIST] [-b BASE_DIR]
                            [-p PROD_DIR] [-t THREADS] [--timeout TIMEOUT]
                            [--skip-download] [--skip-optimize] [--no-incremental]
                            [--dry-run] [--no-whitelist-subdomain]
                            [--whitelist-report] [-v] [-q] [--version]

Options:
  -c, --config FILE         Configuration file (default: blocklists.conf)
  -w, --whitelist FILE      Whitelist file (default: whitelist.txt)
  -b, --base-dir DIR        Base directory for lists (default: pihole_blocklists)
  -p, --prod-dir DIR        Production directory (default: pihole_blocklists_prod)
  -t, --threads N           Download threads 1-16 (default: 4)
  --timeout SECONDS         HTTP timeout (default: 30)
  --skip-download           Skip downloading (use existing files)
  --skip-optimize           Skip optimization
  --no-incremental          Force re-download all lists
  --dry-run                 Show what would be done without doing it
  --no-whitelist-subdomain  Disable subdomain matching in whitelist
  --whitelist-report        Generate detailed whitelist match report
  -v, --verbose             Verbose logging
  -q, --quiet               Suppress output except errors
  --version                 Show version
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
├── nsfw.txt                    # Separate - not included in all_domains.txt
├── comprehensive.txt
└── whitelist_report.txt        # (if --whitelist-report used)
```

## Using with Pi-hole

### Option 1: Use Pre-built Lists (Recommended)

Use the companion repository [Pi-hole-Optimized-Blocklists](https://github.com/zachlagden/Pi-hole-Optimized-Blocklists) which runs this optimizer weekly and hosts the results.

Add these URLs to Pi-hole's Adlists:
```
https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt
```

### Option 2: Self-Host

Run the optimizer and host the files on your own server, then add the URLs to Pi-hole.

### Option 3: Local Files

```bash
sudo cp pihole_blocklists_prod/*.txt /etc/pihole/
pihole -g
```

## Performance

- Default config: ~50 blocklists, 6M+ unique domains
- Processing time: 60-120 seconds (depends on network and threads)
- Memory: ~500MB-1GB for full processing

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection errors | Check internet, try fewer threads (`-t 2`) |
| Memory errors | Process fewer lists or increase swap |
| Slow downloads | Increase threads (`-t 8`) |
| Missing domains | Check whitelist isn't too broad |

Check `pihole_downloader.log` for detailed error information.

## Contributing

Contributions welcome! Open an issue or submit a PR.

```bash
git clone https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer
cd Pi-hole-Blocklist-Optimizer
python -m venv venv
source venv/bin/activate
pip install requests tqdm
```

## License

This project is licensed under the MIT License - see the [LICENCE](LICENCE) file for details.

## Acknowledgements

- Blocklist maintainers listed in the configuration file
- [Pi-hole](https://pi-hole.net/) team
