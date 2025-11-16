# Pi-hole Blocklist Optimizer

<div align="center">

![GitHub release (latest by date)](https://img.shields.io/github/v/release/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![GitHub](https://img.shields.io/github/license/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)
![Stars](https://img.shields.io/github/stars/zachlagden/Pi-hole-Blocklist-Optimizer?style=flat-square)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg?style=flat-square)](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer/graphs/commit-activity)

**A powerful Python tool that downloads, optimizes, and organizes blocklists for [Pi-hole](https://pi-hole.net/) with automatic deduplication, whitelist support, and intelligent cleanup**

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Configuration](#%EF%B8%8F-configuration) •
[Usage](#%EF%B8%8F-usage) •
[Documentation](#-documentation) •
[License](#-license)

</div>

---

## 🎯 What Does This Tool Do?

Pi-hole Blocklist Optimizer streamlines your Pi-hole DNS filtering by automating the entire blocklist management process:

1. **Downloads** blocklists from multiple sources (50+ curated lists available)
2. **Optimizes** by removing duplicates, validating domains, and filtering invalid entries
3. **Whitelists** false positives using custom whitelist sources (remote or local)
4. **Organizes** into logical categories (advertising, tracking, malicious, suspicious, NSFW)
5. **Produces** clean, production-ready blocklists for immediate Pi-hole deployment
6. **Cleans up** temporary files automatically, leaving only optimized outputs

**The goal:** Transform dozens of blocklists from various sources into optimized, deduplicated, production-ready files with minimal manual intervention.

---

## ✨ Features

### Core Functionality
- **🔄 Multi-threaded Downloads** - Process 1-16 blocklists simultaneously for faster operation
- **🎯 Format Auto-Detection** - Automatically handles hosts files, AdBlock syntax, and plain domain lists
- **♻️ Smart Deduplication** - Removes duplicates across all lists while preserving unique domains
- **✅ Domain Validation** - Filters out invalid entries, ensures RFC-compliant domains
- **🗂️ Category Organization** - Groups domains by threat type for granular control

### Advanced Features
- **⚪ Whitelist Support** - Remove false positives using remote URLs or local file sources
- **🧹 Automatic Cleanup** - Temporary files deleted after processing (configurable)
- **📊 Detailed Statistics** - Comprehensive reports showing domains processed, removed, and categorized
- **🔧 Flexible Configuration** - External config files for easy blocklist and whitelist management
- **⚡ Performance Optimized** - Handles millions of domains efficiently with minimal memory usage
- **🛡️ Error Recovery** - Failed downloads auto-disabled in config, processing continues

### Output Quality
- **Production-Ready Lists** - Formatted for immediate Pi-hole import
- **Metadata Preservation** - Retains valuable comments, version info, and timestamps when available
- **Multiple Formats** - Master list plus category-specific lists for granular blocking
- **Detailed Reporting** - JSON and text statistics with whitelist impact analysis

---

## 💻 System Requirements

- **Python:** 3.6 or higher
- **Dependencies:**
  - `requests` - HTTP client for downloading blocklists
  - `tqdm` - Progress bar visualization
- **Platform:** Linux, macOS, or Windows
- **Storage:** ~100MB for temporary files during processing (auto-cleaned)

---

## 📥 Installation

### Quick Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer
   cd Pi-hole-Blocklist-Optimizer
   ```

2. **Install dependencies:**
   ```bash
   pip install requests tqdm
   ```

3. **You're ready to go!**
   ```bash
   python3 blocklist-optimizer.py --help
   ```

### Virtual Environment (Recommended)

For isolated dependency management:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install dependencies
pip install requests tqdm
```

---

## 🚀 Quick Start

### Basic Usage

1. **Edit configuration files** to select your blocklists:
   ```bash
   nano blocklists.conf    # Uncomment blocklists you want
   nano whitelists.conf    # Optional: add whitelists
   ```

2. **Run the optimizer:**
   ```bash
   python3 blocklist-optimizer.py
   ```

3. **Use the production files** from `pihole_blocklists_prod/`:
   - `all_domains.txt` - Master list with all unique domains
   - `advertising.txt`, `tracking.txt`, `malicious.txt`, etc. - Category-specific lists

### What Happens During Processing

```
1. Load Configuration
   ├── Read blocklists.conf
   └── Read whitelists.conf (if present)

2. Download Phase
   ├── Create temp/ directory
   ├── Download blocklists in parallel (default: 4 threads)
   └── Save raw files to temp/

3. Optimization Phase
   ├── Detect and parse various formats
   ├── Extract and validate domains
   ├── Remove duplicates per list
   └── Store optimized files in temp/

4. Whitelist Phase (optional)
   ├── Download/read whitelist sources
   ├── Parse whitelist domains
   └── Remove whitelisted domains from blocklists

5. Production Phase
   ├── Combine all domains
   ├── Deduplicate across all lists
   ├── Create category-specific lists
   ├── Generate master list
   └── Save to pihole_blocklists_prod/

6. Cleanup Phase
   ├── Generate statistics reports
   ├── Delete temp/ directory (unless --skip-delete)
   └── Display summary
```

---

## ⚙️ Configuration

### Blocklist Configuration (`blocklists.conf`)

Define which blocklists to download and optimize.

**Format:**
```
url|name|category
```

**Example:**
```
https://adaway.org/hosts.txt|adaway|advertising
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|stevenblack|comprehensive
https://v.firebog.net/hosts/Prigent-Malware.txt|prigent_malware|malicious
```

**Supported Categories:**
- `comprehensive` - Multi-category curated lists
- `advertising` - Ad networks and ad servers
- `tracking` - Analytics, telemetry, user tracking
- `malicious` - Malware, phishing, ransomware, security threats
- `suspicious` - Spam, scams, potentially unwanted content
- `nsfw` - Adult content
- `custom` - Create your own categories

**Notes:**
- Lines starting with `#` are ignored (comments)
- Failed downloads are auto-disabled with `#DISABLED:` prefix
- Uncomment example entries in the config file to enable them
- Add your own sources with custom category names

### Whitelist Configuration (`whitelists.conf`)

Define whitelists to remove false positives from your blocklists.

**Format:**
```
url_or_file_path|name|whitelist
```

**Remote URL Example:**
```
https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt|anudeep_whitelist|whitelist
```

**Local File Examples:**
```
# Absolute path
file:///root/my-custom-whitelist.txt|custom_whitelist|whitelist

# Relative path (relative to script directory)
file://./my-whitelist.txt|local_whitelist|whitelist
```

**Supported Formats:**
- Plain domain lists (one domain per line)
- Hosts file format (`0.0.0.0 domain` or `127.0.0.1 domain`)
- AdBlock Plus format (`||domain^`)
- Comments (lines starting with `#`) are ignored

**How Whitelisting Works:**
1. Whitelists are processed **after** all blocklists are downloaded
2. Domains found in whitelists are **removed** from all blocklists
3. Whitelist impact is tracked per category in statistics
4. A report file (`whitelisted_domains.txt`) lists all removed domains

**Notes:**
- Whitelists are **optional** - script works fine without them
- Domains are matched case-insensitively
- Exact domain matches only (wildcards not supported)
- Use `--skip-whitelist` flag to disable temporarily

---

## 🛠️ Usage

### Basic Command

```bash
python3 blocklist-optimizer.py
```

This runs with default settings:
- Reads `blocklists.conf` and `whitelists.conf`
- Downloads to `temp/` directory
- Saves production files to `pihole_blocklists_prod/`
- Uses 4 download threads
- Cleans up temp files after processing

### Common Usage Examples

**With custom configuration:**
```bash
python3 blocklist-optimizer.py --config my-blocklists.conf
```

**Faster downloads (more threads):**
```bash
python3 blocklist-optimizer.py --threads 8
```

**Keep temporary files for debugging:**
```bash
python3 blocklist-optimizer.py --skip-delete
```

**Skip whitelist processing:**
```bash
python3 blocklist-optimizer.py --skip-whitelist
```

**Use existing downloads (don't re-download):**
```bash
python3 blocklist-optimizer.py --skip-download
```

**Verbose logging for troubleshooting:**
```bash
python3 blocklist-optimizer.py --verbose
```

**Quiet mode (errors only):**
```bash
python3 blocklist-optimizer.py --quiet
```

### Complete CLI Reference

```
usage: blocklist-optimizer.py [-h] [-c CONFIG] [--temp-dir TEMP_DIR]
                               [-p PROD_DIR] [-t THREADS] [--skip-download]
                               [--skip-optimize] [--skip-delete]
                               [--whitelist-config WHITELIST_CONFIG]
                               [--skip-whitelist] [-v] [-q] [--version]

Pi-hole Blocklist Optimizer

options:
  -h, --help            Show this help message and exit
  -c CONFIG, --config CONFIG
                        Blocklist configuration file (default: blocklists.conf)
  --temp-dir TEMP_DIR   Temporary directory for processing (default: temp)
  -p PROD_DIR, --prod-dir PROD_DIR
                        Production output directory (default: pihole_blocklists_prod)
  -t THREADS, --threads THREADS
                        Number of download threads, 1-16 (default: 4)
  --skip-download       Skip downloading, use existing files in temp/
  --skip-optimize       Download only, skip optimization
  --skip-delete         Keep temporary files after processing
  --whitelist-config WHITELIST_CONFIG
                        Whitelist configuration file (default: whitelists.conf)
  --skip-whitelist      Skip whitelist processing even if configured
  -v, --verbose         Enable verbose logging for troubleshooting
  -q, --quiet           Suppress output except errors
  --version             Show program version and exit
```

---

## 📁 Output Directory Structure

```
temp/                           # Temporary directory (auto-deleted unless --skip-delete)
├── advertising/                # Individual advertising blocklists
├── tracking/                   # Individual tracking blocklists
├── malicious/                  # Individual malicious blocklists
├── suspicious/                 # Individual suspicious blocklists
├── nsfw/                       # Individual NSFW blocklists
├── comprehensive/              # Individual comprehensive blocklists
└── pihole_downloader.log       # Processing log file

pihole_blocklists_prod/         # Production directory (permanent)
├── all_domains.txt             # ⭐ Master list - all unique domains
├── advertising.txt             # Combined advertising domains
├── tracking.txt                # Combined tracking domains
├── malicious.txt               # Combined malicious domains
├── suspicious.txt              # Combined suspicious domains
├── nsfw.txt                    # Combined NSFW domains
├── comprehensive.txt           # Combined comprehensive domains
├── whitelisted_domains.txt     # Report of domains removed by whitelist
├── blocklist_stats.txt         # Detailed human-readable statistics
├── blocklist_stats.json        # Statistics in JSON format
├── _production_lists.txt       # Index of production files
└── _production_stats.json      # Production metadata in JSON
```

### Files You'll Use

**For Pi-hole:**
- `all_domains.txt` - Import as a single comprehensive blocklist
- `advertising.txt`, `tracking.txt`, etc. - Import category-specific lists for granular control

**For Analysis:**
- `blocklist_stats.txt` - Human-readable processing report
- `whitelisted_domains.txt` - Review what was whitelisted
- `blocklist_stats.json` - Machine-parseable statistics

---

## 🔄 Pi-hole Integration

The production files in `pihole_blocklists_prod/` are ready for immediate Pi-hole import.

### Option 1: Remote Import (Recommended)

1. **Host the files** on a web server or GitHub:
   ```bash
   # Example: Push to GitHub and use raw URLs
   git add pihole_blocklists_prod/
   git commit -m "Update blocklists"
   git push
   ```

2. **Add to Pi-hole** via web interface:
   - Go to **Adlists** in Pi-hole admin
   - Add URL: `https://raw.githubusercontent.com/yourusername/repo/main/pihole_blocklists_prod/all_domains.txt`
   - Update Gravity: `pihole -g`

### Option 2: Local Import

1. **Copy files to Pi-hole:**
   ```bash
   scp pihole_blocklists_prod/*.txt pi@your-pihole:/tmp/
   ```

2. **On Pi-hole device:**
   ```bash
   sudo cp /tmp/*.txt /etc/pihole/custom-lists/
   pihole -g
   ```

### Option 3: Manual Import

1. Open `pihole_blocklists_prod/all_domains.txt`
2. Copy domains
3. Paste into Pi-hole web interface under **Adlists** or **Blacklist**

### Which List Should I Use?

- **Most Users:** `all_domains.txt` - Single comprehensive list
- **Granular Control:** Import category-specific lists to enable/disable categories in Pi-hole
- **Selective Blocking:** Use individual category lists and toggle them as needed

---

## 📊 Performance & Statistics

### Typical Performance

**With 48 blocklists (default config examples):**
- **Processing Time:** 60-90 seconds on modern hardware
- **Total Domains:** ~6-8 million (with duplicates)
- **Unique Domains:** ~2-4 million (after deduplication)
- **Removed Duplicates:** ~50-60% reduction
- **Memory Usage:** ~1GB during processing
- **Disk Space:** ~100MB temp files (auto-cleaned), ~50MB production files

**Factors Affecting Performance:**
- Number of blocklists
- Download thread count (`--threads`)
- Internet connection speed
- System CPU and memory

### Statistics Reporting

After each run, detailed statistics are saved to `pihole_blocklists_prod/`:

**`blocklist_stats.txt`** includes:
- Total lists processed (successful/failed)
- Total and unique domain counts
- Duplicate domain statistics
- Domains per category
- Domains per individual list
- Whitelist impact (if applicable)
- Processing time and system info

**`blocklist_stats.json`** provides:
- Machine-parseable JSON format
- All statistics from text file
- Structured data for automation

**Example Statistics:**
```
Total Lists: 48
Successfully Downloaded: 48
Failed Downloads: 0
Total Domains (with duplicates): 6,234,891
Unique Domains: 3,142,556
Duplicate Domains: 3,092,335

Whitelist Statistics:
Total Whitelist Sources: 1
Total Whitelist Domains: 1,234
Domains Removed by Whitelist: 987
  Advertising: 423 domains
  Tracking: 312 domains
  Suspicious: 252 domains
```

---

## 🔧 Troubleshooting

### Common Issues

**Issue: "Configuration file not found"**
- **Solution:** Ensure `blocklists.conf` exists in the same directory as the script
- **Workaround:** Specify path with `--config /path/to/blocklists.conf`

**Issue: "No valid blocklists found"**
- **Solution:** Uncomment at least one blocklist entry in `blocklists.conf`
- **Check:** Lines must not start with `#` to be active

**Issue: Connection errors or timeouts**
- **Solution:** Check internet connection and firewall settings
- **Retry:** Some sources may be temporarily unavailable, run again later
- **Note:** Failed downloads are auto-disabled with `#DISABLED:` prefix

**Issue: Memory errors with large blocklists**
- **Solution:** Reduce number of lists or use fewer threads
- **Alternative:** Process categories separately with custom configs

**Issue: Permission denied errors**
- **Solution:** Ensure write permissions in script directory
- **Alternative:** Use `--temp-dir` and `--prod-dir` to specify different locations

**Issue: "Module not found" errors**
- **Solution:** Install dependencies: `pip install requests tqdm`
- **Alternative:** Use virtual environment (see Installation section)

### Getting Help

1. **Check logs:** Review `temp/pihole_downloader.log` (if `--skip-delete` used)
2. **Run verbose:** Use `--verbose` flag for detailed output
3. **Check stats:** Review `pihole_blocklists_prod/blocklist_stats.txt` for processing details
4. **Test individual list:** Create a minimal `blocklists.conf` with one entry to isolate issues

### Debug Mode

To keep all temporary files for inspection:
```bash
python3 blocklist-optimizer.py --skip-delete --verbose
```

This preserves:
- Raw downloaded files in `temp/`
- Individual optimized files
- Processing log file
- All intermediate data

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

1. **Add Blocklist Sources**
   - Submit PRs with new quality blocklist sources
   - Include source reputation and category justification

2. **Improve Documentation**
   - Fix typos, clarify instructions
   - Add examples and use cases
   - Translate documentation

3. **Report Issues**
   - Bug reports with reproducible steps
   - Feature requests with use cases
   - Performance issues with system details

4. **Code Improvements**
   - Performance optimizations
   - New features (discuss first in issues)
   - Bug fixes

### Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/Pi-hole-Blocklist-Optimizer
cd Pi-hole-Blocklist-Optimizer

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install requests tqdm

# Make your changes
# Test thoroughly

# Submit PR with clear description
```

### Code Guidelines

- Follow existing code style
- Add comments for complex logic
- Test with various blocklist sources
- Ensure backward compatibility
- Update documentation for new features

---

## 📚 Documentation

### Configuration Files

- **`blocklists.conf`** - Main blocklist configuration with 50+ examples
- **`whitelists.conf`** - Whitelist configuration with examples

### Output Files

- **`pihole_blocklists_prod/all_domains.txt`** - Master blocklist
- **`pihole_blocklists_prod/{category}.txt`** - Category-specific lists
- **`pihole_blocklists_prod/blocklist_stats.txt`** - Processing statistics

### Logs

- **`temp/pihole_downloader.log`** - Detailed processing log (if `--skip-delete`)

### Further Reading

- [Pi-hole Documentation](https://docs.pi-hole.net/)
- [RFC 1035 - Domain Names](https://www.rfc-editor.org/rfc/rfc1035)
- [AdBlock Plus Filter Syntax](https://help.eyeo.com/adblockplus/how-to-write-filters)

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 Zachariah Michael Lagden

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgements

### Blocklist Sources

This tool is designed to work with high-quality blocklist sources maintained by the community:

- **[Steven Black](https://github.com/StevenBlack/hosts)** - Comprehensive unified hosts
- **[Firebog](https://firebog.net/)** - Curated blocklist collection
- **[OISD](https://oisd.nl/)** - Internet's #1 domain blocklist
- **[AdAway](https://adaway.org/)** - Mobile ad blocking
- **[EasyList](https://easylist.to/)** - Filter lists for ad blocking
- **[URLhaus](https://urlhaus.abuse.ch/)** - Malware URL tracking
- **[Phishing Army](https://phishing.army/)** - Anti-phishing blocklist

And many more contributors to the blocklist community!

### Whitelist Sources

- **[Anudeep ND](https://github.com/anudeepND/whitelist)** - Commonly whitelisted domains

### Built With

- **Python** - Core language
- **Requests** - HTTP library for downloads
- **tqdm** - Progress bar visualization

---

## 📊 Project Stats

- **Language:** Python 3.6+
- **License:** MIT
- **Maintained:** Yes
- **Platform:** Linux, macOS, Windows
- **Status:** Active Development

---

<div align="center">

**[⬆ Back to Top](#pi-hole-blocklist-optimizer)**

Made with ❤️ for the Pi-hole community

</div>
