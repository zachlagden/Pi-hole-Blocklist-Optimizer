#!/usr/bin/env python3
"""
Pi-hole Blocklist Downloader and Optimizer v2.0

Downloads, optimizes, and organizes Pi-hole blocklists into categorized folders.

Features:
- Multi-threaded downloads using requests
- Domain validation and normalization
- Whitelist support (exact, wildcard, regex)
- Incremental updates with ETags
- Progress tracking
"""

import os
import sys
import re
import time
import json
import logging
import argparse
import platform
import functools
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Try to import tqdm for progress bars
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kwargs):
        return iterable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pihole_downloader.log')
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_CONFIG_FILE = "blocklists.conf"
DEFAULT_WHITELIST_FILE = "whitelist.txt"
PROGRESS_FILE = "download_progress.json"

BASE_DIR = "pihole_blocklists"
PROD_DIR = "pihole_blocklists_prod"

MIN_THREADS = 1
MAX_THREADS = 16
DEFAULT_THREADS = 4
DEFAULT_TIMEOUT = 30

MAX_RETRIES = 3
RETRY_BACKOFF = 0.5
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

MAX_DOMAIN_LENGTH = 253
FORMAT_DETECTION_LINES = 200

# Pre-compiled regex patterns
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
)
ADBLOCK_PATTERN = re.compile(r'^\|\|(.+?)\^(?:\$.*)?$')
IP_DOMAIN_PATTERN = re.compile(r'^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\S+)$')
COMMENT_PATTERN = re.compile(r'(#|!).*$')

METADATA_KEYWORDS = ['title:', 'last modified:', 'version:', 'blocked:', 'updated:', 'count:', 'description:']

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Blocklist:
    """Represents a single blocklist source."""
    url: str
    name: str
    category: str
    etag: Optional[str] = None
    last_modified: Optional[str] = None


@dataclass
class BlocklistStats:
    """Statistics for a processed blocklist."""
    category: str
    domains: Set[str]
    count: int


@dataclass
class FailedList:
    """Represents a failed blocklist download."""
    url: str
    name: str
    category: str
    error: str


@dataclass
class WhitelistMatch:
    """Represents a whitelist match."""
    pattern: str
    pattern_type: str
    matched_domains: List[str] = field(default_factory=list)


@dataclass
class Config:
    """Configuration for the blocklist manager."""
    config_file: str = DEFAULT_CONFIG_FILE
    whitelist_file: str = DEFAULT_WHITELIST_FILE
    base_dir: str = BASE_DIR
    prod_dir: str = PROD_DIR
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    skip_download: bool = False
    skip_optimize: bool = False
    incremental: bool = True
    dry_run: bool = False
    quiet: bool = False
    verbose: bool = False
    whitelist_subdomain: bool = True
    whitelist_report: bool = False

    def __post_init__(self):
        self.threads = max(MIN_THREADS, min(self.threads, MAX_THREADS))
        if self.timeout <= 0:
            self.timeout = DEFAULT_TIMEOUT


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

@functools.lru_cache(maxsize=10000)
def validate_domain(domain: str) -> bool:
    """Validate a domain name."""
    if not domain or domain == 'localhost' or domain.endswith('.local'):
        return False
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False
    check_domain = domain[2:] if domain.startswith('*.') else domain
    return bool(DOMAIN_PATTERN.match(check_domain))


def normalize_domain(domain: str) -> str:
    """Normalize domain to lowercase."""
    return domain.lower().rstrip('.')


def extract_domain_from_line(line: str) -> Optional[str]:
    """Extract domain from various blocklist formats."""
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('!'):
        return None

    # Remove inline comments
    line = COMMENT_PATTERN.sub('', line).strip()
    if not line:
        return None

    # Try IP-domain format (0.0.0.0 domain.com)
    match = IP_DOMAIN_PATTERN.match(line)
    if match:
        return match.group(1)

    # Try AdBlock format (||domain.com^)
    match = ADBLOCK_PATTERN.match(line)
    if match:
        return match.group(1)

    # Plain domain format
    if ' ' not in line and '/' not in line and '?' not in line:
        return line

    return None


# ============================================================================
# HTTP CLIENT
# ============================================================================

class HTTPClient:
    """HTTP client with retry logic."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic."""
        session = requests.Session()
        retry = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def download(self, url: str, etag: Optional[str] = None,
                 last_modified: Optional[str] = None) -> Tuple[Optional[bytes], Optional[str], Optional[str], bool]:
        """
        Download content with conditional request support.

        Returns:
            Tuple of (content, new_etag, new_last_modified, was_modified)
        """
        headers = {'User-Agent': 'Pi-hole Blocklist Downloader/2.0'}
        if etag:
            headers['If-None-Match'] = etag
        if last_modified:
            headers['If-Modified-Since'] = last_modified

        response = self.session.get(url, headers=headers, timeout=self.timeout)

        # 304 Not Modified
        if response.status_code == 304:
            return None, etag, last_modified, False

        response.raise_for_status()

        new_etag = response.headers.get('ETag')
        new_last_modified = response.headers.get('Last-Modified')

        return response.content, new_etag, new_last_modified, True


# ============================================================================
# WHITELIST MANAGER
# ============================================================================

class WhitelistManager:
    """Manages domain whitelisting with exact, wildcard, and regex matching.

    Optimized for large domain sets using:
    - Set lookups for exact matches (O(1))
    - Suffix extraction for subdomain matching (O(k) where k = domain parts)
    - Combined regex for patterns (single pass)
    """

    def __init__(self, whitelist_file: str = DEFAULT_WHITELIST_FILE,
                 enable_subdomain_matching: bool = True):
        self.whitelist_file = whitelist_file
        self.enable_subdomain_matching = enable_subdomain_matching

        self.exact_domains: Set[str] = set()
        self.wildcard_patterns: List[Tuple[str, re.Pattern]] = []  # Pre-compiled
        self.regex_patterns: List[Tuple[str, re.Pattern]] = []
        self.combined_pattern: Optional[re.Pattern] = None  # Single combined regex
        self.match_stats: Dict[str, WhitelistMatch] = {}

        self.load()

    def load(self) -> None:
        """Load whitelist from file."""
        if not os.path.exists(self.whitelist_file):
            logger.debug(f"Whitelist file not found: {self.whitelist_file}")
            return

        try:
            exact_count = wildcard_count = regex_count = 0
            all_patterns = []  # For combined regex

            with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if '#' in line:
                        line = line[:line.index('#')]
                    line = line.strip()

                    if not line:
                        continue

                    # Regex pattern
                    if line.startswith('/') and line.endswith('/'):
                        pattern = line[1:-1]
                        try:
                            compiled = re.compile(pattern)
                            self.regex_patterns.append((line, compiled))
                            self.match_stats[line] = WhitelistMatch(pattern=line, pattern_type='regex')
                            all_patterns.append(f'(?:{pattern})')
                            regex_count += 1
                        except re.error as e:
                            logger.warning(f"Invalid regex pattern on line {line_num}: {pattern} - {e}")
                        continue

                    # Wildcard pattern - pre-compile
                    if '*' in line:
                        regex_pattern = line.replace('.', r'\.').replace('*', '.*')
                        regex_pattern = f'^{regex_pattern}$'
                        try:
                            compiled = re.compile(regex_pattern)
                            self.wildcard_patterns.append((line, compiled))
                            self.match_stats[line] = WhitelistMatch(pattern=line, pattern_type='wildcard')
                            all_patterns.append(f'(?:{regex_pattern})')
                            wildcard_count += 1
                        except re.error as e:
                            logger.warning(f"Invalid wildcard pattern on line {line_num}: {line} - {e}")
                        continue

                    # Exact domain
                    domain = normalize_domain(line)
                    if validate_domain(domain):
                        self.exact_domains.add(domain)
                        self.match_stats[domain] = WhitelistMatch(pattern=domain, pattern_type='exact')
                        exact_count += 1

            # Build combined regex for wildcard/regex patterns (much faster than checking each)
            if all_patterns:
                try:
                    self.combined_pattern = re.compile('|'.join(all_patterns))
                except re.error:
                    logger.warning("Failed to compile combined pattern, falling back to individual checks")
                    self.combined_pattern = None

            total = exact_count + wildcard_count + regex_count
            if total > 0:
                logger.info(f"Loaded {total} whitelist entries: {exact_count} exact, "
                           f"{wildcard_count} wildcard, {regex_count} regex")

        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")

    def _check_subdomain(self, domain: str) -> Optional[str]:
        """Check if domain is a subdomain of any whitelisted domain.

        Efficient O(k) algorithm where k = number of domain parts.
        Instead of checking all whitelist entries, extract all possible
        parent domains and check if any exist in the set.
        """
        parts = domain.split('.')
        # Check each possible parent domain
        # e.g., for "sub.example.com" check "example.com" and "com"
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.exact_domains:
                return parent
        return None

    def filter_domains(self, domains: Set[str], track_stats: bool = True) -> Tuple[Set[str], int]:
        """Filter out whitelisted domains - optimized for large sets."""
        if not (self.exact_domains or self.wildcard_patterns or self.regex_patterns):
            return domains, 0

        # Fast path: exact match removal (set difference is O(min(n,m)))
        # First remove exact matches
        remaining = domains - self.exact_domains
        removed_exact = len(domains) - len(remaining)

        if track_stats and removed_exact > 0:
            for domain in domains & self.exact_domains:
                if domain in self.match_stats:
                    self.match_stats[domain].matched_domains.append(domain)

        # If no other patterns and no subdomain matching, we're done
        if not self.enable_subdomain_matching and not self.wildcard_patterns and not self.regex_patterns:
            if removed_exact > 0:
                logger.info(f"Filtered {removed_exact} whitelisted domains")
            return remaining, removed_exact

        # Process remaining domains for subdomain/wildcard/regex matches
        filtered = set()
        removed_count = removed_exact

        # Check if we have patterns to match against
        has_patterns = bool(self.wildcard_patterns or self.regex_patterns)

        for domain in remaining:
            matched = False
            matched_pattern = None
            match_type = None

            # Subdomain matching - O(k) per domain
            if self.enable_subdomain_matching:
                parent = self._check_subdomain(domain)
                if parent:
                    matched = True
                    matched_pattern = parent
                    match_type = 'subdomain'

            # Wildcard/regex matching - use combined pattern for speed
            if not matched and has_patterns:
                if self.combined_pattern and self.combined_pattern.match(domain):
                    matched = True
                    # Find which pattern matched (only if tracking stats)
                    if track_stats:
                        for pattern_str, compiled in self.wildcard_patterns:
                            if compiled.match(domain):
                                matched_pattern = pattern_str
                                match_type = 'wildcard'
                                break
                        if not matched_pattern:
                            for pattern_str, compiled in self.regex_patterns:
                                if compiled.match(domain):
                                    matched_pattern = pattern_str
                                    match_type = 'regex'
                                    break

            if matched:
                removed_count += 1
                if track_stats and matched_pattern and matched_pattern in self.match_stats:
                    self.match_stats[matched_pattern].matched_domains.append(domain)
            else:
                filtered.add(domain)

        if removed_count > 0:
            logger.info(f"Filtered {removed_count:,} whitelisted domains")

        return filtered, removed_count

    def generate_report(self, output_file: str) -> None:
        """Generate detailed whitelist report."""
        try:
            sorted_matches = sorted(
                self.match_stats.items(),
                key=lambda x: len(x[1].matched_domains),
                reverse=True
            )

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("Whitelist Report\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                total_matches = sum(len(m.matched_domains) for _, m in sorted_matches)
                f.write(f"Total Domains Removed: {total_matches}\n\n")

                for pattern, match_info in sorted_matches:
                    if match_info.matched_domains:
                        f.write(f"Pattern: {pattern} ({match_info.pattern_type})\n")
                        f.write(f"Matches: {len(match_info.matched_domains)}\n")
                        for domain in match_info.matched_domains[:50]:
                            f.write(f"  - {domain}\n")
                        if len(match_info.matched_domains) > 50:
                            f.write(f"  ... and {len(match_info.matched_domains) - 50} more\n")
                        f.write("\n")

            logger.info(f"Whitelist report saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate whitelist report: {e}")


# ============================================================================
# PROGRESS TRACKER
# ============================================================================

class ProgressTracker:
    """Tracks and persists download progress."""

    def __init__(self, progress_file: str = PROGRESS_FILE):
        self.progress_file = progress_file
        self.progress: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Load progress from file."""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r', encoding='utf-8') as f:
                    self.progress = json.load(f)
                logger.debug(f"Loaded progress for {len(self.progress)} lists")
            except Exception as e:
                logger.warning(f"Failed to load progress file: {e}")
                self.progress = {}

    def save(self) -> None:
        """Save progress to file."""
        try:
            with open(self.progress_file, 'w', encoding='utf-8') as f:
                json.dump(self.progress, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save progress file: {e}")

    def get_blocklist_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get cached info for a blocklist."""
        return self.progress.get(name)

    def update_blocklist(self, name: str, etag: Optional[str] = None,
                        last_modified: Optional[str] = None,
                        domain_count: int = 0) -> None:
        """Update progress for a blocklist."""
        self.progress[name] = {
            'etag': etag,
            'last_modified': last_modified,
            'domain_count': domain_count,
            'last_download': datetime.now().isoformat()
        }
        self.save()


# ============================================================================
# BLOCKLIST MANAGER
# ============================================================================

class BlocklistManager:
    """Main orchestrator for blocklist downloads and optimization."""

    def __init__(self, config: Config):
        self.config = config
        self.blocklists: List[Blocklist] = []
        self.categories: Set[str] = set()
        self.domain_stats: Dict[str, BlocklistStats] = {}
        self.failed_lists: List[FailedList] = []

        self.http_client = HTTPClient(timeout=config.timeout)
        self.progress_tracker = ProgressTracker()
        self.whitelist_manager = WhitelistManager(config.whitelist_file, config.whitelist_subdomain)

        self.stats: Dict[str, Any] = {
            'total_lists': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'total_domains': 0,
            'unique_domains': 0,
            'whitelisted_domains': 0,
            'categories': {},
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

    def load_config(self) -> None:
        """Load blocklist configuration from file."""
        if not os.path.exists(self.config.config_file):
            logger.error(f"Configuration file '{self.config.config_file}' not found.")
            sys.exit(1)

        logger.info(f"Loading configuration from {self.config.config_file}")

        try:
            with open(self.config.config_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    if not line or line.startswith('#'):
                        continue

                    try:
                        parts = line.split('|')
                        if len(parts) != 3:
                            logger.warning(f"Invalid format in line {line_num}: {line}")
                            continue

                        url, name, category = [p.strip() for p in parts]

                        # Validate URL
                        result = urlparse(url)
                        if not all([result.scheme, result.netloc]):
                            logger.warning(f"Invalid URL in line {line_num}: {url}")
                            continue

                        # Get cached info
                        cached_info = self.progress_tracker.get_blocklist_info(name)
                        etag = cached_info.get('etag') if cached_info else None
                        last_modified = cached_info.get('last_modified') if cached_info else None

                        blocklist = Blocklist(
                            url=url,
                            name=name,
                            category=category,
                            etag=etag,
                            last_modified=last_modified
                        )

                        self.blocklists.append(blocklist)
                        self.categories.add(category)

                    except Exception as e:
                        logger.warning(f"Error parsing line {line_num}: {e}")

            self.stats['total_lists'] = len(self.blocklists)
            if self.stats['total_lists'] == 0:
                logger.error("No valid blocklists found in configuration file.")
                sys.exit(1)

            logger.info(f"Loaded {self.stats['total_lists']} blocklists in {len(self.categories)} categories")

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)

    def create_directories(self) -> None:
        """Create the necessary directory structure."""
        if self.config.dry_run:
            logger.info("[DRY RUN] Would create directories")
            return

        os.makedirs(self.config.base_dir, exist_ok=True)
        for category in self.categories:
            os.makedirs(os.path.join(self.config.base_dir, category), exist_ok=True)
        os.makedirs(self.config.prod_dir, exist_ok=True)

    def process_blocklist_content(self, content: bytes, name: str) -> Set[str]:
        """Process blocklist content to extract domains."""
        try:
            text = content.decode('utf-8', errors='ignore')
            lines = text.splitlines()
            domains: Set[str] = set()

            for line in lines:
                domain = extract_domain_from_line(line)
                if domain and validate_domain(domain):
                    domains.add(normalize_domain(domain))

            return domains

        except Exception as e:
            logger.error(f"Error processing {name}: {e}")
            return set()

    def download_blocklist(self, blocklist: Blocklist) -> Tuple[str, bool, Optional[Set[str]], Dict[str, Any]]:
        """Download and process a single blocklist."""
        try:
            content, new_etag, new_last_modified, was_modified = self.http_client.download(
                blocklist.url,
                blocklist.etag if self.config.incremental else None,
                blocklist.last_modified if self.config.incremental else None
            )

            if not was_modified:
                return blocklist.name, True, None, {'skipped': True}

            # Process content
            domains = self.process_blocklist_content(content, blocklist.name)

            return blocklist.name, True, domains, {
                'content': content,
                'etag': new_etag,
                'last_modified': new_last_modified,
                'category': blocklist.category
            }

        except Exception as e:
            logger.error(f"Error downloading {blocklist.name}: {e}")
            return blocklist.name, False, None, {'error': str(e)}

    def download_all_blocklists(self) -> None:
        """Download all blocklists using thread pool."""
        if self.config.dry_run or self.config.skip_download:
            return

        logger.info(f"Downloading {len(self.blocklists)} blocklists with {self.config.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self.download_blocklist, bl): bl for bl in self.blocklists}

            if HAS_TQDM:
                futures_iter = tqdm(as_completed(futures), total=len(futures), desc="Downloading")
            else:
                futures_iter = as_completed(futures)

            for future in futures_iter:
                blocklist = futures[future]
                try:
                    name, success, domains, metadata = future.result()

                    if not success:
                        self.stats['failed'] += 1
                        self.failed_lists.append(FailedList(
                            url=blocklist.url,
                            name=blocklist.name,
                            category=blocklist.category,
                            error=metadata.get('error', 'Unknown error')
                        ))
                        continue

                    if metadata.get('skipped'):
                        self.stats['skipped'] += 1
                        logger.info(f"  {name}: No changes (skipped)")
                        continue

                    # Save files
                    category = metadata['category']
                    destination = os.path.join(self.config.base_dir, category, f"{name}.txt")

                    # Save raw file
                    with open(destination + '.raw', 'wb') as f:
                        f.write(metadata['content'])

                    # Save optimized file
                    with open(destination, 'w', encoding='utf-8') as f:
                        f.write(f"# Pi-hole optimized blocklist\n")
                        f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"# Total domains: {len(domains)}\n\n")
                        for domain in sorted(domains):
                            f.write(f"0.0.0.0 {domain}\n")

                    # Update stats
                    self.stats['successful'] += 1
                    self.stats['total_domains'] += len(domains)

                    if category not in self.stats['categories']:
                        self.stats['categories'][category] = {'lists': 0, 'domains': 0}
                    self.stats['categories'][category]['lists'] += 1
                    self.stats['categories'][category]['domains'] += len(domains)

                    self.domain_stats[name] = BlocklistStats(
                        category=category,
                        domains=domains,
                        count=len(domains)
                    )

                    # Update progress
                    self.progress_tracker.update_blocklist(
                        name,
                        metadata.get('etag'),
                        metadata.get('last_modified'),
                        len(domains)
                    )

                    logger.info(f"  {name}: {len(domains):,} domains")

                except Exception as e:
                    logger.error(f"Error processing {blocklist.name}: {e}")
                    self.stats['failed'] += 1

    def create_production_lists(self) -> None:
        """Create optimized production blocklists with whitelist filtering."""
        if self.config.dry_run:
            return

        logger.info("Creating production blocklists...")

        all_domains: Set[str] = set()
        category_domains: Dict[str, Set[str]] = {category: set() for category in self.categories}

        for name, stats in self.domain_stats.items():
            # NSFW category is kept separate and not included in all_domains
            if stats.category != 'nsfw':
                all_domains.update(stats.domains)
            category_domains[stats.category].update(stats.domains)

        self.stats['unique_domains'] = len(all_domains)

        # Apply whitelist filtering
        logger.info("Applying whitelist filtering...")
        all_domains_filtered, removed = self.whitelist_manager.filter_domains(all_domains)
        self.stats['whitelisted_domains'] = removed
        self.stats['unique_domains_after_whitelist'] = len(all_domains_filtered)

        # Create master file
        self._write_production_file(
            os.path.join(self.config.prod_dir, "all_domains.txt"),
            all_domains_filtered,
            "Master"
        )

        # Create category files
        for category, domains in category_domains.items():
            if domains:
                filtered, _ = self.whitelist_manager.filter_domains(domains, track_stats=False)
                self._write_production_file(
                    os.path.join(self.config.prod_dir, f"{category}.txt"),
                    filtered,
                    category.capitalize()
                )

        # Generate whitelist report
        if self.config.whitelist_report and removed > 0:
            self.whitelist_manager.generate_report(
                os.path.join(self.config.prod_dir, "whitelist_report.txt")
            )

    def _write_production_file(self, filepath: str, domains: Set[str], label: str) -> None:
        """Write a production blocklist file."""
        sorted_domains = sorted(domains)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Pi-hole {label} Blocklist\n")
            f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(sorted_domains)}\n\n")
            for domain in sorted_domains:
                f.write(f"0.0.0.0 {domain}\n")
        logger.info(f"Created {label} blocklist: {len(sorted_domains):,} domains")

    def run(self) -> Dict[str, Any]:
        """Run the blocklist downloader pipeline."""
        start_time = time.time()

        self.load_config()
        self.create_directories()

        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would process {len(self.blocklists)} blocklists")
            self.stats['elapsed_time'] = "0.00 seconds (dry run)"
            return self.stats

        # Download and process
        self.download_all_blocklists()

        # Create production lists
        if not self.config.skip_optimize:
            self.create_production_lists()

        elapsed_time = time.time() - start_time
        self.stats['elapsed_time'] = f"{elapsed_time:.2f} seconds"

        return self.stats


# ============================================================================
# CLI
# ============================================================================

def parse_arguments() -> Config:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Pi-hole Blocklist Downloader v2.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE,
                        help="Configuration file")
    parser.add_argument("-w", "--whitelist", default=DEFAULT_WHITELIST_FILE,
                        help="Whitelist file")
    parser.add_argument("-b", "--base-dir", default=BASE_DIR,
                        help="Base directory")
    parser.add_argument("-p", "--prod-dir", default=PROD_DIR,
                        help="Production directory")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Download threads ({MIN_THREADS}-{MAX_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="HTTP timeout in seconds")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip downloading")
    parser.add_argument("--skip-optimize", action="store_true",
                        help="Skip optimization")
    parser.add_argument("--no-incremental", action="store_true",
                        help="Disable incremental updates")
    parser.add_argument("--dry-run", action="store_true",
                        help="Dry run mode")
    parser.add_argument("--no-whitelist-subdomain", action="store_true",
                        help="Disable subdomain matching")
    parser.add_argument("--whitelist-report", action="store_true",
                        help="Generate whitelist report")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode")
    parser.add_argument("--version", action="version", version="Pi-hole Blocklist Downloader v2.0")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)

    return Config(
        config_file=args.config,
        whitelist_file=args.whitelist,
        base_dir=args.base_dir,
        prod_dir=args.prod_dir,
        threads=args.threads,
        timeout=args.timeout,
        skip_download=args.skip_download,
        skip_optimize=args.skip_optimize,
        incremental=not args.no_incremental,
        dry_run=args.dry_run,
        quiet=args.quiet,
        verbose=args.verbose,
        whitelist_subdomain=not args.no_whitelist_subdomain,
        whitelist_report=args.whitelist_report
    )


def main() -> int:
    """Main function."""
    config = parse_arguments()

    if not config.quiet:
        print("\n" + "=" * 60)
        print(" " * 10 + "PI-HOLE BLOCKLIST DOWNLOADER v2.0")
        print("=" * 60 + "\n")

    manager = BlocklistManager(config)

    try:
        stats = manager.run()

        if not config.quiet:
            print("\n" + "=" * 60)
            print(" " * 25 + "SUMMARY")
            print("=" * 60)
            print(f"Total lists:        {stats['total_lists']}")
            print(f"Successful:         {stats['successful']}")
            print(f"Skipped:            {stats['skipped']}")
            print(f"Failed:             {stats['failed']}")
            print(f"Unique domains:     {stats['unique_domains']:,}")
            if stats.get('whitelisted_domains', 0) > 0:
                print(f"Whitelisted:        {stats['whitelisted_domains']:,}")
                print(f"Final count:        {stats.get('unique_domains_after_whitelist', 0):,}")
            print(f"Runtime:            {stats.get('elapsed_time', 'N/A')}")
            print("=" * 60 + "\n")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
