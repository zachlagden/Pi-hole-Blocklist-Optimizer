#!/usr/bin/env python3
"""
Pi-hole Blocklist Downloader and Optimizer
Downloads, optimizes, and organizes Pi-hole blocklists into categorized folders
Reads blocklist configuration from an external file

Features:
- Multi-threaded downloads with progress tracking
- Smart format detection for various blocklist types
- Deduplication and optimization of domain lists
- Category-based organization with statistics
- Production-ready merged blocklists by category
"""

import os
import requests
from urllib.parse import urlparse
import time
import sys
import re
import ipaddress
from datetime import datetime
import argparse
import logging
import hashlib
import concurrent.futures
import platform
import json
import shutil
from tqdm import tqdm

# Configure logging (log file will be in temp directory)
# Create temp directory for logs if it doesn't exist
os.makedirs("temp", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('temp/pihole_downloader.log')
    ]
)
logger = logging.getLogger(__name__)

# Default configuration file
DEFAULT_CONFIG_FILE = "blocklists.conf"

# Default directories
TEMP_DIR = "temp"
PROD_DIR = "pihole_blocklists_prod"

# Define regular expressions for domain extraction
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
)
ADBLOCK_PATTERN = re.compile(r'^\|\|(.+?)\^(?:\$.*)?$')
IP_DOMAIN_PATTERN = re.compile(r'^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\S+)$')

class BlocklistManager:
    def __init__(self, config_file=DEFAULT_CONFIG_FILE, temp_dir=TEMP_DIR, prod_dir=PROD_DIR,
                 threads=4, skip_download=False, skip_optimize=False, quiet=False, verbose=False,
                 whitelist_config="whitelists.conf", skip_whitelist=False, skip_delete=False):
        self.config_file = config_file
        self.temp_dir = temp_dir
        self.prod_dir = prod_dir
        self.threads = max(1, min(threads, 16))  # Limit threads between 1 and 16
        self.skip_download = skip_download
        self.skip_optimize = skip_optimize
        self.quiet = quiet
        self.verbose = verbose
        self.whitelist_config = whitelist_config
        self.skip_whitelist = skip_whitelist
        self.skip_delete = skip_delete
        self.blocklists = []
        self.whitelists = []
        self.categories = set()
        self.domain_stats = {}
        self.whitelist_domains = set()
        self.failed_lists = []
        
        # Statistics
        self.stats = {
            'total_lists': 0,
            'successful': 0,
            'failed': 0,
            'total_domains': 0,
            'unique_domains': 0,
            'duplicate_domains': 0,
            'categories': {},
            'whitelist': {
                'total_whitelists': 0,
                'whitelist_domains': 0,
                'total_removed': 0,
                'removed_by_category': {},
            },
            'system_info': self._get_system_info(),
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    
    def _get_system_info(self):
        """Get system information for diagnostics."""
        return {
            'platform': platform.platform(),
            'python': platform.python_version(),
            'processor': platform.processor() or "Unknown",
            'machine': platform.machine(),
        }
    
    def load_config(self):
        """Load blocklist configuration from file."""
        if not os.path.exists(self.config_file):
            logger.error(f"Configuration file '{self.config_file}' not found.")
            sys.exit(1)
        
        logger.info(f"Loading configuration from {self.config_file}")
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        # Track if this is a disabled entry
                        if line.startswith('#DISABLED:'):
                            disabled_entry = line[10:].strip()
                            logger.debug(f"Skipping disabled entry: {disabled_entry}")
                        continue
                    
                    # Parse line
                    try:
                        parts = line.split('|')
                        if len(parts) != 3:
                            logger.warning(f"Invalid format in line {line_num}: {line}")
                            continue
                        
                        url, name, category = parts
                        url = url.strip()
                        name = name.strip()
                        category = category.strip()
                        
                        # Validate URL
                        try:
                            result = urlparse(url)
                            if not all([result.scheme, result.netloc]):
                                logger.warning(f"Invalid URL in line {line_num}: {url}")
                                continue
                        except Exception:
                            logger.warning(f"Invalid URL in line {line_num}: {url}")
                            continue
                        
                        self.blocklists.append({
                            'url': url,
                            'name': name,
                            'category': category,
                        })
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

    def load_whitelist_config(self):
        """Load whitelist configuration from file."""
        # Whitelist is optional, so don't error if file doesn't exist
        if not os.path.exists(self.whitelist_config):
            logger.info(f"No whitelist configuration file found at '{self.whitelist_config}' (optional)")
            return

        logger.info(f"Loading whitelist configuration from {self.whitelist_config}")
        try:
            with open(self.whitelist_config, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse line
                    try:
                        parts = line.split('|')
                        if len(parts) != 3:
                            logger.warning(f"Invalid format in whitelist line {line_num}: {line}")
                            continue

                        source, name, whitelist_marker = parts
                        source = source.strip()
                        name = name.strip()
                        whitelist_marker = whitelist_marker.strip()

                        # Verify the third field says 'whitelist'
                        if whitelist_marker.lower() != 'whitelist':
                            logger.warning(f"Invalid whitelist marker in line {line_num}: expected 'whitelist', got '{whitelist_marker}'")
                            continue

                        # Check if it's a local file (file://) or a URL
                        is_local_file = source.startswith('file://')

                        if is_local_file:
                            # Remove file:// prefix and validate the path
                            file_path = source[7:]  # Remove 'file://'

                            # Handle relative paths
                            if not os.path.isabs(file_path):
                                # Make it relative to the script directory
                                file_path = os.path.abspath(file_path)

                            if not os.path.exists(file_path):
                                logger.warning(f"Local whitelist file not found: {file_path}")
                                continue

                            self.whitelists.append({
                                'source': source,
                                'file_path': file_path,
                                'name': name,
                                'is_local': True,
                            })
                        else:
                            # Validate URL
                            try:
                                result = urlparse(source)
                                if not all([result.scheme, result.netloc]):
                                    logger.warning(f"Invalid URL in whitelist line {line_num}: {source}")
                                    continue
                            except Exception:
                                logger.warning(f"Invalid URL in whitelist line {line_num}: {source}")
                                continue

                            self.whitelists.append({
                                'source': source,
                                'url': source,
                                'name': name,
                                'is_local': False,
                            })
                    except Exception as e:
                        logger.warning(f"Error parsing whitelist line {line_num}: {e}")

            self.stats['whitelist']['total_whitelists'] = len(self.whitelists)
            if len(self.whitelists) > 0:
                logger.info(f"Loaded {len(self.whitelists)} whitelist source(s)")
            else:
                logger.info("No valid whitelist entries found (continuing without whitelist)")

        except Exception as e:
            logger.error(f"Failed to load whitelist configuration: {e}")
            # Don't exit - whitelist is optional
            logger.warning("Continuing without whitelist processing")

    def create_directories(self):
        """Create the necessary directory structure."""
        # Create temp directory
        os.makedirs(self.temp_dir, exist_ok=True)
        logger.info(f"Created temporary directory: {os.path.abspath(self.temp_dir)}")

        # Create category subdirectories in temp
        for category in self.categories:
            path = os.path.join(self.temp_dir, category)
            os.makedirs(path, exist_ok=True)
            logger.debug(f"Created temp category directory: {path}")

        # Create production directory
        os.makedirs(self.prod_dir, exist_ok=True)
        logger.info(f"Created production directory: {os.path.abspath(self.prod_dir)}")
    
    def is_valid_domain(self, domain):
        """Check if a domain is valid."""
        if not domain or domain == 'localhost' or domain.endswith('.local'):
            return False
        
        # Check length constraints
        if len(domain) > 253:
            return False
        
        # Handle wildcards (*.example.com) - extract the domain part after *
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Check for valid domain pattern
        return bool(DOMAIN_PATTERN.match(domain))
    
    def extract_domain_from_line(self, line):
        """Extract domain from various blocklist formats."""
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            return None
        
        # Remove inline comments
        line = re.sub(r'(#|!).*$', '', line).strip()
        if not line:
            return None
        
        # Format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
        ip_domain_match = IP_DOMAIN_PATTERN.match(line)
        if ip_domain_match:
            return ip_domain_match.group(1)
        
        # Format: ||domain.com^ (AdBlock Plus syntax)
        adblock_match = ADBLOCK_PATTERN.match(line)
        if adblock_match:
            return adblock_match.group(1)
        
        # Format: domain.com (plain domain)
        if ' ' not in line and '/' not in line and '?' not in line and '!' not in line and '#' not in line:
            # Check for wildcard domain (*.example.com)
            if line.startswith('*.'):
                return line
            
            # Straight domain
            return line
        
        return None
    
    def optimize_blocklist(self, content, preserve_metadata=True, preserve_grouping=True, preserve_format=False):
        """
        Optimize a blocklist for Pi-hole by:
        1. Removing invalid entries and duplicates
        2. Standardizing format (unless preserve_format=True)
        3. Preserving useful metadata and grouping if requested
        """
        try:
            # Decode content if it's bytes
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
                
            lines = content.splitlines()
            domains = set()  # Use a set to automatically remove duplicates
            
            # Keep track of original format for each domain
            domain_formats = {}
            
            # Extract metadata
            metadata = []
            current_group = None
            groups = {}
            
            # Detect if this is primarily an adblock-style list
            adblock_count = 0
            host_count = 0
            plain_count = 0
            total_lines = 0
            
            # First pass to analyze format
            for line in lines[:200]:  # Sample first 200 lines
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                
                total_lines += 1
                if ADBLOCK_PATTERN.match(line):
                    adblock_count += 1
                elif IP_DOMAIN_PATTERN.match(line):
                    host_count += 1
                elif ' ' not in line and '/' not in line:
                    plain_count += 1
            
            # Determine primary format
            adblock_style = False
            if total_lines > 0:
                if adblock_count / total_lines > 0.5:
                    adblock_style = True
                    preserve_format = True
                elif host_count / total_lines > 0.5:
                    preserve_format = True
            
            # Second pass to process content
            for line in lines:
                line = line.strip()
                
                # Handle metadata lines (comments)
                if line.startswith('#') or line.startswith('!'):
                    # Convert adblock ! comments to # for consistency
                    if line.startswith('!'):
                        line = '#' + line[1:]
                        
                    if preserve_metadata and (
                        any(keyword in line.lower() for keyword in 
                        ['title:', 'last modified:', 'version:', 'blocked:', 'updated:', 'count:', 'description:'])
                    ):
                        metadata.append(line)
                    
                    # Handle group labels
                    if preserve_grouping and (
                        (line.startswith('#[') and line.endswith(']')) or 
                        (line.startswith('# [') and line.endswith(']'))
                    ):
                        if line.startswith('# ['):
                            current_group = line[3:-1].strip()  # Extract group name
                        else:
                            current_group = line[2:-1].strip()  # Extract group name
                        groups[current_group] = []
                    continue
                
                # Skip empty lines
                if not line:
                    continue
                
                # Extract domain
                domain = self.extract_domain_from_line(line)
                
                # Validate and add the domain
                if domain and self.is_valid_domain(domain):
                    domains.add(domain)
                    
                    # Remember original format if preserving
                    if preserve_format:
                        domain_formats[domain] = line
                    
                    # If we're in a group, add domain to that group
                    if preserve_grouping and current_group:
                        groups[current_group].append(domain)
            
            # Create optimized content
            optimized_content = []
            
            # Add original metadata if available
            if preserve_metadata and metadata:
                optimized_content.extend(metadata)
            else:
                # Add our own metadata
                optimized_content.append(f"# Pi-hole optimized blocklist")
                optimized_content.append(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Add domain count
            optimized_content.append(f"# Total domains: {len(domains)}")
            optimized_content.append("")
            
            # If preserving groups and we found groups
            if preserve_grouping and groups:
                for group_name, group_domains in groups.items():
                    # Only include groups that have valid domains
                    valid_domains = [d for d in group_domains if d in domains]
                    if valid_domains:
                        optimized_content.append(f"#[{group_name}]")
                        for domain in sorted(valid_domains):
                            if preserve_format and domain in domain_formats:
                                optimized_content.append(domain_formats[domain])
                            else:
                                optimized_content.append(f"0.0.0.0 {domain}")
                        optimized_content.append("")
                
                # Find domains that aren't in any group
                all_grouped = set()
                for group_domains in groups.values():
                    all_grouped.update([d for d in group_domains if d in domains])
                
                ungrouped = domains - all_grouped
                if ungrouped:
                    optimized_content.append("#[ungrouped]")
                    for domain in sorted(ungrouped):
                        if preserve_format and domain in domain_formats:
                            optimized_content.append(domain_formats[domain])
                        else:
                            optimized_content.append(f"0.0.0.0 {domain}")
            else:
                # No groups, just add all domains sorted
                for domain in sorted(list(domains)):
                    if preserve_format and domain in domain_formats:
                        optimized_content.append(domain_formats[domain])
                    else:
                        if adblock_style:
                            optimized_content.append(f"||{domain}^")
                        else:
                            optimized_content.append(f"0.0.0.0 {domain}")
            
            return '\n'.join(optimized_content), domains
        except Exception as e:
            logger.error(f"Error optimizing blocklist: {e}")
            return "# Error processing blocklist", set()
    
    def process_blocklist(self, blocklist):
        """Process a single blocklist (download and optimize)."""
        url = blocklist['url']
        name = blocklist['name']
        category = blocklist['category']

        filename = f"{name}.txt"
        destination = os.path.join(self.temp_dir, category, filename)
        abs_destination = os.path.abspath(destination)
        
        logger.info(f"Processing: {name} ({category})")
        logger.debug(f"  Source: {url}")
        
        if not self.skip_download:
            try:
                logger.debug(f"  Downloading...")
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                # Store raw content
                raw_file = destination + '.raw'
                abs_raw_file = os.path.abspath(raw_file)
                with open(raw_file, 'wb') as f:
                    f.write(response.content)
                logger.debug(f"  Raw file saved: {abs_raw_file}")
                
                if not self.skip_optimize:
                    # Detect format characteristics
                    content_sample = response.content[:4000].decode('utf-8', errors='ignore')
                    has_metadata = any(marker in content_sample.lower() for marker in 
                                      ["title:", "version:", "last updated:", "last modified:", "blocked:"])
                    has_grouping = "#[" in content_sample or "# [" in content_sample
                    
                    # Detect if primarily adblock format
                    adblock_lines = sum(1 for line in content_sample.splitlines() if ADBLOCK_PATTERN.match(line.strip()))
                    total_non_comment_lines = sum(1 for line in content_sample.splitlines() 
                                               if line.strip() and not line.strip().startswith('#') 
                                               and not line.strip().startswith('!'))
                    
                    is_primarily_adblock = (total_non_comment_lines > 0 and 
                                           adblock_lines / total_non_comment_lines > 0.5)
                    
                    logger.debug(f"  Format detection: metadata={has_metadata}, grouping={has_grouping}, adblock={is_primarily_adblock}")
                    
                    # Apply appropriate optimization strategy
                    optimized_content, domains = self.optimize_blocklist(
                        response.content, 
                        preserve_metadata=has_metadata,
                        preserve_grouping=has_grouping,
                        preserve_format=is_primarily_adblock
                    )
                    
                    with open(destination, 'w', encoding='utf-8') as f:
                        f.write(optimized_content)
                    
                    # Count domains
                    domain_count = len(domains)
                    
                    logger.info(f"  Optimized: {domain_count} domains")
                    logger.info(f"  Saved to: {abs_destination}")
                    
                    # Update stats
                    self.stats['successful'] += 1
                    self.stats['total_domains'] += domain_count
                    
                    if category not in self.stats['categories']:
                        self.stats['categories'][category] = {
                            'lists': 0,
                            'domains': 0
                        }
                    
                    self.stats['categories'][category]['lists'] += 1
                    self.stats['categories'][category]['domains'] += domain_count
                    
                    # Store domains for deduplication
                    self.domain_stats[name] = {
                        'category': category,
                        'domains': domains,
                        'count': domain_count
                    }
                    
                    return True, domain_count, domains
                else:
                    # Just copy raw file to destination if skipping optimization
                    with open(destination, 'wb') as f:
                        f.write(response.content)
                    logger.info(f"  Downloaded (optimization skipped)")
                    logger.info(f"  Saved to: {abs_destination}")
                    self.stats['successful'] += 1
                    return True, 0, set()
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"  Error downloading {url}: {e}")
                self.stats['failed'] += 1
                self.failed_lists.append({
                    'url': url,
                    'name': name,
                    'category': category,
                    'error': str(e)
                })
                return False, 0, set()
            except Exception as e:
                logger.error(f"  Error processing {name}: {e}")
                self.stats['failed'] += 1
                self.failed_lists.append({
                    'url': url,
                    'name': name,
                    'category': category,
                    'error': str(e)
                })
                return False, 0, set()
        else:
            logger.info(f"  Download skipped")
            return True, 0, set()

    def process_whitelist(self, whitelist):
        """Process a single whitelist (download or read local file)."""
        source = whitelist['source']
        name = whitelist['name']
        is_local = whitelist['is_local']

        logger.info(f"Processing whitelist: {name}")

        try:
            # Get content either from URL or local file
            if is_local:
                file_path = whitelist['file_path']
                logger.debug(f"  Reading local file: {file_path}")
                with open(file_path, 'rb') as f:
                    content = f.read()
            else:
                url = whitelist['url']
                logger.debug(f"  Downloading from: {url}")
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                content = response.content

            # Extract domains from content
            domains = set()
            try:
                lines = content.decode('utf-8', errors='ignore').splitlines()
                for line in lines:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#') or line.startswith('!'):
                        continue

                    # Extract domain using the existing method
                    domain = self.extract_domain_from_line(line)
                    if domain:
                        domains.add(domain.lower())

            except Exception as e:
                logger.error(f"  Error parsing whitelist content: {e}")
                return False, 0

            domain_count = len(domains)
            logger.info(f"  Loaded {domain_count} domains from whitelist")

            # Add to global whitelist domains
            self.whitelist_domains.update(domains)

            return True, domain_count

        except requests.exceptions.RequestException as e:
            logger.error(f"  Error downloading whitelist from {source}: {e}")
            return False, 0
        except IOError as e:
            logger.error(f"  Error reading local whitelist file {source}: {e}")
            return False, 0
        except Exception as e:
            logger.error(f"  Error processing whitelist {name}: {e}")
            return False, 0

    def apply_whitelist(self, domains, category=None):
        """Apply whitelist filtering to a set of domains."""
        if not self.whitelist_domains or len(self.whitelist_domains) == 0:
            return domains  # No whitelist to apply

        original_count = len(domains)
        filtered_domains = domains - self.whitelist_domains
        removed_count = original_count - len(filtered_domains)

        if removed_count > 0:
            if category:
                logger.info(f"  Removed {removed_count} whitelisted domains from {category}")
                self.stats['whitelist']['removed_by_category'][category] = removed_count
            else:
                logger.info(f"  Removed {removed_count} whitelisted domains")

            # Track total removed
            self.stats['whitelist']['total_removed'] += removed_count

        return filtered_domains

    def create_production_lists(self):
        """Create optimized production blocklists."""
        logger.info("Creating production blocklists...")
        
        # All domains across all lists
        all_domains = set()
        category_domains = {category: set() for category in self.categories}
        
        # Collect all domains
        for name, stats in self.domain_stats.items():
            category = stats['category']
            domains = stats['domains']

            # Add to all domains
            all_domains.update(domains)

            # Add to category domains
            category_domains[category].update(domains)

        # Apply whitelist filtering if enabled
        if not self.skip_whitelist and len(self.whitelist_domains) > 0:
            logger.info(f"Applying whitelist with {len(self.whitelist_domains)} domains...")

            # Store removed domains for reporting
            removed_domains = all_domains.intersection(self.whitelist_domains)

            # Apply to master list
            all_domains = self.apply_whitelist(all_domains)

            # Apply to each category
            for category in category_domains:
                category_domains[category] = self.apply_whitelist(category_domains[category], category)

            # Save list of whitelisted domains
            if len(removed_domains) > 0:
                whitelist_report_file = os.path.join(self.prod_dir, "whitelisted_domains.txt")
                with open(whitelist_report_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Whitelisted Domains Removed from Blocklists\n")
                    f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total whitelisted domains: {len(self.whitelist_domains)}\n")
                    f.write(f"# Domains removed from blocklists: {len(removed_domains)}\n\n")
                    for domain in sorted(removed_domains):
                        f.write(f"{domain}\n")
                logger.info(f"Whitelisted domains report saved to: {os.path.abspath(whitelist_report_file)}")

        # Track duplicate statistics
        duplicate_count = 0
        for category1, domains1 in category_domains.items():
            for category2, domains2 in category_domains.items():
                if category1 != category2:
                    overlap = domains1.intersection(domains2)
                    duplicate_count += len(overlap)
        
        # Divide by 2 because we count each duplicate twice
        duplicate_count = duplicate_count // 2
        self.stats['duplicate_domains'] = duplicate_count
        self.stats['unique_domains'] = len(all_domains)
        
        # Create master list for all domains
        master_file = os.path.join(self.prod_dir, "all_domains.txt")
        abs_master_file = os.path.abspath(master_file)
        all_domains_list = sorted(list(all_domains))
        
        with open(master_file, 'w', encoding='utf-8') as f:
            f.write(f"# Pi-hole Master Blocklist\n")
            f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(all_domains_list)}\n\n")
            for domain in all_domains_list:
                f.write(f"0.0.0.0 {domain}\n")
        
        logger.info(f"Created master blocklist with {len(all_domains_list)} domains: {abs_master_file}")
        
        # Create category lists
        category_files = []
        for category, domains in category_domains.items():
            if domains:
                category_file = os.path.join(self.prod_dir, f"{category}.txt")
                abs_category_file = os.path.abspath(category_file)
                domains_list = sorted(list(domains))
                
                with open(category_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Pi-hole {category.capitalize()} Blocklist\n")
                    f.write(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total domains: {len(domains_list)}\n\n")
                    for domain in domains_list:
                        f.write(f"0.0.0.0 {domain}\n")
                
                logger.info(f"Created {category} blocklist with {len(domains_list)} domains: {abs_category_file}")
                category_files.append((category, abs_category_file, len(domains_list)))
        
        # Save list of production files and JSON report
        prod_list_file = os.path.join(self.prod_dir, "_production_lists.txt")
        prod_json_file = os.path.join(self.prod_dir, "_production_stats.json")
        
        # Create text summary
        with open(prod_list_file, 'w', encoding='utf-8') as f:
            f.write("Pi-hole Production Blocklists\n")
            f.write("=============================\n\n")
            f.write(f"Master List: {abs_master_file} ({len(all_domains_list)} domains)\n\n")
            f.write("Category Lists:\n")
            for category, path, count in category_files:
                f.write(f"- {category.capitalize()}: {path} ({count} domains)\n")
        
        # Create JSON stats
        prod_stats = {
            'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'master_list': {
                'path': abs_master_file,
                'domains': len(all_domains_list)
            },
            'categories': {
                category: {
                    'path': os.path.abspath(os.path.join(self.prod_dir, f"{category}.txt")),
                    'domains': len(domains_list)
                }
                for category, domains_list in 
                [(c, sorted(list(d))) for c, d in category_domains.items() if d]
            }
        }
        
        with open(prod_json_file, 'w', encoding='utf-8') as f:
            json.dump(prod_stats, f, indent=2)
                
        logger.info(f"Production list index saved to: {os.path.abspath(prod_list_file)}")
        logger.info(f"Production stats saved to: {os.path.abspath(prod_json_file)}")
    
    def create_stats_report(self):
        """Generate statistics report."""
        stats_file = os.path.join(self.prod_dir, "blocklist_stats.txt")
        
        with open(stats_file, 'w', encoding='utf-8') as f:
            f.write("Pi-hole Blocklist Statistics\n")
            f.write("===========================\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Lists: {self.stats['total_lists']}\n")
            f.write(f"Successfully Downloaded: {self.stats['successful']}\n")
            f.write(f"Failed Downloads: {self.stats['failed']}\n")
            f.write(f"Total Domains (with duplicates): {self.stats['total_domains']}\n")
            f.write(f"Unique Domains: {self.stats['unique_domains']}\n")
            f.write(f"Duplicate Domains: {self.stats['duplicate_domains']}\n\n")

            # Whitelist statistics
            if not self.skip_whitelist and self.stats['whitelist']['whitelist_domains'] > 0:
                f.write("Whitelist Statistics\n")
                f.write("-------------------\n")
                f.write(f"Total Whitelist Sources: {self.stats['whitelist']['total_whitelists']}\n")
                f.write(f"Total Whitelist Domains: {self.stats['whitelist']['whitelist_domains']}\n")
                f.write(f"Domains Removed by Whitelist: {self.stats['whitelist']['total_removed']}\n")

                if self.stats['whitelist']['removed_by_category']:
                    f.write("\nDomains Removed by Category:\n")
                    for category, count in sorted(self.stats['whitelist']['removed_by_category'].items()):
                        f.write(f"  {category.capitalize()}: {count} domains\n")
                f.write("\n")

            f.write("Lists by Category\n")
            f.write("-----------------\n")
            for category, stats in self.stats['categories'].items():
                f.write(f"{category.capitalize()}: {stats['lists']} lists, {stats['domains']} domains\n")
            
            f.write("\nDetailed List Statistics\n")
            f.write("----------------------\n")
            sorted_stats = sorted(
                [(name, stat['category'], stat['count']) for name, stat in self.domain_stats.items()],
                key=lambda x: (x[1], -x[2])  # Sort by category then by count (descending)
            )
            
            current_category = None
            for name, category, count in sorted_stats:
                if category != current_category:
                    f.write(f"\n[{category}]\n")
                    current_category = category
                f.write(f"{name}: {count} domains\n")
            
            if self.failed_lists:
                f.write("\nFailed Lists\n")
                f.write("------------\n")
                for failed in self.failed_lists:
                    f.write(f"{failed['name']} ({failed['category']}): {failed['error']}\n")
        
        # Also save JSON stats
        json_stats_file = os.path.join(self.prod_dir, "blocklist_stats.json")
        with open(json_stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, default=str)

        logger.info(f"Statistics report saved to: {stats_file}")
        logger.info(f"JSON statistics saved to: {json_stats_file}")

    def cleanup_temp_files(self):
        """Clean up temporary files after processing."""
        if not os.path.exists(self.temp_dir):
            logger.debug(f"Temp directory does not exist, skipping cleanup")
            return

        try:
            logger.info(f"Cleaning up temporary files in {self.temp_dir}...")
            shutil.rmtree(self.temp_dir)
            logger.info("Temporary files cleaned up successfully")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary files: {e}")
            logger.warning("You may need to manually delete the temp directory")

    def update_config_file(self):
        """Update the configuration file to comment out failed lists."""
        if not self.failed_lists:
            return
            
        logger.info("Updating configuration file to disable failed lists...")
        
        # Read current config
        with open(self.config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Find failed URLs
        failed_urls = [item['url'] for item in self.failed_lists]
        
        # Update file
        with open(self.config_file, 'w', encoding='utf-8') as f:
            for line in lines:
                if any(url in line for url in failed_urls) and not line.startswith('#'):
                    f.write(f"#DISABLED: {line}")
                    logger.info(f"Disabled line: {line.strip()}")
                else:
                    f.write(line)
        
        logger.info(f"Configuration file updated: {self.config_file}")
    
    def run(self):
        """Run the blocklist downloader pipeline."""
        start_time = time.time()
        
        # Load configuration
        self.load_config()
        
        # Create directories
        self.create_directories()
        
        # Process blocklists
        logger.info(f"Processing {len(self.blocklists)} blocklists with {self.threads} threads")
        
        if self.threads > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.process_blocklist, blocklist): blocklist for blocklist in self.blocklists}
                
                # Process results as they complete
                for future in tqdm(concurrent.futures.as_completed(futures), 
                                   total=len(self.blocklists), 
                                   desc="Processing blocklists",
                                   disable=self.quiet):
                    blocklist = futures[future]
                    try:
                        success, count, domains = future.result()
                    except Exception as e:
                        logger.error(f"Error processing {blocklist['name']}: {e}")
        else:
            # Sequential processing
            for blocklist in tqdm(self.blocklists, 
                                 desc="Processing blocklists",
                                 disable=self.quiet):
                self.process_blocklist(blocklist)

        # Process whitelists if not skipped
        if not self.skip_whitelist and not self.skip_optimize:
            self.load_whitelist_config()

            if len(self.whitelists) > 0:
                logger.info(f"Processing {len(self.whitelists)} whitelist(s)")

                for whitelist in self.whitelists:
                    success, count = self.process_whitelist(whitelist)
                    if success:
                        self.stats['whitelist']['whitelist_domains'] = len(self.whitelist_domains)

        # Create production lists
        if not self.skip_optimize:
            self.create_production_lists()
        
        # Create statistics report
        self.create_stats_report()
        
        # Update config file to disable failed lists
        if self.failed_lists:
            self.update_config_file()

        # Clean up temporary files unless skip_delete is set
        if not self.skip_delete:
            self.cleanup_temp_files()
        else:
            logger.info(f"Temporary files preserved in: {os.path.abspath(self.temp_dir)}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        self.stats['elapsed_time'] = f"{elapsed_time:.2f} seconds"
        
        logger.info(f"\nProcessing complete in {elapsed_time:.2f} seconds")
        logger.info(f"Total Lists:       {self.stats['total_lists']}")
        logger.info(f"Successful:        {self.stats['successful']}")
        logger.info(f"Failed:            {self.stats['failed']}")
        logger.info(f"Total Domains:     {self.stats['total_domains']}")
        logger.info(f"Unique Domains:    {self.stats['unique_domains']}")
        logger.info(f"Duplicate Domains: {self.stats['duplicate_domains']}")

        # Show whitelist stats if applied
        if not self.skip_whitelist and self.stats['whitelist']['whitelist_domains'] > 0:
            logger.info(f"\nWhitelist Statistics:")
            logger.info(f"Whitelist Sources: {self.stats['whitelist']['total_whitelists']}")
            logger.info(f"Whitelist Domains: {self.stats['whitelist']['whitelist_domains']}")
            logger.info(f"Domains Removed:   {self.stats['whitelist']['total_removed']}")
        
        if self.stats['successful'] > 0:
            logger.info(f"\nProduction blocklists saved to: {os.path.abspath(self.prod_dir)}")
            logger.info(f"Statistics report saved to: {os.path.join(self.prod_dir, 'blocklist_stats.txt')}")
            
        # Return stats for potential external use
        return self.stats

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Pi-hole Blocklist Downloader and Optimizer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE,
                        help=f"Configuration file (default: {DEFAULT_CONFIG_FILE})")
    parser.add_argument("--temp-dir", default=TEMP_DIR,
                        help=f"Temporary directory for raw and optimized lists (default: {TEMP_DIR})")
    parser.add_argument("-p", "--prod-dir", default=PROD_DIR,
                        help=f"Production directory for combined lists (default: {PROD_DIR})")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of download threads (1-16)")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip downloading files (use existing files)")
    parser.add_argument("--skip-optimize", action="store_true",
                        help="Skip optimization (just download)")
    parser.add_argument("--skip-delete", action="store_true",
                        help="Keep temporary files after processing (default: delete)")
    parser.add_argument("--whitelist-config", default="whitelists.conf",
                        help="Whitelist configuration file (default: whitelists.conf)")
    parser.add_argument("--skip-whitelist", action="store_true",
                        help="Skip whitelist processing even if configured")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all output except errors")
    parser.add_argument("--version", action="version", version="Pi-hole Blocklist Downloader v1.2.0",
                        help="Show program's version number and exit")
    
    args = parser.parse_args()
    
    # Set logging level based on arguments
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)
    
    return args

def main():
    """Main function."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Print banner
    if not args.quiet:
        print("\n" + "="*60)
        print(" "*15 + "PI-HOLE BLOCKLIST DOWNLOADER v1.2.0")
        print("="*60 + "\n")
    
    # Create and run blocklist manager
    manager = BlocklistManager(
        config_file=args.config,
        temp_dir=args.temp_dir,
        prod_dir=args.prod_dir,
        threads=args.threads,
        skip_download=args.skip_download,
        skip_optimize=args.skip_optimize,
        quiet=args.quiet,
        verbose=args.verbose,
        whitelist_config=args.whitelist_config,
        skip_whitelist=args.skip_whitelist,
        skip_delete=args.skip_delete
    )
    
    try:
        stats = manager.run()
        
        # Print summary box if not quiet
        if not args.quiet:
            print("\n" + "="*60)
            print(" "*20 + "SUMMARY")
            print("="*60)
            print(f"Total lists processed:  {stats['total_lists']}")
            print(f"Successfully downloaded: {stats['successful']}")
            print(f"Failed:                 {stats['failed']}")
            print(f"Unique domains:         {stats['unique_domains']:,}")
            print(f"Total runtime:          {stats.get('elapsed_time', 'N/A')}")
            print("="*60 + "\n")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())