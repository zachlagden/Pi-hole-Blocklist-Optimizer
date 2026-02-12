use anyhow::Result;
use log::{debug, info, warn};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

use crate::domain::{normalize_domain, validate_domain};

pub struct WhitelistManager {
    exact_domains: HashSet<String>,
    combined_pattern: Option<Regex>,
    enable_subdomain: bool,
}

impl WhitelistManager {
    pub fn load(whitelist_file: &str, enable_subdomain: bool) -> Self {
        let mut manager = Self {
            exact_domains: HashSet::new(),
            combined_pattern: None,
            enable_subdomain,
        };

        if !Path::new(whitelist_file).exists() {
            debug!("Whitelist file not found: {whitelist_file}");
            return manager;
        }

        let content = match std::fs::read_to_string(whitelist_file) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to load whitelist: {e}");
                return manager;
            }
        };

        let mut exact_count = 0usize;
        let mut wildcard_count = 0usize;
        let mut regex_count = 0usize;
        let mut all_patterns: Vec<String> = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Regex pattern: /pattern/
            if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
                let pattern = &line[1..line.len() - 1];
                match Regex::new(pattern) {
                    Ok(_) => {
                        all_patterns.push(format!("(?:{pattern})"));
                        regex_count += 1;
                    }
                    Err(e) => {
                        warn!(
                            "Invalid regex on line {}: {pattern} - {e}",
                            line_num + 1
                        );
                    }
                }
                continue;
            }

            // Wildcard pattern: contains *
            if line.contains('*') {
                let regex_pattern = format!(
                    "^{}$",
                    line.replace('.', r"\.").replace('*', ".*")
                );
                match Regex::new(&regex_pattern) {
                    Ok(_) => {
                        all_patterns.push(format!("(?:{regex_pattern})"));
                        wildcard_count += 1;
                    }
                    Err(e) => {
                        warn!(
                            "Invalid wildcard on line {}: {line} - {e}",
                            line_num + 1
                        );
                    }
                }
                continue;
            }

            // Exact domain
            let domain = normalize_domain(line);
            if validate_domain(&domain) {
                manager.exact_domains.insert(domain);
                exact_count += 1;
            }
        }

        // Build combined regex for wildcard and regex patterns
        if !all_patterns.is_empty() {
            match Regex::new(&all_patterns.join("|")) {
                Ok(re) => manager.combined_pattern = Some(re),
                Err(_) => warn!("Failed to compile combined whitelist pattern"),
            }
        }

        let total = exact_count + wildcard_count + regex_count;
        if total > 0 {
            info!(
                "Loaded {total} whitelist entries: {exact_count} exact, \
                 {wildcard_count} wildcard, {regex_count} regex"
            );
        }

        manager
    }

    /// Check if domain is a subdomain of any whitelisted exact domain.
    /// Zero-allocation: iterates through dot positions and checks suffixes.
    fn check_subdomain(&self, domain: &str) -> bool {
        let mut start = 0;
        while let Some(dot_pos) = domain[start..].find('.') {
            start += dot_pos + 1;
            if self.exact_domains.contains(&domain[start..]) {
                return true;
            }
        }
        false
    }

    pub fn filter_domains(
        &self,
        domains: &HashSet<String>,
    ) -> (HashSet<String>, usize) {
        if self.exact_domains.is_empty()
            && self.combined_pattern.is_none()
        {
            return (domains.clone(), 0);
        }

        let mut filtered = HashSet::with_capacity(domains.len());
        let mut removed = 0usize;

        for domain in domains {
            let mut matched = false;

            // Exact match (O(1) set lookup)
            if self.exact_domains.contains(domain.as_str()) {
                matched = true;
            }

            // Subdomain match (O(k) where k = domain label count)
            if !matched && self.enable_subdomain {
                matched = self.check_subdomain(domain);
            }

            // Wildcard/regex match (single combined pattern)
            if !matched {
                if let Some(ref re) = self.combined_pattern {
                    matched = re.is_match(domain);
                }
            }

            if matched {
                removed += 1;
            } else {
                filtered.insert(domain.clone());
            }
        }

        if removed > 0 {
            info!("Filtered {removed} whitelisted domains");
        }

        (filtered, removed)
    }

    pub fn generate_report(
        &self,
        output_file: &str,
        removed_domains: &HashSet<String>,
    ) -> Result<()> {
        use std::io::Write;

        let file = std::fs::File::create(output_file)?;
        let mut w = std::io::BufWriter::new(file);

        writeln!(w, "Whitelist Report")?;
        writeln!(w, "{}", "=".repeat(80))?;
        writeln!(w)?;
        writeln!(
            w,
            "Generated: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )?;
        writeln!(w)?;
        writeln!(w, "Total Domains Removed: {}", removed_domains.len())?;
        writeln!(w)?;

        // Categorize removed domains by match type
        let mut exact = Vec::new();
        let mut subdomain = Vec::new();
        let mut pattern = Vec::new();

        for domain in removed_domains {
            if self.exact_domains.contains(domain.as_str()) {
                exact.push(domain.as_str());
            } else if self.enable_subdomain && self.check_subdomain(domain) {
                subdomain.push(domain.as_str());
            } else {
                pattern.push(domain.as_str());
            }
        }

        exact.sort();
        subdomain.sort();
        pattern.sort();

        if !exact.is_empty() {
            writeln!(w, "Exact Matches: {}", exact.len())?;
            for d in exact.iter().take(100) {
                writeln!(w, "  - {d}")?;
            }
            if exact.len() > 100 {
                writeln!(w, "  ... and {} more", exact.len() - 100)?;
            }
            writeln!(w)?;
        }

        if !subdomain.is_empty() {
            writeln!(w, "Subdomain Matches: {}", subdomain.len())?;
            for d in subdomain.iter().take(100) {
                writeln!(w, "  - {d}")?;
            }
            if subdomain.len() > 100 {
                writeln!(w, "  ... and {} more", subdomain.len() - 100)?;
            }
            writeln!(w)?;
        }

        if !pattern.is_empty() {
            writeln!(w, "Pattern Matches (wildcard/regex): {}", pattern.len())?;
            for d in pattern.iter().take(100) {
                writeln!(w, "  - {d}")?;
            }
            if pattern.len() > 100 {
                writeln!(w, "  ... and {} more", pattern.len() - 100)?;
            }
            writeln!(w)?;
        }

        info!("Whitelist report saved to: {output_file}");
        Ok(())
    }
}
