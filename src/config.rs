use anyhow::{bail, Context, Result};
use log::{info, warn};
use std::collections::HashSet;
use std::path::Path;
use url::Url;

use crate::progress::ProgressTracker;

pub struct AppConfig {
    pub config_file: String,
    pub whitelist_file: String,
    pub base_dir: String,
    pub prod_dir: String,
    pub threads: usize,
    pub timeout: u64,
    pub skip_download: bool,
    pub skip_optimize: bool,
    pub incremental: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub whitelist_subdomain: bool,
    pub whitelist_report: bool,
    pub abp_lists: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Blocklist {
    pub url: String,
    pub name: String,
    pub category: String,
    pub allow_wildcards: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub struct ParsedSource {
    pub url: String,
    pub name: String,
    pub category: String,
    pub allow_wildcards: bool,
}

pub fn parse_source_line(line: &str) -> Option<ParsedSource> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return None;
    }

    let url = parts[0].trim();
    let name = parts[1].trim();
    let category = parts[2].trim();

    if Url::parse(url).is_err() {
        return None;
    }

    let allow_wildcards = parts
        .get(3)
        .map(|f| f.trim().eq_ignore_ascii_case("abp"))
        .unwrap_or(false);

    Some(ParsedSource {
        url: url.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        allow_wildcards,
    })
}

pub fn load_blocklists(config_file: &str, progress: &ProgressTracker) -> Result<Vec<Blocklist>> {
    let path = Path::new(config_file);
    if !path.exists() {
        bail!("Configuration file '{config_file}' not found");
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {config_file}"))?;

    let mut blocklists = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(parsed) = parse_source_line(trimmed) else {
            warn!("Invalid blocklist line {}: {line}", line_num + 1);
            continue;
        };

        let cached = progress.get(&parsed.name);
        let etag = cached.and_then(|c| c.etag.clone());
        let last_modified = cached.and_then(|c| c.last_modified.clone());

        blocklists.push(Blocklist {
            url: parsed.url,
            name: parsed.name,
            category: parsed.category,
            allow_wildcards: parsed.allow_wildcards,
            etag,
            last_modified,
        });
    }

    if blocklists.is_empty() {
        bail!("No valid blocklists found in configuration file");
    }

    let categories: HashSet<&str> = blocklists.iter().map(|b| b.category.as_str()).collect();
    info!(
        "Loaded {} blocklists in {} categories",
        blocklists.len(),
        categories.len()
    );

    Ok(blocklists)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_field_line_without_wildcards() {
        let p = parse_source_line("https://example.com/a.txt|name|advertising").unwrap();
        assert_eq!(p.name, "name");
        assert_eq!(p.category, "advertising");
        assert!(!p.allow_wildcards);
    }

    #[test]
    fn parses_abp_flag_as_allow_wildcards() {
        let p = parse_source_line("https://example.com/a.txt|name|advertising|abp").unwrap();
        assert!(p.allow_wildcards);
        let upper = parse_source_line("https://example.com/a.txt|name|advertising|ABP").unwrap();
        assert!(upper.allow_wildcards);
    }

    #[test]
    fn unknown_fourth_field_is_not_wildcards() {
        let p = parse_source_line("https://example.com/a.txt|name|advertising|xyz").unwrap();
        assert!(!p.allow_wildcards);
    }

    #[test]
    fn skips_comment_and_blank_lines() {
        assert!(parse_source_line("# comment").is_none());
        assert!(parse_source_line("   ").is_none());
    }

    #[test]
    fn rejects_bad_field_counts_and_urls() {
        assert!(parse_source_line("a|b").is_none());
        assert!(parse_source_line("a|b|c|d|e").is_none());
        assert!(parse_source_line("not-a-url|n|advertising").is_none());
    }
}
