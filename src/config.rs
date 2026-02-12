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
}

#[derive(Debug, Clone)]
pub struct Blocklist {
    pub url: String,
    pub name: String,
    pub category: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub fn load_blocklists(
    config_file: &str,
    progress: &ProgressTracker,
) -> Result<Vec<Blocklist>> {
    let path = Path::new(config_file);
    if !path.exists() {
        bail!("Configuration file '{config_file}' not found");
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {config_file}"))?;

    let mut blocklists = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 3 {
            warn!("Invalid format on line {}: {line}", line_num + 1);
            continue;
        }

        let url = parts[0].trim();
        let name = parts[1].trim();
        let category = parts[2].trim();

        if Url::parse(url).is_err() {
            warn!("Invalid URL on line {}: {url}", line_num + 1);
            continue;
        }

        let cached = progress.get(name);
        let etag = cached.and_then(|c| c.etag.clone());
        let last_modified = cached.and_then(|c| c.last_modified.clone());

        blocklists.push(Blocklist {
            url: url.to_string(),
            name: name.to_string(),
            category: category.to_string(),
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
