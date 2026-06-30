use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use crate::client::HttpClient;
use crate::config::{load_blocklists, AppConfig};
use crate::domain::{extract_entry, format_num};
use crate::progress::ProgressTracker;
use crate::whitelist::WhitelistManager;

pub struct BlocklistManager {
    pub config: AppConfig,
    http_client: HttpClient,
    progress: ProgressTracker,
    whitelist: WhitelistManager,
}

impl BlocklistManager {
    pub fn new(config: AppConfig) -> Result<Self> {
        let http_client = HttpClient::new(config.timeout)?;
        let progress = ProgressTracker::load();
        let whitelist = WhitelistManager::load(&config.whitelist_file, config.whitelist_subdomain);

        Ok(Self {
            config,
            http_client,
            progress,
            whitelist,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();

        let blocklists = load_blocklists(&self.config.config_file, &self.progress)?;
        let categories: HashSet<String> = blocklists.iter().map(|b| b.category.clone()).collect();
        let total_lists = blocklists.len();

        if self.config.dry_run {
            info!(
                "[DRY RUN] Would process {total_lists} blocklists in {} categories",
                categories.len()
            );
            return Ok(());
        }

        self.create_directories(&categories)?;

        let mut category_domains: HashMap<String, HashSet<String>> = HashMap::new();
        let mut successful = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;

        if self.config.skip_download {
            info!("Skipping downloads, loading existing files...");
            for bl in &blocklists {
                let path = Path::new(&self.config.base_dir)
                    .join(&bl.category)
                    .join(format!("{}.txt", bl.name));
                if path.exists() {
                    match load_domains_from_file(&path, bl.allow_wildcards) {
                        Ok(domains) => {
                            debug!("  {}: {} domains (from file)", bl.name, domains.len());
                            category_domains
                                .entry(bl.category.clone())
                                .or_default()
                                .extend(domains);
                            successful += 1;
                        }
                        Err(e) => {
                            warn!("  {}: Failed to load - {e}", bl.name);
                            failed += 1;
                        }
                    }
                } else {
                    warn!("  {}: No local file found", bl.name);
                    failed += 1;
                }
            }
        } else {
            info!(
                "Downloading {total_lists} blocklists with {} threads...",
                self.config.threads
            );

            let pb = if self.config.quiet || self.config.verbose {
                ProgressBar::hidden()
            } else {
                let pb = ProgressBar::new(total_lists as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template(
                            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                        )
                        .unwrap()
                        .progress_chars("#>-"),
                );
                pb
            };

            let client = self.http_client.clone();
            let incremental = self.config.incremental;

            let results: Vec<_> = stream::iter(blocklists.clone())
                .map(|bl| {
                    let client = client.clone();
                    async move {
                        let result = client
                            .download(
                                &bl.url,
                                if incremental {
                                    bl.etag.as_deref()
                                } else {
                                    None
                                },
                                if incremental {
                                    bl.last_modified.as_deref()
                                } else {
                                    None
                                },
                            )
                            .await;
                        (bl, result)
                    }
                })
                .buffer_unordered(self.config.threads)
                .collect()
                .await;

            for (bl, result) in results {
                pb.inc(1);

                match result {
                    Err(e) => {
                        error!("  {}: {e}", bl.name);
                        failed += 1;
                    }
                    Ok(dl) if !dl.was_modified => {
                        debug!("  {}: Not modified (skipped)", bl.name);
                        skipped += 1;

                        // Load existing local file for production list generation
                        let path = Path::new(&self.config.base_dir)
                            .join(&bl.category)
                            .join(format!("{}.txt", bl.name));
                        if path.exists() {
                            if let Ok(domains) = load_domains_from_file(&path, bl.allow_wildcards) {
                                category_domains
                                    .entry(bl.category.clone())
                                    .or_default()
                                    .extend(domains);
                            }
                        }
                    }
                    Ok(dl) => {
                        let content = dl.content.expect("modified response must have content");
                        let domains = process_content(&content, bl.allow_wildcards);
                        let count = domains.len();

                        if count == 0 {
                            warn!("  {}: No valid domains extracted", bl.name);
                        }

                        // Save raw file
                        let cat_dir = Path::new(&self.config.base_dir).join(&bl.category);
                        let raw_path = cat_dir.join(format!("{}.txt.raw", bl.name));
                        if let Err(e) = std::fs::write(&raw_path, &content) {
                            warn!("Failed to write raw file for {}: {e}", bl.name);
                        }

                        // Save optimized file
                        let opt_path = cat_dir.join(format!("{}.txt", bl.name));
                        if let Err(e) = write_blocklist_file(&opt_path, &domains, None, false) {
                            warn!("Failed to write optimized file for {}: {e}", bl.name);
                        }

                        // Update progress tracker
                        self.progress.update(
                            &bl.name,
                            dl.etag.as_deref(),
                            dl.last_modified.as_deref(),
                            count,
                        );

                        category_domains
                            .entry(bl.category.clone())
                            .or_default()
                            .extend(domains);
                        successful += 1;

                        debug!("  {}: {count} domains", bl.name);
                    }
                }
            }

            pb.finish_and_clear();
        }

        // Compute unique domain count (excluding NSFW)
        let unique_domains = {
            let mut all: HashSet<&String> = HashSet::new();
            for (cat, domains) in &category_domains {
                if cat != "nsfw" {
                    all.extend(domains);
                }
            }
            all.len()
        };

        let mut whitelisted = 0usize;
        let mut final_domains = unique_domains;

        // Create production lists
        if !self.config.skip_optimize {
            let (w, f) = self.create_production_lists(&category_domains)?;
            whitelisted = w;
            final_domains = f;
        }

        let elapsed = start.elapsed();

        // Print summary
        if !self.config.quiet {
            println!();
            println!("{}", "=".repeat(60));
            println!("{:>35}", "SUMMARY");
            println!("{}", "=".repeat(60));
            println!("Total lists:        {total_lists}");
            println!("Successful:         {successful}");
            println!("Skipped:            {skipped}");
            println!("Failed:             {failed}");
            println!("Unique domains:     {}", format_num(unique_domains));
            if whitelisted > 0 {
                println!("Whitelisted:        {}", format_num(whitelisted));
                println!("Final count:        {}", format_num(final_domains));
            }
            println!("Runtime:            {:.2} seconds", elapsed.as_secs_f64());
            println!("{}", "=".repeat(60));
            println!();
        }

        Ok(())
    }

    fn create_directories(&self, categories: &HashSet<String>) -> Result<()> {
        std::fs::create_dir_all(&self.config.base_dir)?;
        for cat in categories {
            std::fs::create_dir_all(Path::new(&self.config.base_dir).join(cat))?;
        }
        std::fs::create_dir_all(&self.config.prod_dir)?;
        Ok(())
    }

    fn create_production_lists(
        &self,
        category_domains: &HashMap<String, HashSet<String>>,
    ) -> Result<(usize, usize)> {
        info!("Creating production blocklists...");

        // Combine all non-NSFW domains
        let mut all_domains: HashSet<String> = HashSet::new();
        for (cat, domains) in category_domains {
            if cat != "nsfw" {
                all_domains.extend(domains.iter().cloned());
            }
        }

        // Apply whitelist filtering
        info!("Applying whitelist filtering...");
        let (filtered, removed) = self.whitelist.filter_domains(&all_domains);

        // Write master file
        let master_path = Path::new(&self.config.prod_dir).join("all_domains.txt");
        write_blocklist_file(&master_path, &filtered, Some("Master"), false)?;
        info!(
            "Created Master blocklist: {} domains",
            format_num(filtered.len())
        );

        // Write per-category files
        for (cat, domains) in category_domains {
            if !domains.is_empty() {
                let (cat_filtered, _) = self.whitelist.filter_domains(domains);
                let cat_path = Path::new(&self.config.prod_dir).join(format!("{cat}.txt"));
                let label = capitalize(cat);
                write_blocklist_file(&cat_path, &cat_filtered, Some(&label), false)?;
                info!(
                    "Created {label} blocklist: {} domains",
                    format_num(cat_filtered.len())
                );

                if self
                    .config
                    .abp_lists
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(cat))
                {
                    let abp_path = Path::new(&self.config.prod_dir).join(format!("{cat}_abp.txt"));
                    let abp_label = format!("{label} (ABP)");
                    write_blocklist_file(&abp_path, &cat_filtered, Some(&abp_label), true)?;
                    info!(
                        "Created {abp_label} blocklist: {} entries",
                        format_num(cat_filtered.len())
                    );
                }
            }
        }

        // Whitelist report
        if self.config.whitelist_report && removed > 0 {
            let removed_set: HashSet<String> = all_domains.difference(&filtered).cloned().collect();
            let report_path = Path::new(&self.config.prod_dir).join("whitelist_report.txt");
            self.whitelist.generate_report(
                report_path
                    .to_str()
                    .expect("report path must be valid UTF-8"),
                &removed_set,
            )?;
        }

        Ok((removed, filtered.len()))
    }
}

fn process_content(content: &[u8], allow_wildcards: bool) -> HashSet<String> {
    let text = String::from_utf8_lossy(content);
    let mut domains = HashSet::new();
    for line in text.lines() {
        if let Some(entry) = extract_entry(line, allow_wildcards) {
            domains.insert(entry.to_key());
        }
    }
    domains
}

fn load_domains_from_file(path: &Path, allow_wildcards: bool) -> Result<HashSet<String>> {
    let content =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(process_content(&content, allow_wildcards))
}

fn write_blocklist_file(
    path: &Path,
    domains: &HashSet<String>,
    label: Option<&str>,
    force_abp: bool,
) -> Result<()> {
    let mut sorted: Vec<&String> = domains.iter().collect();
    sorted.sort();

    let file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    let mut w = std::io::BufWriter::new(file);

    let label = label.unwrap_or("Optimized");
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

    writeln!(w, "# Pi-hole {label} Blocklist")?;
    writeln!(w, "# Last updated: {now}")?;
    writeln!(w, "# Total domains: {}", sorted.len())?;
    writeln!(w)?;

    for domain in sorted {
        let line = if force_abp {
            format_abp_line(domain)
        } else {
            format_blocklist_line(domain)
        };
        writeln!(w, "{line}")?;
    }

    Ok(())
}

fn format_blocklist_line(key: &str) -> String {
    if key.starts_with("||") {
        key.to_string()
    } else {
        format!("0.0.0.0 {key}")
    }
}

fn format_abp_line(key: &str) -> String {
    if key.starts_with("||") {
        key.to_string()
    } else {
        format!("||{key}^")
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_content_emits_wildcards_when_enabled() {
        let set = process_content(b"||foo.com^\n*.bar.com\n0.0.0.0 baz.com\n", true);
        assert!(set.contains("||foo.com^"));
        assert!(set.contains("||bar.com^"));
        assert!(set.contains("baz.com"));
    }

    #[test]
    fn process_content_flattens_when_disabled() {
        let set = process_content(b"||foo.com^\n*.bar.com\n", false);
        assert!(set.contains("foo.com"));
        assert!(set.contains("bar.com"));
        assert!(!set.iter().any(|d| d.contains('*') || d.starts_with("||")));
    }

    #[test]
    fn format_blocklist_line_handles_both_forms() {
        assert_eq!(format_blocklist_line("foo.com"), "0.0.0.0 foo.com");
        assert_eq!(format_blocklist_line("||foo.com^"), "||foo.com^");
    }

    #[test]
    fn format_abp_line_wraps_exact_and_keeps_wildcards() {
        assert_eq!(format_abp_line("foo.com"), "||foo.com^");
        assert_eq!(format_abp_line("sub.foo.com"), "||sub.foo.com^");
        assert_eq!(format_abp_line("||foo.com^"), "||foo.com^");
    }
}
