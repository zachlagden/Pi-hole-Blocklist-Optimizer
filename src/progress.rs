use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const PROGRESS_FILE: &str = "download_progress.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEntry {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub domain_count: usize,
    pub last_download: String,
}

pub struct ProgressTracker {
    entries: HashMap<String, ProgressEntry>,
}

impl ProgressTracker {
    pub fn load() -> Self {
        let entries = if Path::new(PROGRESS_FILE).exists() {
            match std::fs::read_to_string(PROGRESS_FILE) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(map) => {
                        let map: HashMap<String, ProgressEntry> = map;
                        log::debug!("Loaded progress for {} lists", map.len());
                        map
                    }
                    Err(e) => {
                        log::warn!("Failed to parse progress file: {e}");
                        HashMap::new()
                    }
                },
                Err(e) => {
                    log::warn!("Failed to read progress file: {e}");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Self { entries }
    }

    pub fn get(&self, name: &str) -> Option<&ProgressEntry> {
        self.entries.get(name)
    }

    pub fn update(
        &mut self,
        name: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        domain_count: usize,
    ) {
        self.entries.insert(
            name.to_string(),
            ProgressEntry {
                etag: etag.map(String::from),
                last_modified: last_modified.map(String::from),
                domain_count,
                last_download: chrono::Local::now().to_rfc3339(),
            },
        );
        self.save();
    }

    fn save(&self) {
        match serde_json::to_string_pretty(&self.entries) {
            Ok(json) => {
                if let Err(e) = std::fs::write(PROGRESS_FILE, json) {
                    log::error!("Failed to save progress: {e}");
                }
            }
            Err(e) => log::error!("Failed to serialize progress: {e}"),
        }
    }
}
