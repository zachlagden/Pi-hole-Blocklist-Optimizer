use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

const MAX_DOMAIN_LENGTH: usize = 253;

static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$",
    )
    .unwrap()
});

static ADBLOCK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|\|(.+?)\^(?:\$.*)?$").unwrap());

static IP_DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\S+)$").unwrap());

static COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[#!].*$").unwrap());

pub fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain == "localhost" || domain.ends_with(".local") {
        return false;
    }
    if domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }
    let check = if let Some(stripped) = domain.strip_prefix("*.") {
        stripped
    } else {
        domain
    };
    DOMAIN_RE.is_match(check)
}

pub fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Exact(String),
    Wildcard(String),
}

impl Entry {
    pub fn to_key(&self) -> String {
        match self {
            Entry::Exact(d) => d.clone(),
            Entry::Wildcard(d) => format!("||{d}^"),
        }
    }

    pub fn from_key(key: &str) -> Entry {
        if is_wildcard_key(key) {
            Entry::Wildcard(key_domain(key).to_string())
        } else {
            Entry::Exact(key.to_string())
        }
    }

    pub fn to_line(&self) -> String {
        match self {
            Entry::Exact(d) => format!("0.0.0.0 {d}"),
            Entry::Wildcard(d) => format!("||{d}^"),
        }
    }
}

fn is_wildcard_key(key: &str) -> bool {
    key.starts_with("||") && key.ends_with('^')
}

pub fn key_domain(key: &str) -> &str {
    key.strip_prefix("||")
        .and_then(|k| k.strip_suffix('^'))
        .unwrap_or(key)
}

fn parent_domains(domain: &str) -> impl Iterator<Item = &str> {
    domain
        .match_indices('.')
        .map(move |(i, _)| &domain[i + 1..])
}

pub fn collapse_entries(keys: &HashSet<String>, all_wildcard: bool) -> Vec<Entry> {
    let is_wildcard = |key: &str| all_wildcard || is_wildcard_key(key);
    let wildcards: HashSet<&str> = keys
        .iter()
        .filter(|k| is_wildcard(k))
        .map(|k| key_domain(k))
        .collect();
    let covered = |domain: &str| parent_domains(domain).any(|p| wildcards.contains(p));

    let mut entries: Vec<Entry> = wildcards
        .iter()
        .filter(|d| !covered(d))
        .map(|d| Entry::Wildcard(d.to_string()))
        .collect();
    entries.extend(
        keys.iter()
            .filter(|k| !is_wildcard(k))
            .filter(|d| !wildcards.contains(d.as_str()) && !covered(d))
            .map(|d| Entry::Exact(d.clone())),
    );
    entries
}

fn make_exact(domain: &str) -> Option<Entry> {
    let d = normalize_domain(domain);
    if !d.contains('*') && validate_domain(&d) {
        Some(Entry::Exact(d))
    } else {
        None
    }
}

fn make_wildcard(domain: &str) -> Option<Entry> {
    let d = normalize_domain(domain);
    if !d.contains('*') && validate_domain(&d) {
        Some(Entry::Wildcard(d))
    } else {
        None
    }
}

pub fn extract_entry(line: &str, allow_wildcards: bool) -> Option<Entry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }

    let line = COMMENT_RE.replace(line, "");
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    if let Some(caps) = IP_DOMAIN_RE.captures(line) {
        return make_exact(caps.get(1)?.as_str());
    }

    if let Some(caps) = ADBLOCK_RE.captures(line) {
        let domain = caps.get(1)?.as_str();
        return if allow_wildcards {
            make_wildcard(domain)
        } else {
            make_exact(domain)
        };
    }

    if let Some(stripped) = line.strip_prefix("*.") {
        return if allow_wildcards {
            make_wildcard(stripped)
        } else {
            make_exact(stripped)
        };
    }

    if !line.contains(' ') && !line.contains('/') && !line.contains('?') {
        return make_exact(line);
    }

    None
}

pub fn format_num(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com"));
        assert!(validate_domain("sub.example.com"));
        assert!(validate_domain("a.b.c.d.example.com"));
        assert!(!validate_domain("localhost"));
        assert!(!validate_domain("test.local"));
        assert!(!validate_domain(""));
        assert!(!validate_domain("-invalid.com"));
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Example.COM"), "example.com");
        assert_eq!(normalize_domain("test.com."), "test.com");
    }

    #[test]
    fn test_extract_entry_hosts_and_plain() {
        assert_eq!(
            extract_entry("0.0.0.0 ads.example.com", true),
            Some(Entry::Exact("ads.example.com".to_string()))
        );
        assert_eq!(
            extract_entry("ads.example.com", false),
            Some(Entry::Exact("ads.example.com".to_string()))
        );
    }

    #[test]
    fn test_extract_entry_abp_respects_flag() {
        assert_eq!(
            extract_entry("||foo.com^", true),
            Some(Entry::Wildcard("foo.com".to_string()))
        );
        assert_eq!(
            extract_entry("||foo.com^", false),
            Some(Entry::Exact("foo.com".to_string()))
        );
        assert_eq!(
            extract_entry("||tracker.com^$third-party", true),
            Some(Entry::Wildcard("tracker.com".to_string()))
        );
    }

    #[test]
    fn test_extract_entry_star_sugar_respects_flag() {
        assert_eq!(
            extract_entry("*.bar.com", true),
            Some(Entry::Wildcard("bar.com".to_string()))
        );
        assert_eq!(
            extract_entry("*.bar.com", false),
            Some(Entry::Exact("bar.com".to_string()))
        );
    }

    #[test]
    fn test_extract_entry_rejects_junk() {
        assert_eq!(extract_entry("# comment", true), None);
        assert_eq!(extract_entry("", true), None);
        assert_eq!(extract_entry("||*.^", true), None);
        assert_eq!(extract_entry("*.", true), None);
    }

    #[test]
    fn test_extract_entry_inline_comment() {
        assert_eq!(
            extract_entry("ads.example.com # inline comment", true),
            Some(Entry::Exact("ads.example.com".to_string()))
        );
    }

    #[test]
    fn test_entry_to_key() {
        assert_eq!(Entry::Exact("foo.com".to_string()).to_key(), "foo.com");
        assert_eq!(
            Entry::Wildcard("foo.com".to_string()).to_key(),
            "||foo.com^"
        );
    }

    #[test]
    fn test_entry_from_key_and_to_line() {
        assert_eq!(
            Entry::from_key("foo.com"),
            Entry::Exact("foo.com".to_string())
        );
        assert_eq!(
            Entry::from_key("||foo.com^"),
            Entry::Wildcard("foo.com".to_string())
        );
        assert_eq!(Entry::from_key("foo.com").to_line(), "0.0.0.0 foo.com");
        assert_eq!(Entry::from_key("||foo.com^").to_line(), "||foo.com^");
    }

    #[test]
    fn test_key_domain() {
        assert_eq!(key_domain("foo.com"), "foo.com");
        assert_eq!(key_domain("||foo.com^"), "foo.com");
    }

    fn keys(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn sorted_lines(entries: Vec<Entry>) -> Vec<String> {
        let mut lines: Vec<String> = entries.iter().map(Entry::to_line).collect();
        lines.sort();
        lines
    }

    #[test]
    fn test_collapse_abp_output_has_no_duplicates() {
        let entries = collapse_entries(&keys(&["foo.com", "||foo.com^"]), true);
        assert_eq!(sorted_lines(entries), vec!["||foo.com^"]);
    }

    #[test]
    fn test_collapse_abp_output_drops_covered_subdomains() {
        let entries = collapse_entries(
            &keys(&[
                "example.com",
                "ads.example.com",
                "a.b.example.com",
                "other.com",
            ]),
            true,
        );
        assert_eq!(
            sorted_lines(entries),
            vec!["||example.com^", "||other.com^"]
        );
    }

    #[test]
    fn test_collapse_drops_exact_entries_covered_by_wildcards() {
        let entries = collapse_entries(
            &keys(&[
                "||example.com^",
                "example.com",
                "ads.example.com",
                "||cdn.example.com^",
                "other.com",
            ]),
            false,
        );
        assert_eq!(
            sorted_lines(entries),
            vec!["0.0.0.0 other.com", "||example.com^"]
        );
    }

    #[test]
    fn test_collapse_keeps_exact_subdomains_without_wildcard_parent() {
        let entries = collapse_entries(&keys(&["example.com", "ads.example.com"]), false);
        assert_eq!(
            sorted_lines(entries),
            vec!["0.0.0.0 ads.example.com", "0.0.0.0 example.com"]
        );
    }

    #[test]
    fn test_collapse_does_not_match_partial_labels() {
        let entries = collapse_entries(&keys(&["||example.com^", "badexample.com"]), false);
        assert_eq!(
            sorted_lines(entries),
            vec!["0.0.0.0 badexample.com", "||example.com^"]
        );
    }

    #[test]
    fn test_format_num() {
        assert_eq!(format_num(0), "0");
        assert_eq!(format_num(999), "999");
        assert_eq!(format_num(1000), "1,000");
        assert_eq!(format_num(1622550), "1,622,550");
    }
}
