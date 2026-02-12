use regex::Regex;
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

pub fn extract_domain_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }

    let line = COMMENT_RE.replace(line, "");
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // IP-domain format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
    if let Some(caps) = IP_DOMAIN_RE.captures(line) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }

    // AdBlock format: ||domain.com^ or ||domain.com^$third-party
    if let Some(caps) = ADBLOCK_RE.captures(line) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }

    // Plain domain: no spaces, slashes, or question marks
    if !line.contains(' ') && !line.contains('/') && !line.contains('?') {
        return Some(line.to_string());
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
    fn test_extract_ip_domain() {
        assert_eq!(
            extract_domain_from_line("0.0.0.0 ads.example.com"),
            Some("ads.example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_line("127.0.0.1 tracker.com"),
            Some("tracker.com".to_string())
        );
    }

    #[test]
    fn test_extract_adblock() {
        assert_eq!(
            extract_domain_from_line("||ads.example.com^"),
            Some("ads.example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_line("||tracker.com^$third-party"),
            Some("tracker.com".to_string())
        );
    }

    #[test]
    fn test_extract_plain_domain() {
        assert_eq!(
            extract_domain_from_line("ads.example.com"),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_comments() {
        assert_eq!(extract_domain_from_line("# comment"), None);
        assert_eq!(extract_domain_from_line("! comment"), None);
        assert_eq!(
            extract_domain_from_line("ads.example.com # inline comment"),
            Some("ads.example.com".to_string())
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
