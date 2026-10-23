use anyhow::{bail, Result};
use std::fmt;

pub fn normalize_dns_name(name: &str) -> Result<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        bail!("invalid DNS name");
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || character == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            bail!("invalid DNS name");
        }
    }
    Ok(name)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum MatchKind {
    All,
    DomainAndSubdomains,
    SubdomainsOnly,
}

/// A normalized DNS domain selection pattern shared by proxy routes and DNS
/// rewriting rules.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DomainPattern {
    value: String,
    base: String,
    label_count: usize,
    kind: MatchKind,
}

impl DomainPattern {
    pub fn parse(pattern: &str) -> Result<Self> {
        if pattern == "*" {
            return Ok(Self {
                value: pattern.to_owned(),
                base: String::new(),
                label_count: 0,
                kind: MatchKind::All,
            });
        }

        let (base, kind) = match pattern.strip_prefix("*.") {
            Some(base) => (normalize_dns_name(base)?, MatchKind::SubdomainsOnly),
            None => (normalize_dns_name(pattern)?, MatchKind::DomainAndSubdomains),
        };
        let label_count = base.split('.').count();
        let value = match kind {
            MatchKind::SubdomainsOnly => format!("*.{base}"),
            MatchKind::DomainAndSubdomains => base.clone(),
            MatchKind::All => unreachable!(),
        };
        Ok(Self {
            value,
            base,
            label_count,
            kind,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn matches_normalized_name(&self, name: &str) -> bool {
        self.matches_labels(name.split('.').map(str::as_bytes))
    }

    pub(crate) fn matches_wire_labels(&self, labels: &[Vec<u8>]) -> bool {
        self.matches_labels(labels.iter().map(Vec::as_slice))
    }

    pub(crate) fn specificity(&self) -> (usize, bool) {
        (self.label_count, self.kind == MatchKind::SubdomainsOnly)
    }

    fn matches_labels<'a, I>(&self, labels: I) -> bool
    where
        I: Clone + DoubleEndedIterator<Item = &'a [u8]>,
    {
        if self.kind == MatchKind::All {
            return true;
        }

        let actual_count = labels.clone().count();
        let count_matches = match self.kind {
            MatchKind::All => true,
            MatchKind::DomainAndSubdomains => actual_count >= self.label_count,
            MatchKind::SubdomainsOnly => actual_count > self.label_count,
        };
        count_matches
            && labels
                .rev()
                .take(self.label_count)
                .zip(self.base.rsplit('.'))
                .all(|(actual, wanted)| actual.eq_ignore_ascii_case(wanted.as_bytes()))
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_validates_dns_names() {
        assert_eq!(normalize_dns_name("Example.COM.").unwrap(), "example.com");
        for invalid in ["", ".example", "a..b", "-bad.com", "a/b", "a\nB", "*.x"] {
            assert!(normalize_dns_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn plain_pattern_matches_domain_and_nested_subdomains() {
        let pattern = DomainPattern::parse("Example.COM.").unwrap();
        assert_eq!(pattern.as_str(), "example.com");
        for name in ["example.com", "a.example.com", "b.a.example.com"] {
            assert!(pattern.matches_normalized_name(name), "{name}");
        }
        for name in ["badexample.com", "example.com.evil"] {
            assert!(!pattern.matches_normalized_name(name), "{name}");
        }
    }

    #[test]
    fn wildcard_pattern_matches_nested_subdomains_only() {
        let pattern = DomainPattern::parse("*.Example.COM.").unwrap();
        assert_eq!(pattern.as_str(), "*.example.com");
        for name in ["a.example.com", "b.a.example.com"] {
            assert!(pattern.matches_normalized_name(name), "{name}");
        }
        for name in ["example.com", "badexample.com", "example.com.evil"] {
            assert!(!pattern.matches_normalized_name(name), "{name}");
        }
    }

    #[test]
    fn star_matches_every_name_and_partial_wildcards_are_rejected() {
        let pattern = DomainPattern::parse("*").unwrap();
        for name in ["example.com", "other.test", "a.b.example.org"] {
            assert!(pattern.matches_normalized_name(name), "{name}");
        }
        for invalid in [
            "*.",
            "api*.example.com",
            "api.*.example.com",
            "**.example.com",
        ] {
            assert!(DomainPattern::parse(invalid).is_err(), "{invalid}");
        }
    }
}
