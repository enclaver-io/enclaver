use std::net::IpAddr;

use anyhow::Result;
use ipnetwork::IpNetwork;

#[derive(Debug)]
struct Pattern(IpNetwork);

impl Pattern {
    fn new(pattern: &str) -> Result<Self> {
        let ipn: IpNetwork = pattern.parse()?;
        Ok(Pattern(ipn))
    }

    fn matches(&self, addr: IpAddr) -> bool {
        self.0.contains(addr)
    }
}

pub struct IpFilter {
    patterns: Vec<Pattern>,
}

impl IpFilter {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn allow_all() -> Self {
        Self {
            patterns: vec![
                Pattern::new("0.0.0.0/0").unwrap(),
                Pattern::new("::/0").unwrap(),
            ],
        }
    }

    pub fn add(&mut self, pattern: &str) -> Result<()> {
        self.patterns.push(Pattern::new(pattern)?);
        Ok(())
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        self.patterns.iter().any(|p| p.matches(addr))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{IpFilter, Pattern};

    struct TestCase {
        pattern: &'static str,
        positives: Vec<&'static str>,
        negatives: Vec<&'static str>,
    }

    #[test]
    fn test_pattern_matching() {
        let cases = vec![
            TestCase {
                pattern: "66.254.33.22",
                positives: vec!["66.254.33.22"],
                negatives: vec!["66.254.33.21"],
            },
            TestCase {
                pattern: "66.254.33.22/32",
                positives: vec!["66.254.33.22"],
                negatives: vec!["66.254.33.21", "66.254.33.23"],
            },
            TestCase {
                pattern: "0.0.0.0/0",
                positives: vec!["66.254.33.22", "1.2.3.4", "255.255.255.255"],
                negatives: vec![],
            },
            TestCase {
                pattern: "66.254.33.22/24",
                positives: vec!["66.254.33.1", "66.254.33.22", "66.254.33.255"],
                negatives: vec!["66.254.34.1", "67.254.33.22", "66.254.32.255"],
            },
            TestCase {
                pattern: "::/0",
                positives: vec![
                    "::",
                    "fc00::1234",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                negatives: vec![],
            },
            // TODO: support IPv4 addresses encoded in IPv6
            // TestCase{
            //    pattern: "::ffff:42fe:2116/124",
            //    positives: vec!["66.254.33.1", "66.254.33.22", "66.254.33.255"],
            //    negatives: vec!["66.254.34.1", "67.254.33.22", "66.254.32.255"],
            // },
        ];

        for tc in &cases {
            let pat = Pattern::new(tc.pattern).unwrap();

            let pos = tc.positives.iter().map(|a| a.parse::<IpAddr>().unwrap());

            for a in pos {
                println!("pattern={:?}, addr={}", pat, a);
                assert!(pat.matches(a));
            }

            let neg = tc.negatives.iter().map(|a| a.parse::<IpAddr>().unwrap());

            for a in neg {
                assert!(!pat.matches(a));
            }
        }
    }

    #[test]
    fn test_ip_filter() {
        let mut df = IpFilter::new();
        df.add("66.254.33.22").unwrap();
        df.add("66.254.34.22/32").unwrap();
        df.add("66.254.35.0/24").unwrap();

        assert!(df.matches("66.254.33.22".parse().unwrap()));
        assert!(df.matches("66.254.34.22".parse().unwrap()));
        assert!(df.matches("66.254.35.22".parse().unwrap()));
        assert!(!df.matches("66.254.33.21".parse().unwrap()));
        assert!(!df.matches("66.254.34.23".parse().unwrap()));
        assert!(!df.matches("66.254.36.23".parse().unwrap()));
    }
}
