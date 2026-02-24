enum PatternPart {
    Superwild,
    Wild,
    Named(String),
}

impl PatternPart {
    fn new(part: &str) -> Self {
        match part {
            "**" => Self::Superwild,
            "*" => Self::Wild,
            _ => Self::Named(part.to_ascii_lowercase()),
        }
    }
}

struct Pattern(Vec<PatternPart>);

impl Pattern {
    fn new(pat: &str) -> Self {
        let parts = pat.split('.').map(PatternPart::new).rev().collect();

        Self(parts)
    }

    fn matches(&self, query: &Domain) -> bool {
        let mut pat_iter = self.0.iter();
        let mut q_iter = query.0.iter();

        loop {
            match pat_iter.next() {
                Some(pat) => {
                    let q = if let Some(q) = q_iter.next() {
                        q
                    } else {
                        return false;
                    };

                    match pat {
                        PatternPart::Superwild => return true,
                        PatternPart::Wild => continue,
                        PatternPart::Named(part) => {
                            if part == q {
                                continue;
                            } else {
                                return false;
                            }
                        }
                    }
                }
                None => {
                    // the pattern is exhausted, ensure that the q is also exhausted
                    return q_iter.next().is_none();
                }
            }
        }
    }
}

struct Domain(Vec<String>);

impl Domain {
    fn new(dom: &str) -> Self {
        let parts = dom.split('.').map(str::to_ascii_lowercase).rev().collect();

        Self(parts)
    }
}

pub struct DomainFilter {
    patterns: Vec<Pattern>,
}

impl DomainFilter {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn allow_all() -> Self {
        Self {
            patterns: vec![Pattern::new("**")],
        }
    }

    pub fn add(&mut self, pattern: &str) {
        self.patterns.push(Pattern::new(pattern));
    }

    pub fn matches(&self, domain: &str) -> bool {
        let dom = Domain::new(domain);

        self.patterns.iter().any(|pat| pat.matches(&dom))
    }
}

#[cfg(test)]
mod tests {

    use super::{Domain, DomainFilter, Pattern};

    struct TestCase {
        pattern: &'static str,
        positives: Vec<&'static str>,
        negatives: Vec<&'static str>,
    }

    #[test]
    fn test_pattern_matching() {
        let cases = vec![
            TestCase {
                pattern: "example.com",
                positives: vec!["example.com", "Example.COM"],
                negatives: vec![
                    "example.net",
                    ".example.com",
                    "foo.com",
                    "",
                    "abc.example.com",
                    "example.",
                ],
            },
            TestCase {
                pattern: "*.com",
                positives: vec!["example.com", "cnn.CoM"],
                negatives: vec![
                    "example.net",
                    "",
                    "news.ycombinator.com",
                    "beta.client1.saas.com",
                    "example.",
                ],
            },
            TestCase {
                pattern: "foo.*.com",
                positives: vec!["foo.example.com"],
                negatives: vec!["example.net", "", "example.", "foo.bar.example.com", ".com"],
            },
            TestCase {
                pattern: "**.amazonaws.com",
                positives: vec!["kms.us-east-1.amazonaws.com", "s3.amazonaws.com"],
                negatives: vec!["amazonaws.com", "", "example.com"],
            },
        ];

        for tc in &cases {
            let pat = Pattern::new(tc.pattern);

            let pos = tc.positives.iter().map(|d| Domain::new(d));

            for d in pos {
                assert!(pat.matches(&d));
            }

            let neg = tc.negatives.iter().map(|d| Domain::new(d));

            for d in neg {
                assert!(!pat.matches(&d));
            }
        }
    }

    #[test]
    fn test_domain_filter() {
        let mut df = DomainFilter::new();
        df.add("example.com");
        df.add("*.net");
        df.add("foo.*.com");
        df.add("**.amazonaws.com");

        assert!(df.matches("example.com"));
        assert!(!df.matches("cnn.com"));
        assert!(df.matches("example.net"));
        assert!(!df.matches("foo.bar.org"));
        assert!(df.matches("kms.amazonaws.com"));
        assert!(df.matches("kms.us-east-1.amazonaws.com"));
    }
}
