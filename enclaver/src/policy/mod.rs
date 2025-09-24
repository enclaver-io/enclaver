pub mod domain_filter;
pub mod ip_filter;

use std::net::IpAddr;

use domain_filter::DomainFilter;
use ip_filter::IpFilter;

pub struct EgressPolicy {
    domain_allow: DomainFilter,
    domain_deny: DomainFilter,
    ip_allow: IpFilter,
    ip_deny: IpFilter,
}

impl EgressPolicy {
    pub fn new(spec: &crate::manifest::Egress) -> Self {
        let (domain_allow, ip_allow) = load_filters(&spec.allow);
        let (domain_deny, ip_deny) = load_filters(&spec.deny);

        Self {
            domain_allow,
            domain_deny,
            ip_allow,
            ip_deny,
        }
    }

    pub fn allow_all() -> Self {
        Self {
            domain_allow: DomainFilter::allow_all(),
            domain_deny: DomainFilter::new(),
            ip_allow: IpFilter::allow_all(),
            ip_deny: IpFilter::new(),
        }
    }

    pub fn is_host_allowed(&self, mut host: &str) -> bool {
        log::trace!("is_host_allowed({host})");

        // An IPv6 address gets passed with the brackets, e.g. [::1],
        // and need to be stripped before converting to an IpAddr
        host = host.strip_prefix('[').unwrap_or(host);
        host = host.strip_suffix(']').unwrap_or(host);

        match host.parse::<IpAddr>() {
            Ok(addr) => self.ip_allow.matches(addr) && !self.ip_deny.matches(addr),
            Err(_) => self.domain_allow.matches(host) && !self.domain_deny.matches(host),
        }
    }
}

fn load_filters(opt_spec: &Option<Vec<String>>) -> (DomainFilter, IpFilter) {
    let mut domains = DomainFilter::new();
    let mut ips = IpFilter::new();

    if let Some(spec) = opt_spec {
        for pattern in spec {
            if ips.add(pattern).is_err() {
                domains.add(pattern);
            }
        }
    }

    (domains, ips)
}
