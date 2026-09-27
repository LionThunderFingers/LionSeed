//! Addresses on every network LionSeed crawls.
//!
//! The text form is the one used in seeder dumps and by Knots' `contrib/seeds/makeseeds.py`:
//! `1.2.3.4:8333`, `[2001:db8::1]:8333`, `<56 chars>.onion:8333`, `<52 chars>.b32.i2p:0`, and CJDNS
//! as a bracketed IPv6 address in fc00::/8.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Which kind of network an address is on. Tor and I2P are only reachable through a local proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Net {
    Ipv4,
    Ipv6,
    Onion,
    I2p,
    Cjdns,
}

impl Net {
    /// Reached through a SOCKS proxy rather than directly.
    pub fn is_proxied(self) -> bool {
        matches!(self, Net::Onion | Net::I2p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Host {
    Ipv4(Ipv4Addr),
    /// Includes CJDNS, which is an IPv6 address in fc00::/8.
    Ipv6(Ipv6Addr),
    /// The 56 base32 characters of a Tor v3 address, lowercase, without ".onion".
    Onion(String),
    /// The 52 base32 characters of an I2P address, lowercase, without ".b32.i2p".
    I2p(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetAddr {
    pub host: Host,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn is_base32(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

impl NetAddr {
    pub fn net(&self) -> Net {
        match &self.host {
            Host::Ipv4(_) => Net::Ipv4,
            Host::Ipv6(ip) if ip.octets()[0] == 0xfc => Net::Cjdns,
            Host::Ipv6(_) => Net::Ipv6,
            Host::Onion(_) => Net::Onion,
            Host::I2p(_) => Net::I2p,
        }
    }

    /// Whether this address is somewhere a public node could actually be listening. Rejects private,
    /// loopback, link-local, documentation and similar ranges, and port 0 outside I2P (where the
    /// port is always 0 by convention).
    pub fn is_routable(&self) -> bool {
        match &self.host {
            Host::Ipv4(ip) => {
                self.port != 0
                    && !(ip.is_private()
                        || ip.is_loopback()
                        || ip.is_link_local()
                        || ip.is_broadcast()
                        || ip.is_documentation()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || ip.octets()[0] == 0
                        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64/10 CGNAT
                        || ip.octets()[0] >= 240)
            }
            Host::Ipv6(ip) => {
                let seg = ip.segments();
                let cjdns = ip.octets()[0] == 0xfc;
                self.port != 0
                    && !(ip.is_loopback()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || (seg[0] & 0xffc0) == 0xfe80 // link-local
                        || (!cjdns && (seg[0] & 0xfe00) == 0xfc00) // unique local, except CJDNS
                        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
                        || ip.to_ipv4_mapped().is_some())
            }
            Host::Onion(s) => self.port != 0 && s.len() == 56 && is_base32(s),
            Host::I2p(s) => s.len() == 52 && is_base32(s),
        }
    }
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ipv4(ip) => write!(f, "{}:{}", ip, self.port),
            Host::Ipv6(ip) => write!(f, "[{}]:{}", ip, self.port),
            Host::Onion(s) => write!(f, "{}.onion:{}", s, self.port),
            Host::I2p(s) => write!(f, "{}.b32.i2p:{}", s, self.port),
        }
    }
}

impl FromStr for NetAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<NetAddr, ParseError> {
        let err = || ParseError(format!("not an address: {s}"));
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (ip, port) = rest.split_once("]:").ok_or_else(err)?;
            (ip, port)
        } else {
            s.rsplit_once(':').ok_or_else(err)?
        };
        let port: u16 = port.parse().map_err(|_| err())?;
        let lower = host.to_ascii_lowercase();
        let host = if let Some(b) = lower.strip_suffix(".onion") {
            Host::Onion(b.to_string())
        } else if let Some(b) = lower.strip_suffix(".b32.i2p") {
            Host::I2p(b.to_string())
        } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
            Host::Ipv4(ip)
        } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
            Host::Ipv6(ip)
        } else {
            return Err(err());
        };
        Ok(NetAddr { host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "wh3cdsnjylvrrhbnis73fyrsy53fyfkajhbf7dlobjccjp5j5ev6ykqd";
    const I2P: &str = "3jj6gov3oweh6dpv3adzxsktk5rvbiyd7s5pcd4atr7ygxwz6ytq";

    fn a(s: &str) -> NetAddr {
        s.parse().unwrap()
    }

    #[test]
    fn round_trips_every_network_in_dump_format() {
        for s in [
            "1.2.3.4:8333",
            "[2001:4860::1]:8333",
            &format!("{ONION}.onion:8333"),
            &format!("{I2P}.b32.i2p:0"),
            "[fc00::1]:8333",
        ] {
            assert_eq!(a(s).to_string(), *s);
        }
    }

    #[test]
    fn classifies_networks() {
        assert_eq!(a("1.2.3.4:8333").net(), Net::Ipv4);
        assert_eq!(a("[2001:4860::1]:8333").net(), Net::Ipv6);
        assert_eq!(a("[fc12::1]:8333").net(), Net::Cjdns);
        assert_eq!(a(&format!("{ONION}.onion:8333")).net(), Net::Onion);
        assert!(a(&format!("{ONION}.onion:8333")).net().is_proxied());
        assert!(!a("1.2.3.4:8333").net().is_proxied());
    }

    #[test]
    fn rejects_unroutable() {
        for s in [
            "10.0.0.1:8333",
            "127.0.0.1:8333",
            "192.168.1.20:8333",
            "100.64.1.1:8333",
            "0.1.2.3:8333",
            "1.2.3.4:0",
            "[::1]:8333",
            "[fe80::1]:8333",
            "[fd00::1]:8333",
            "[2001:db8::1]:8333",
            "[::ffff:1.2.3.4]:8333",
            "short.onion:8333",
        ] {
            assert!(!a(s).is_routable(), "{s} should not be routable");
        }
        for s in [
            "1.2.3.4:8333",
            "[2001:4860::1]:8333",
            "[fc00::1]:8333",
            &format!("{ONION}.onion:8333"),
            &format!("{I2P}.b32.i2p:0"),
        ] {
            assert!(a(s).is_routable(), "{s} should be routable");
        }
    }

    #[test]
    fn parse_errors_are_errors_not_panics() {
        for s in [
            "",
            "1.2.3.4",
            "1.2.3.4:x",
            "[::1",
            "nonsense:8333",
            "[::1]8333",
        ] {
            assert!(s.parse::<NetAddr>().is_err(), "{s} should not parse");
        }
    }
}
