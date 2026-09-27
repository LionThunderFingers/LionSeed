//! What LionSeed knows about one address, and whether it is good enough to hand out.
//!
//! The rule that matters most: a node's class and services only ever come from a successful VERSION
//! handshake with that node. Service bits seen in addr gossip are kept for information but never
//! make a node a fork node.

use crate::addr::{Net, NetAddr};
use serde::{Deserialize, Serialize};

pub const NODE_NETWORK: u64 = 1;
pub const NODE_WITNESS: u64 = 1 << 3;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;
pub const NODE_BLAKE2B: u64 = 1 << 28;

/// The lowest protocol version we consider usable (same floor as dnsseedrs and sipa's seeder).
pub const MIN_PROTOCOL_VERSION: u32 = 70001;

/// Reliability windows: 2 hours, 8 hours, 1 day, 1 week, 1 month.
pub const WINDOWS: [u64; 5] = [2 * 3600, 8 * 3600, 86400, 7 * 86400, 30 * 86400];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Class {
    /// Never completed a handshake. Whatever gossip claimed, nothing is proven.
    Unknown,
    /// Completed a handshake without advertising NODE_BLAKE2B.
    NonFork,
    /// Completed a handshake advertising NODE_BLAKE2B.
    Fork,
}

/// What a successful VERSION handshake told us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub services: u64,
    pub height: i32,
    pub protocol_version: u32,
    pub user_agent: String,
}

/// Chain-level rules for what may be served.
#[derive(Clone, Debug)]
pub struct ChainRules {
    pub default_port: u16,
    /// The BLAKE2b activation height. Nodes reporting less are not served.
    pub min_height: i32,
    /// A node whose last successful handshake is older than this is not served, whatever its
    /// longer-window reliability says. With fork nodes re-checked every 15 minutes, an hour is four
    /// missed checks in a row.
    pub max_silence_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub class: Class,
    /// Services from the most recent successful handshake. 0 until the first one.
    pub services: u64,
    /// Services claimed in addr gossip. Informational only.
    pub gossip_services: u64,
    pub height: i32,
    pub protocol_version: u32,
    pub user_agent: String,
    pub first_seen: u64,
    /// Start time of the most recent attempt (0 = never tried).
    pub last_try: u64,
    /// Time of the most recent successful handshake (0 = never).
    pub last_success: u64,
    /// When we last asked this node for addresses (0 = never).
    pub last_getaddr: u64,
    pub tries: u32,
    pub successes: u32,
    /// Exponentially weighted success rate per window in `WINDOWS`.
    pub reliability: [f64; 5],
}

impl NodeRecord {
    pub fn from_gossip(gossip_services: u64, now: u64) -> NodeRecord {
        NodeRecord {
            class: Class::Unknown,
            services: 0,
            gossip_services,
            height: 0,
            protocol_version: 0,
            user_agent: String::new(),
            first_seen: now,
            last_try: 0,
            last_success: 0,
            last_getaddr: 0,
            tries: 0,
            successes: 0,
            reliability: [0.0; 5],
        }
    }

    /// Time-aware exponential moving average: the longer since the previous attempt, the more this
    /// result counts. A first attempt counts fully.
    fn update_reliability(&mut self, success: bool, now: u64) {
        let x = if success { 1.0 } else { 0.0 };
        let age = if self.last_try == 0 {
            u64::MAX
        } else {
            now.saturating_sub(self.last_try)
        };
        for (r, window) in self.reliability.iter_mut().zip(WINDOWS) {
            let alpha = if age == u64::MAX {
                1.0
            } else {
                1.0 - (-(age as f64) / window as f64).exp()
            };
            *r = alpha * x + (1.0 - alpha) * *r;
        }
    }

    /// Record a successful handshake at `now`. This is the only place a node's class can change.
    pub fn record_success(&mut self, now: u64, hs: Handshake) {
        self.update_reliability(true, now);
        self.last_try = now;
        self.last_success = now;
        self.tries = self.tries.saturating_add(1);
        self.successes = self.successes.saturating_add(1);
        self.class = if hs.services & NODE_BLAKE2B != 0 {
            Class::Fork
        } else {
            Class::NonFork
        };
        self.services = hs.services;
        self.height = hs.height;
        self.protocol_version = hs.protocol_version;
        self.user_agent = hs.user_agent;
    }

    /// Record a failed attempt at `now`. Class and services are left as they were: a node that goes
    /// offline is still the kind of node it was, it is just not good while it is down.
    pub fn record_failure(&mut self, now: u64) {
        self.update_reliability(false, now);
        self.last_try = now;
        self.tries = self.tries.saturating_add(1);
    }

    /// Whether this node may be handed out to clients at `now`.
    pub fn is_good(&self, addr: &NetAddr, rules: &ChainRules, now: u64) -> bool {
        if self.class != Class::Fork || self.successes == 0 {
            return false;
        }
        // Freshness first: the reliability windows below are long, and a node that went away an
        // hour ago must not keep being handed out on the strength of its past.
        if now.saturating_sub(self.last_success) > rules.max_silence_secs {
            return false;
        }
        if addr.net() != Net::I2p && addr.port != rules.default_port {
            return false;
        }
        if self.services & NODE_NETWORK == 0
            || self.protocol_version < MIN_PROTOCOL_VERSION
            || self.height < rules.min_height
        {
            return false;
        }
        let [r2h, r8h, r1d, r1w, r1m] = self.reliability;
        (r2h > 0.85 && self.tries > 2)
            || (r8h > 0.70 && self.tries > 4)
            || (r1d > 0.55 && self.tries > 8)
            || (r1w > 0.45 && self.tries > 16)
            || (r1m > 0.35 && self.tries > 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 3000;

    fn rules() -> ChainRules {
        ChainRules {
            default_port: 8333,
            min_height: 961640,
            max_silence_secs: 3600,
        }
    }

    fn addr() -> NetAddr {
        "1.2.3.4:8333".parse().unwrap()
    }

    fn fork_hs() -> Handshake {
        Handshake {
            services: NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B,
            height: 974000,
            protocol_version: 70016,
            user_agent: "/Satoshi:29.4.2/Knots:20260508/".into(),
        }
    }

    fn plain_hs() -> Handshake {
        Handshake {
            services: NODE_NETWORK | NODE_WITNESS,
            ..fork_hs()
        }
    }

    #[test]
    fn gossip_claims_never_make_a_fork_node() {
        let n = NodeRecord::from_gossip(NODE_NETWORK | NODE_BLAKE2B, 100);
        assert_eq!(n.class, Class::Unknown);
        assert!(!n.is_good(&addr(), &rules(), NOW));
    }

    #[test]
    fn handshake_sets_class_both_ways() {
        let mut n = NodeRecord::from_gossip(0, 0);
        n.record_success(1000, fork_hs());
        assert_eq!(n.class, Class::Fork);
        n.record_success(2000, plain_hs());
        assert_eq!(n.class, Class::NonFork);
        n.record_success(3000, fork_hs());
        assert_eq!(n.class, Class::Fork);
    }

    #[test]
    fn failure_keeps_class_and_services() {
        let mut n = NodeRecord::from_gossip(0, 0);
        n.record_success(1000, fork_hs());
        n.record_failure(2000);
        assert_eq!(n.class, Class::Fork);
        assert_eq!(n.services, fork_hs().services);
        assert_eq!(n.tries, 2);
        assert_eq!(n.successes, 1);
    }

    #[test]
    fn becomes_good_after_three_quick_successes() {
        let mut n = NodeRecord::from_gossip(0, 0);
        for t in [1000, 1900, 2800] {
            assert!(!n.is_good(&addr(), &rules(), NOW));
            n.record_success(t, fork_hs());
        }
        assert!(n.is_good(&addr(), &rules(), NOW));
    }

    fn good_fork() -> NodeRecord {
        let mut n = NodeRecord::from_gossip(0, 0);
        for t in [1000, 1900, 2800] {
            n.record_success(t, fork_hs());
        }
        n
    }

    #[test]
    fn not_good_for_each_disqualifier() {
        let r = rules();
        let mut low = good_fork();
        low.height = 961639;
        assert!(!low.is_good(&addr(), &r, NOW));

        let mut old = good_fork();
        old.protocol_version = 70000;
        assert!(!old.is_good(&addr(), &r, NOW));

        let mut limited = good_fork();
        limited.services = NODE_NETWORK_LIMITED | NODE_BLAKE2B;
        assert!(!limited.is_good(&addr(), &r, NOW));

        let odd_port: NetAddr = "1.2.3.4:9333".parse().unwrap();
        assert!(!good_fork().is_good(&odd_port, &r, NOW));

        let mut plain = good_fork();
        plain.record_success(3700, plain_hs());
        assert!(!plain.is_good(&addr(), &r, NOW));
    }

    #[test]
    fn a_node_that_goes_down_stops_being_good() {
        let mut n = good_fork();
        let mut t = 2800;
        for _ in 0..4 {
            t += 900;
            n.record_failure(t);
        }
        // Last success was at 2800; an hour and a bit later it is no longer served.
        assert!(n.is_good(&addr(), &rules(), 2800 + 3600));
        assert!(!n.is_good(&addr(), &rules(), t + 1));
    }

    #[test]
    fn user_agent_does_not_matter() {
        let mut n = NodeRecord::from_gossip(0, 0);
        for t in [1000, 1900, 2800] {
            n.record_success(
                t,
                Handshake {
                    user_agent: "/Satoshi:29.4.2(BIP110 meow miao)/Knots:20260508/".into(),
                    ..fork_hs()
                },
            );
        }
        assert!(n.is_good(&addr(), &rules(), NOW));
    }

    #[test]
    fn i2p_port_zero_is_fine() {
        let i2p: NetAddr = "3jj6gov3oweh6dpv3adzxsktk5rvbiyd7s5pcd4atr7ygxwz6ytq.b32.i2p:0"
            .parse()
            .unwrap();
        assert!(good_fork().is_good(&i2p, &rules(), NOW));
    }
}
