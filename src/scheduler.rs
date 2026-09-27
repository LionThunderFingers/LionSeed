//! When each address is crawled next.
//!
//! Workers pull work: a free worker asks for the next due address in its pool and gets one or is told
//! when to ask again. Nothing loops looking for work, so there is nothing to spin.
//!
//! Each pool (direct, or through the Tor/I2P proxy) has one due-time queue per tier, and tiers are
//! served strictly in priority order: fork nodes first, then never-tried addresses, then failed
//! unknowns due a retry, then non-fork nodes.

use crate::addr::NetAddr;
use crate::node::{Class, NodeRecord};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pool {
    Direct,
    Proxied,
}

impl Pool {
    pub fn for_addr(addr: &NetAddr) -> Pool {
        if addr.net().is_proxied() {
            Pool::Proxied
        } else {
            Pool::Direct
        }
    }
}

/// Priority order is the declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    Fork,
    NewUnknown,
    RetryUnknown,
    NonFork,
}

const TIERS: [Tier; 4] = [
    Tier::Fork,
    Tier::NewUnknown,
    Tier::RetryUnknown,
    Tier::NonFork,
];

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub fork_secs: u64,
    pub unknown_retry_secs: u64,
    pub nonfork_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> RetryPolicy {
        RetryPolicy {
            fork_secs: 15 * 60,
            unknown_retry_secs: 6 * 3600,
            nonfork_secs: 24 * 3600,
        }
    }
}

/// Which tier a node belongs in and when it is next due.
pub fn due_for(node: &NodeRecord, policy: &RetryPolicy) -> (Tier, u64) {
    match node.class {
        Class::Fork => (Tier::Fork, node.last_try + policy.fork_secs),
        Class::NonFork => (Tier::NonFork, node.last_try + policy.nonfork_secs),
        Class::Unknown if node.last_try == 0 => (Tier::NewUnknown, 0),
        Class::Unknown => (
            Tier::RetryUnknown,
            node.last_try + policy.unknown_retry_secs,
        ),
    }
}

/// What a worker should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Crawl(NetAddr),
    /// Nothing due yet; the earliest thing becomes due at this time.
    WaitUntil(u64),
    /// Nothing queued in this pool at all.
    Idle,
}

/// Min-heap of (due, seq, generation, addr). seq keeps equal due times first in, first out.
type Queue = BinaryHeap<Reverse<(u64, u64, u64, NetAddr)>>;

#[derive(Default)]
pub struct Scheduler {
    queues: HashMap<(Pool, Tier), Queue>,
    // The generation of each address's one live queue entry. Entries with an older generation are
    // stale (the address was rescheduled) and are dropped when they surface.
    live: HashMap<NetAddr, u64>,
    in_flight: HashMap<NetAddr, Pool>,
    seq: u64,
}

impl Scheduler {
    pub fn new() -> Scheduler {
        Scheduler::default()
    }

    /// Queue `addr` in `tier`, due at `due`. Replaces any earlier entry for the same address. Ignored
    /// while the address is in flight: its worker reschedules it when it finishes.
    pub fn schedule(&mut self, addr: NetAddr, tier: Tier, due: u64) {
        if self.in_flight.contains_key(&addr) {
            return;
        }
        self.seq += 1;
        let generation = self.seq;
        self.live.insert(addr.clone(), generation);
        let pool = Pool::for_addr(&addr);
        self.queues
            .entry((pool, tier))
            .or_default()
            .push(Reverse((due, self.seq, generation, addr)));
    }

    /// Hand the next due address in `pool` to a worker. The address counts as in flight until
    /// `finished` is called for it.
    pub fn next(&mut self, pool: Pool, now: u64) -> Next {
        let mut earliest: Option<u64> = None;
        for tier in TIERS {
            let Some(heap) = self.queues.get_mut(&(pool, tier)) else {
                continue;
            };
            while let Some(Reverse((due, _, generation, addr))) = heap.peek() {
                if self.live.get(addr) != Some(generation) {
                    heap.pop(); // stale entry
                    continue;
                }
                if *due <= now {
                    let Reverse((_, _, _, addr)) = heap.pop().expect("peeked");
                    self.live.remove(&addr);
                    self.in_flight.insert(addr.clone(), pool);
                    return Next::Crawl(addr);
                }
                earliest = Some(earliest.map_or(*due, |e| e.min(*due)));
                break;
            }
        }
        match earliest {
            Some(t) => Next::WaitUntil(t),
            None => Next::Idle,
        }
    }

    /// Drop any queued entry for `addr` (it was pruned from the store).
    pub fn forget(&mut self, addr: &NetAddr) {
        self.live.remove(addr);
    }

    /// The worker is done with `addr`. The caller reschedules it from its updated record.
    pub fn finished(&mut self, addr: &NetAddr) {
        self.in_flight.remove(addr);
    }

    pub fn in_flight(&self, pool: Pool) -> usize {
        self.in_flight.values().filter(|p| **p == pool).count()
    }

    pub fn queued(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Handshake, NODE_BLAKE2B, NODE_NETWORK};

    fn a(s: &str) -> NetAddr {
        s.parse().unwrap()
    }
    const ONION: &str = "wh3cdsnjylvrrhbnis73fyrsy53fyfkajhbf7dlobjccjp5j5ev6ykqd.onion:8333";

    #[test]
    fn fork_first_then_new_then_retry_then_nonfork() {
        let mut s = Scheduler::new();
        s.schedule(a("4.4.4.4:8333"), Tier::NonFork, 10);
        s.schedule(a("3.3.3.3:8333"), Tier::RetryUnknown, 10);
        s.schedule(a("2.2.2.2:8333"), Tier::NewUnknown, 0);
        s.schedule(a("1.1.1.1:8333"), Tier::Fork, 10);
        let order: Vec<_> = (0..4)
            .map(|_| match s.next(Pool::Direct, 100) {
                Next::Crawl(x) => x.to_string(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            order,
            [
                "1.1.1.1:8333",
                "2.2.2.2:8333",
                "3.3.3.3:8333",
                "4.4.4.4:8333"
            ]
        );
        assert_eq!(s.next(Pool::Direct, 100), Next::Idle);
    }

    #[test]
    fn nothing_before_its_time_and_says_when() {
        let mut s = Scheduler::new();
        s.schedule(a("1.1.1.1:8333"), Tier::Fork, 900);
        s.schedule(a("2.2.2.2:8333"), Tier::NonFork, 500);
        assert_eq!(s.next(Pool::Direct, 100), Next::WaitUntil(500));
        assert_eq!(s.next(Pool::Direct, 900), Next::Crawl(a("1.1.1.1:8333")));
    }

    #[test]
    fn a_due_fork_node_beats_a_long_backlog_of_new_addresses() {
        let mut s = Scheduler::new();
        for i in 0..10_000u32 {
            let ip = std::net::Ipv4Addr::from(0x0b00_0000 + i);
            s.schedule(
                NetAddr {
                    host: crate::addr::Host::Ipv4(ip),
                    port: 8333,
                },
                Tier::NewUnknown,
                0,
            );
        }
        s.schedule(a("1.1.1.1:8333"), Tier::Fork, 50);
        assert_eq!(s.next(Pool::Direct, 60), Next::Crawl(a("1.1.1.1:8333")));
    }

    #[test]
    fn pools_are_separate() {
        let mut s = Scheduler::new();
        s.schedule(a(ONION), Tier::Fork, 0);
        s.schedule(a("1.1.1.1:8333"), Tier::NewUnknown, 0);
        assert_eq!(s.next(Pool::Direct, 1), Next::Crawl(a("1.1.1.1:8333")));
        assert_eq!(s.next(Pool::Direct, 1), Next::Idle);
        assert_eq!(s.next(Pool::Proxied, 1), Next::Crawl(a(ONION)));
    }

    #[test]
    fn rescheduling_replaces_and_in_flight_is_not_handed_out_twice() {
        let mut s = Scheduler::new();
        s.schedule(a("1.1.1.1:8333"), Tier::NewUnknown, 0);
        s.schedule(a("1.1.1.1:8333"), Tier::Fork, 5000); // replaces the first entry
        assert_eq!(s.next(Pool::Direct, 1), Next::WaitUntil(5000));
        assert_eq!(s.next(Pool::Direct, 5000), Next::Crawl(a("1.1.1.1:8333")));
        assert_eq!(s.in_flight(Pool::Direct), 1);
        // gossip mentioning it again while in flight must not queue a second crawl
        s.schedule(a("1.1.1.1:8333"), Tier::NewUnknown, 0);
        assert_eq!(s.next(Pool::Direct, 5001), Next::Idle);
        s.finished(&a("1.1.1.1:8333"));
        assert_eq!(s.in_flight(Pool::Direct), 0);
        s.schedule(a("1.1.1.1:8333"), Tier::Fork, 5900);
        assert_eq!(s.next(Pool::Direct, 5900), Next::Crawl(a("1.1.1.1:8333")));
    }

    #[test]
    fn due_times_follow_the_policy() {
        let p = RetryPolicy::default();
        let mut n = NodeRecord::from_gossip(NODE_NETWORK | NODE_BLAKE2B, 0);
        assert_eq!(due_for(&n, &p), (Tier::NewUnknown, 0)); // gossip claim is still unknown
        n.record_failure(100);
        assert_eq!(due_for(&n, &p), (Tier::RetryUnknown, 100 + 6 * 3600));
        let hs = Handshake {
            services: NODE_NETWORK | NODE_BLAKE2B,
            height: 974000,
            protocol_version: 70016,
            user_agent: String::new(),
        };
        n.record_success(200, hs.clone());
        assert_eq!(due_for(&n, &p), (Tier::Fork, 200 + 900));
        n.record_success(
            300,
            Handshake {
                services: NODE_NETWORK,
                ..hs
            },
        );
        assert_eq!(due_for(&n, &p), (Tier::NonFork, 300 + 86400));
    }
}
