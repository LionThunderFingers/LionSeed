//! Addresses recently dropped from the table, so gossip cannot put them straight back.
//!
//! When the table is full, addresses that never answered are pruned. Peers keep gossiping the same
//! dead addresses, and without a memory of what was pruned each one would come back as "never
//! tried" and be crawled again within minutes instead of at the normal retry interval. Through Tor
//! that is expensive: every onion attempt costs several circuits.
//!
//! This is a pair of Bloom filters in fixed memory. Inserts go into the current one; every
//! `period` the older one is cleared and becomes current, so an entry is remembered for between one
//! and two periods. A false positive only delays a genuinely new address until the next rotation,
//! and real nodes are gossiped again and again, so it costs nothing that matters.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};

/// Bits per filter: 2^24 bits is 2 MiB, about a 1.5% false positive rate at 1.5 million entries.
const BITS: usize = 1 << 24;
const HASHES: u64 = 3;

pub struct RecentlyDropped {
    filters: [Vec<u64>; 2],
    current: usize,
    rotated_at: u64,
    period: u64,
    hasher: RandomState,
}

impl RecentlyDropped {
    pub fn new(period: u64, now: u64) -> RecentlyDropped {
        RecentlyDropped {
            filters: [vec![0; BITS / 64], vec![0; BITS / 64]],
            current: 0,
            rotated_at: now,
            period: period.max(1),
            hasher: RandomState::new(),
        }
    }

    pub fn insert<T: Hash>(&mut self, item: &T, now: u64) {
        self.rotate(now);
        let current = self.current;
        for bit in self.bits(item) {
            self.filters[current][bit / 64] |= 1 << (bit % 64);
        }
    }

    pub fn contains<T: Hash>(&mut self, item: &T, now: u64) -> bool {
        self.rotate(now);
        let bits = self.bits(item);
        self.filters
            .iter()
            .any(|f| bits.iter().all(|&b| f[b / 64] & (1 << (b % 64)) != 0))
    }

    fn rotate(&mut self, now: u64) {
        if now < self.rotated_at + self.period {
            return;
        }
        if now >= self.rotated_at + 2 * self.period {
            // Idle for two periods or more: everything in both filters has expired.
            self.filters[0].fill(0);
            self.filters[1].fill(0);
            self.rotated_at = now;
            return;
        }
        self.current = 1 - self.current;
        self.filters[self.current].fill(0);
        // Step by exactly one period, not to `now`, so a late call does not stretch lifetimes.
        self.rotated_at += self.period;
    }

    fn bits<T: Hash>(&self, item: &T) -> [usize; HASHES as usize] {
        // Double hashing: bit i = h1 + i * h2. h2 is forced odd so the steps never collapse.
        let h1 = self.hasher.hash_one(item);
        let h2 = h1.rotate_left(32).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut out = [0; HASHES as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % BITS as u64) as usize;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_what_was_inserted_and_not_much_else() {
        let mut r = RecentlyDropped::new(100, 0);
        for i in 0..10_000u32 {
            r.insert(&i, 0);
        }
        assert!((0..10_000u32).all(|i| r.contains(&i, 1)));
        let false_hits = (10_000..20_000u32).filter(|i| r.contains(i, 1)).count();
        assert!(false_hits < 10, "{false_hits} false positives");
    }

    #[test]
    fn entries_last_between_one_and_two_periods() {
        let mut r = RecentlyDropped::new(100, 0);
        r.insert(&"a", 10);
        assert!(r.contains(&"a", 99));
        assert!(r.contains(&"a", 150), "survives the first rotation");
        r.insert(&"b", 150);
        assert!(!r.contains(&"a", 200), "gone after the second rotation");
        assert!(r.contains(&"b", 200), "b went into the newer filter");
        assert!(!r.contains(&"b", 300));
    }

    #[test]
    fn a_long_idle_gap_forgets_everything() {
        let mut r = RecentlyDropped::new(100, 0);
        r.insert(&"a", 0);
        assert!(!r.contains(&"a", 1000));
    }
}
