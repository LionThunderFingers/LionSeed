//! The table of every address LionSeed knows, and its snapshot on disk.
//!
//! Everything lives in memory. A snapshot is written every few minutes to a temporary file which is
//! then renamed over the old one, so a crash or power cut leaves either the previous snapshot or the
//! new one, never half of one.

use crate::addr::NetAddr;
use crate::node::{Class, NodeRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;

const MAGIC: [u8; 4] = *b"LSNP";
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Snapshot {
    magic: [u8; 4],
    version: u32,
    nodes: Vec<(NetAddr, NodeRecord)>,
}

#[derive(Clone, Default)]
pub struct Store {
    nodes: HashMap<NetAddr, NodeRecord>,
}

impl Store {
    pub fn new() -> Store {
        Store::default()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, addr: &NetAddr) -> Option<&NodeRecord> {
        self.nodes.get(addr)
    }

    pub fn get_mut(&mut self, addr: &NetAddr) -> Option<&mut NodeRecord> {
        self.nodes.get_mut(addr)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NetAddr, &NodeRecord)> {
        self.nodes.iter()
    }

    /// Learn about `addr` from gossip. Returns true if it is new. Unroutable addresses are refused.
    /// A known address is left alone: gossip never overwrites what a handshake established.
    pub fn add_gossip(&mut self, addr: NetAddr, services: u64, now: u64) -> bool {
        self.add(addr, services, now, false)
    }

    /// As `add_gossip`, optionally accepting unroutable addresses (operator-given seed nodes on a
    /// private network, and tests on loopback).
    pub fn add(&mut self, addr: NetAddr, services: u64, now: u64, allow_unroutable: bool) -> bool {
        if (!allow_unroutable && !addr.is_routable()) || self.nodes.contains_key(&addr) {
            return false;
        }
        self.nodes
            .insert(addr, NodeRecord::from_gossip(services, now));
        true
    }

    /// Keep the table at most `cap` entries by dropping addresses that have never answered, most
    /// failed attempts first, then oldest. Fork and non-fork nodes are never dropped here. Returns
    /// the dropped addresses so the caller can forget them elsewhere too.
    pub fn prune(&mut self, cap: usize) -> Vec<NetAddr> {
        if self.nodes.len() <= cap {
            return Vec::new();
        }
        let mut candidates: Vec<(u32, u64, NetAddr)> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.class == Class::Unknown && n.successes == 0)
            .map(|(a, n)| (n.tries, n.first_seen, a.clone()))
            .collect();
        // most tries first, then oldest first_seen
        candidates.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
        let excess = self.nodes.len() - cap;
        let dropped: Vec<NetAddr> = candidates.into_iter().take(excess).map(|c| c.2).collect();
        for a in &dropped {
            self.nodes.remove(a);
        }
        dropped
    }

    /// Write the snapshot atomically: temporary file, flush to disk, rename.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("snapshot.tmp");
        {
            let file = File::create(&tmp)?;
            let mut w = BufWriter::new(file);
            let snap = Snapshot {
                magic: MAGIC,
                version: FORMAT_VERSION,
                nodes: self
                    .nodes
                    .iter()
                    .map(|(a, n)| (a.clone(), n.clone()))
                    .collect(),
            };
            bincode::serialize_into(&mut w, &snap).map_err(io::Error::other)?;
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Load a snapshot. A missing file is an empty store; a damaged or foreign file is an error the
    /// caller decides about (the binary logs it and starts empty rather than crash-looping).
    pub fn load(path: &Path) -> io::Result<Store> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Store::new()),
            Err(e) => return Err(e),
        };
        let snap: Snapshot = bincode::deserialize_from(BufReader::new(file))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if snap.magic != MAGIC || snap.version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a LionSeed snapshot of this version",
            ));
        }
        Ok(Store {
            nodes: snap.nodes.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Handshake, NODE_BLAKE2B, NODE_NETWORK};

    fn a(s: &str) -> NetAddr {
        s.parse().unwrap()
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "lionseed-test-{}-{}.snapshot",
            name,
            std::process::id()
        ));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn gossip_adds_once_and_never_overwrites() {
        let mut s = Store::new();
        assert!(s.add_gossip(a("1.2.3.4:8333"), NODE_NETWORK, 10));
        s.get_mut(&a("1.2.3.4:8333")).unwrap().record_success(
            20,
            Handshake {
                services: NODE_NETWORK | NODE_BLAKE2B,
                height: 974000,
                protocol_version: 70016,
                user_agent: String::new(),
            },
        );
        assert!(!s.add_gossip(a("1.2.3.4:8333"), 0, 30));
        assert_eq!(s.get(&a("1.2.3.4:8333")).unwrap().class, Class::Fork);
    }

    #[test]
    fn unroutable_gossip_is_refused() {
        let mut s = Store::new();
        assert!(!s.add_gossip(a("10.0.0.1:8333"), NODE_NETWORK, 10));
        assert!(!s.add_gossip(a("1.2.3.4:0"), NODE_NETWORK, 10));
        assert!(s.is_empty());
    }

    #[test]
    fn snapshot_round_trip() {
        let p = tmp("roundtrip");
        let mut s = Store::new();
        s.add_gossip(a("1.2.3.4:8333"), NODE_NETWORK, 10);
        s.add_gossip(
            a("wh3cdsnjylvrrhbnis73fyrsy53fyfkajhbf7dlobjccjp5j5ev6ykqd.onion:8333"),
            0,
            11,
        );
        s.get_mut(&a("1.2.3.4:8333")).unwrap().record_failure(50);
        s.save(&p).unwrap();
        let back = Store::load(&p).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(&a("1.2.3.4:8333")), s.get(&a("1.2.3.4:8333")));
        assert!(!p.with_extension("snapshot.tmp").exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn missing_snapshot_is_empty_and_garbage_is_an_error() {
        let p = tmp("missing");
        assert!(Store::load(&p).unwrap().is_empty());
        fs::write(&p, b"definitely not a snapshot").unwrap();
        assert!(Store::load(&p).is_err());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn prune_drops_only_never_answered_most_failed_first() {
        let mut s = Store::new();
        s.add_gossip(a("1.1.1.1:8333"), 0, 1); // will fail 3 times
        s.add_gossip(a("2.2.2.2:8333"), 0, 2); // never tried
        s.add_gossip(a("3.3.3.3:8333"), 0, 3); // will be a fork node
        for t in [10, 20, 30] {
            s.get_mut(&a("1.1.1.1:8333")).unwrap().record_failure(t);
        }
        s.get_mut(&a("3.3.3.3:8333")).unwrap().record_success(
            40,
            Handshake {
                services: NODE_NETWORK | NODE_BLAKE2B,
                height: 974000,
                protocol_version: 70016,
                user_agent: String::new(),
            },
        );
        let dropped = s.prune(2);
        assert_eq!(dropped, vec![a("1.1.1.1:8333")]);
        let dropped = s.prune(0);
        assert_eq!(dropped, vec![a("2.2.2.2:8333")]); // fork node survives even at cap 0
        assert_eq!(s.len(), 1);
    }
}
