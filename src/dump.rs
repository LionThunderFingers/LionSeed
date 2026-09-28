//! The seeder dump: one line per address that has been tried, in the text format of sipa's
//! bitcoin-seeder `dnsseed.dump`, which Knots' `contrib/seeds/makeseeds.py` and the census scripts
//! read. Written to a temporary file and renamed, so readers never see half a dump.
//!
//! The uptime columns count time before LionSeed knew of a node as downtime: each window's figure is
//! scaled by how much of that window has passed since the node was first seen. Without that, a node
//! seen for one day would show 100% over 30 days, far above what other seeders report for the same
//! node, and makeseeds.py's uptime filter (50% over 30 days) would stop meaning anything.

use crate::addr::NetAddr;
use crate::node::{ChainRules, NodeRecord, WINDOWS};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub const HEADER: &str = "# address                                        good  lastSuccess    %(2h)   %(8h)   %(1d)   %(7d)  %(30d)  blocks      svcs  version";

/// Reliability per window as the dump reports it: scaled by the share of the window observed.
pub fn reported_uptime(n: &NodeRecord, now: u64) -> [f64; 5] {
    let observed = now.saturating_sub(n.first_seen) as f64;
    let mut out = n.reliability;
    for (r, window) in out.iter_mut().zip(WINDOWS) {
        *r *= 1.0 - (-observed / window as f64).exp();
    }
    out
}

pub fn line(addr: &NetAddr, n: &NodeRecord, rules: &ChainRules, now: u64) -> String {
    let [r2h, r8h, r1d, r1w, r1m] = reported_uptime(n, now);
    let ua: String = n
        .user_agent
        .chars()
        .filter(|c| *c != '"' && !c.is_control())
        .collect();
    format!(
        "{:<47}  {:4}  {:11}  {:6.2}% {:6.2}% {:6.2}% {:6.2}% {:6.2}%  {:6}  {:08x}  {:5} \"{}\"",
        addr.to_string(),
        i32::from(n.is_good(addr, rules, now)),
        n.last_success,
        r2h * 100.0,
        r8h * 100.0,
        r1d * 100.0,
        r1w * 100.0,
        r1m * 100.0,
        n.height,
        n.services,
        n.protocol_version,
        ua
    )
}

/// Write the dump of every tried address. Returns how many lines were written.
pub fn write<'a>(
    path: &Path,
    nodes: impl Iterator<Item = (&'a NetAddr, &'a NodeRecord)>,
    rules: &ChainRules,
    now: u64,
) -> io::Result<usize> {
    let tmp = path.with_extension("dump.tmp");
    let mut count = 0;
    {
        let mut w = BufWriter::new(File::create(&tmp)?);
        writeln!(w, "{HEADER}")?;
        let mut rows: Vec<(&NetAddr, &NodeRecord)> = nodes.filter(|(_, n)| n.tries > 0).collect();
        // Best first, like the original: good nodes, then by 30-day reliability.
        rows.sort_by(|a, b| {
            let ga = a.1.is_good(a.0, rules, now);
            let gb = b.1.is_good(b.0, rules, now);
            gb.cmp(&ga)
                .then(b.1.reliability[4].total_cmp(&a.1.reliability[4]))
        });
        for (a, n) in rows {
            writeln!(w, "{}", line(a, n, rules, now))?;
            count += 1;
        }
        w.flush()?;
        w.get_ref().sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Handshake, NODE_BLAKE2B, NODE_NETWORK, NODE_WITNESS};

    #[test]
    fn line_matches_the_fields_census_and_makeseeds_read() {
        let a: NetAddr = "1.2.3.4:8333".parse().unwrap();
        let mut n = NodeRecord::from_gossip(0, 0);
        for t in [1000, 1900, 2800] {
            n.record_success(
                t,
                Handshake {
                    services: NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B,
                    height: 974000,
                    protocol_version: 70016,
                    user_agent: "/Satoshi:29.4.2/Knots:20260508/".into(),
                },
            );
        }
        let rules = ChainRules {
            default_port: 8333,
            min_height: 961640,
            max_silence_secs: 3600,
        };
        let l = line(&a, &n, &rules, 3000);
        let f: Vec<&str> = l.split_whitespace().collect();
        assert_eq!(f[0], "1.2.3.4:8333");
        assert_eq!(f[1], "1"); // good
        assert_eq!(f[2], "2800"); // last success
        assert!(f[3].ends_with('%'));
        assert_eq!(f[8], "974000"); // blocks
        assert_eq!(f[9], "10000009"); // services, hex
        assert_eq!(
            u64::from_str_radix(f[9], 16).unwrap(),
            NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B
        );
        assert_eq!(f[10], "70016");
        assert_eq!(f[11], "\"/Satoshi:29.4.2/Knots:20260508/\"");
    }

    #[test]
    fn uptime_counts_time_before_the_node_was_known_as_down() {
        let mut n = NodeRecord::from_gossip(0, 0);
        n.reliability = [1.0; 5];
        let day = 86400;
        let [r2h, _, _, _, r30d] = reported_uptime(&n, day);
        assert!(r2h > 0.99, "a full day covers the 2h window: {r2h}");
        assert!(
            (r30d - (1.0 - (-1.0f64 / 30.0).exp())).abs() < 1e-9,
            "{r30d}"
        );
        assert!(r30d < 0.05, "one day is not 50% of 30 days");
        let [.., r30d] = reported_uptime(&n, 60 * day);
        assert!(r30d > 0.85, "two months covers it: {r30d}");
        assert_eq!(reported_uptime(&n, 0), [0.0; 5], "nothing observed yet");
    }

    #[test]
    fn write_is_atomic_and_skips_untried() {
        let p = std::env::temp_dir().join(format!("lionseed-dump-{}.txt", std::process::id()));
        let rules = ChainRules {
            default_port: 8333,
            min_height: 961640,
            max_silence_secs: 3600,
        };
        let a: NetAddr = "1.2.3.4:8333".parse().unwrap();
        let b: NetAddr = "5.6.7.8:8333".parse().unwrap();
        let mut tried = NodeRecord::from_gossip(0, 0);
        tried.record_failure(10);
        let untried = NodeRecord::from_gossip(0, 0);
        let rows = [(&a, &tried), (&b, &untried)];
        let n = write(&p, rows.iter().map(|(x, y)| (*x, *y)), &rules, 20).unwrap();
        assert_eq!(n, 1);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("# address"));
        assert!(text.contains("1.2.3.4:8333") && !text.contains("5.6.7.8"));
        assert!(!p.with_extension("dump.tmp").exists());
        let _ = std::fs::remove_file(&p);
    }
}
