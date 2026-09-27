//! The seeder dump: one line per address that has been tried, in the text format of sipa's
//! bitcoin-seeder `dnsseed.dump`, which Knots' `contrib/seeds/makeseeds.py` and the census scripts
//! read. Written to a temporary file and renamed, so readers never see half a dump.

use crate::addr::NetAddr;
use crate::node::{ChainRules, NodeRecord};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub const HEADER: &str = "# address                                        good  lastSuccess    %(2h)   %(8h)   %(1d)   %(7d)  %(30d)  blocks      svcs  version";

pub fn line(addr: &NetAddr, n: &NodeRecord, rules: &ChainRules, now: u64) -> String {
    let [r2h, r8h, r1d, r1w, r1m] = n.reliability;
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
