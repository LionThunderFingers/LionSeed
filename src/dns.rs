//! A small authoritative DNS server for the seed zone.
//!
//! Answers A, AAAA, NS and SOA for the seed name and its `x<hex>` service-filter subdomains over UDP
//! and TCP. Everything else inside the zone is NXDOMAIN, anything outside it is REFUSED. Answers come
//! from a snapshot of good nodes that the engine refreshes; answering never touches crawler state.
//! Each source address is rate limited so the server cannot be used as an amplifier.

use crate::addr::{Host, NetAddr};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

const RCODE_OK: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;

/// Address records per answer: fits comfortably in a 512-byte UDP reply.
pub const MAX_A: usize = 24;
pub const MAX_AAAA: usize = 12;

#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// The seed name, e.g. seed.example.org (lowercase, no trailing dot).
    pub host: String,
    /// This server's own name, which the NS record points at.
    pub ns: String,
    /// Contact address for the SOA record, as a mail address (user@example.org).
    pub mbox: String,
    pub ttl: u32,
    pub ns_ttl: u32,
    /// Queries per second allowed per source address (burst of twice this).
    pub rate_per_sec: f64,
}

/// The nodes currently being handed out, with their services.
#[derive(Default, Clone, Debug)]
pub struct Answers {
    pub nodes: Vec<(NetAddr, u64)>,
    pub serial: u32,
}

pub type SharedAnswers = Arc<RwLock<Answers>>;

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Read a question name (no compression is allowed in questions we accept). Returns the lowercase
/// dotted name and the offset after it.
fn read_qname(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut total = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointer or invalid length in a question
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    Some((labels.join("."), pos))
}

/// Pick up to `max` addresses of one family from `nodes` that have every bit of `filter`, at most
/// one per /16 (IPv4) or /32 (IPv6), in random order.
fn pick(nodes: &[(NetAddr, u64)], filter: u64, v6: bool, max: usize, seed: u64) -> Vec<IpAddr> {
    let mut eligible: Vec<IpAddr> = nodes
        .iter()
        .filter(|(_, s)| s & filter == filter)
        .filter_map(|(a, _)| match &a.host {
            Host::Ipv4(ip) if !v6 => Some(IpAddr::V4(*ip)),
            Host::Ipv6(ip) if v6 && ip.octets()[0] != 0xfc => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .collect();
    // Fisher-Yates with a small xorshift; cryptographic quality is not needed here.
    let mut x = seed | 1;
    for i in (1..eligible.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        eligible.swap(i, (x % (i as u64 + 1)) as usize);
    }
    let mut groups = HashSet::new();
    let mut out = Vec::new();
    for ip in eligible {
        let group = match ip {
            IpAddr::V4(v) => u64::from(u32::from(v) >> 16),
            IpAddr::V6(v) => u64::from(u128::from(v).wrapping_shr(96) as u32) | 1 << 40,
        };
        if groups.insert(group) {
            out.push(ip);
            if out.len() == max {
                break;
            }
        }
    }
    out
}

/// Parse the leftmost label of a name inside the zone as a service filter: "x9" -> 0x9.
fn parse_filter(label: &str) -> Option<u64> {
    let hex = label.strip_prefix('x')?;
    if hex.is_empty() || hex.len() > 16 {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// Build the reply to one query. Returns None for things not worth answering at all (not a query,
/// or too short to carry an ID).
pub fn answer(query: &[u8], cfg: &DnsConfig, answers: &Answers, random: u64) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None; // too short, or a response rather than a query
    }
    let id = [query[0], query[1]];
    let rd = query[2] & 0x01;
    let opcode = (query[2] >> 3) & 0x0f;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    let mut reply = Vec::with_capacity(512);
    let header = |r: &mut Vec<u8>, rcode: u8, an: u16, ns: u16, aa: bool, qd: u16| {
        r.clear();
        r.extend_from_slice(&id);
        r.push(0x80 | (opcode << 3) | if aa { 0x04 } else { 0 } | rd);
        r.push(rcode);
        r.extend_from_slice(&qd.to_be_bytes());
        r.extend_from_slice(&an.to_be_bytes());
        r.extend_from_slice(&ns.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
    };
    if opcode != 0 {
        header(&mut reply, RCODE_NOTIMP, 0, 0, false, 0);
        return Some(reply);
    }
    if qdcount != 1 {
        header(&mut reply, RCODE_FORMERR, 0, 0, false, 0);
        return Some(reply);
    }
    let Some((qname, pos)) = read_qname(query, 12) else {
        header(&mut reply, RCODE_FORMERR, 0, 0, false, 0);
        return Some(reply);
    };
    let Some(q) = query.get(pos..pos + 4) else {
        header(&mut reply, RCODE_FORMERR, 0, 0, false, 0);
        return Some(reply);
    };
    let qtype = u16::from_be_bytes([q[0], q[1]]);
    let qclass = u16::from_be_bytes([q[2], q[3]]);
    let question = &query[12..pos + 4];

    let in_zone = qname == cfg.host || qname.ends_with(&format!(".{}", cfg.host));
    if !in_zone || qclass != CLASS_IN {
        header(&mut reply, RCODE_REFUSED, 0, 0, false, 1);
        reply.extend_from_slice(question);
        return Some(reply);
    }
    // The apex is the default filter (full nodes with witness); x<hex>.apex narrows it.
    let filter = if qname == cfg.host {
        Some(0x9)
    } else {
        let label = &qname[..qname.len() - cfg.host.len() - 1];
        if label.contains('.') {
            None
        } else {
            parse_filter(label)
        }
    };
    let Some(filter) = filter else {
        // A name in our zone that does not exist: NXDOMAIN with the SOA for negative caching.
        header(&mut reply, RCODE_NXDOMAIN, 0, 1, true, 1);
        reply.extend_from_slice(question);
        push_soa(&mut reply, cfg, answers.serial);
        return Some(reply);
    };

    let mut records: Vec<Vec<u8>> = Vec::new();
    let is_apex = qname == cfg.host;
    if qtype == TYPE_A || qtype == TYPE_ANY {
        for ip in pick(&answers.nodes, filter, false, MAX_A, random) {
            records.push(rr_addr(ip, cfg.ttl));
        }
    }
    if qtype == TYPE_AAAA || qtype == TYPE_ANY {
        for ip in pick(
            &answers.nodes,
            filter,
            true,
            MAX_AAAA,
            random.rotate_left(17),
        ) {
            records.push(rr_addr(ip, cfg.ttl));
        }
    }
    if is_apex && (qtype == TYPE_NS || qtype == TYPE_ANY) {
        records.push(rr_ns(cfg));
    }
    let mut soa_answer = false;
    if is_apex && (qtype == TYPE_SOA || qtype == TYPE_ANY) {
        soa_answer = true;
    }
    // Keep a UDP-sized reply: drop address records beyond what fits.
    let mut size = 12 + question.len() + if soa_answer { 100 } else { 0 };
    records.retain(|r| {
        size += r.len();
        size <= 500
    });
    let an = records.len() as u16 + u16::from(soa_answer);
    // NODATA (no records of that type) carries the SOA in the authority section.
    let nodata = an == 0;
    header(&mut reply, RCODE_OK, an, u16::from(nodata), true, 1);
    reply.extend_from_slice(question);
    for r in &records {
        reply.extend_from_slice(r);
    }
    if soa_answer || nodata {
        push_soa(&mut reply, cfg, answers.serial);
    }
    Some(reply)
}

fn rr_addr(ip: IpAddr, ttl: u32) -> Vec<u8> {
    let mut r = vec![0xc0, 0x0c]; // name: pointer to the question
    match ip {
        IpAddr::V4(v) => {
            r.extend_from_slice(&TYPE_A.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&4u16.to_be_bytes());
            r.extend_from_slice(&v.octets());
        }
        IpAddr::V6(v) => {
            r.extend_from_slice(&TYPE_AAAA.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&16u16.to_be_bytes());
            r.extend_from_slice(&v.octets());
        }
    }
    r
}

fn rr_ns(cfg: &DnsConfig) -> Vec<u8> {
    let mut r = vec![0xc0, 0x0c];
    r.extend_from_slice(&TYPE_NS.to_be_bytes());
    r.extend_from_slice(&CLASS_IN.to_be_bytes());
    r.extend_from_slice(&cfg.ns_ttl.to_be_bytes());
    let mut name = Vec::new();
    encode_name(&mut name, &cfg.ns);
    r.extend_from_slice(&(name.len() as u16).to_be_bytes());
    r.extend_from_slice(&name);
    r
}

fn push_soa(out: &mut Vec<u8>, cfg: &DnsConfig, serial: u32) {
    encode_name(out, &cfg.host);
    out.extend_from_slice(&TYPE_SOA.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&cfg.ns_ttl.to_be_bytes());
    let mut rdata = Vec::new();
    encode_name(&mut rdata, &cfg.ns);
    encode_name(&mut rdata, &cfg.mbox.replacen('@', ".", 1));
    for v in [serial, 3600, 600, 86400 * 7, 60] {
        // serial, refresh, retry, expire, negative-caching TTL
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
}

/// Per-source token bucket.
pub struct RateLimiter {
    per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new(per_sec: f64) -> RateLimiter {
        RateLimiter {
            per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if b.len() > 100_000 {
            // Forget buckets idle for a minute rather than grow without bound under a flood.
            b.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let (tokens, last) = b.entry(ip).or_insert((self.per_sec * 2.0, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.per_sec)
            .min(self.per_sec * 2.0);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn random_u64() -> u64 {
    // Mixes the clock with a counter; enough to vary answers between queries.
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    t ^ C.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
}

pub async fn serve_udp(
    bind: SocketAddr,
    cfg: Arc<DnsConfig>,
    answers: SharedAnswers,
    limiter: Arc<RateLimiter>,
) -> std::io::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    let mut buf = [0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if !limiter.allow(peer.ip()) {
            continue;
        }
        let reply = {
            let a = answers.read().unwrap_or_else(|p| p.into_inner());
            answer(&buf[..n], &cfg, &a, random_u64())
        };
        if let Some(r) = reply {
            let _ = sock.send_to(&r, peer).await;
        }
    }
}

pub async fn serve_tcp(
    bind: SocketAddr,
    cfg: Arc<DnsConfig>,
    answers: SharedAnswers,
    limiter: Arc<RateLimiter>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let Ok((mut s, peer)) = listener.accept().await else {
            continue;
        };
        if !limiter.allow(peer.ip()) {
            continue;
        }
        let cfg = cfg.clone();
        let answers = answers.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await?;
                let n = u16::from_be_bytes(len) as usize;
                let mut q = vec![0u8; n];
                s.read_exact(&mut q).await?;
                let reply = {
                    let a = answers.read().unwrap_or_else(|p| p.into_inner());
                    answer(&q, &cfg, &a, random_u64())
                };
                if let Some(r) = reply {
                    s.write_all(&(r.len() as u16).to_be_bytes()).await?;
                    s.write_all(&r).await?;
                }
                Ok::<(), std::io::Error>(())
            })
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DnsConfig {
        DnsConfig {
            host: "seed.example.org".into(),
            ns: "ns.example.org".into(),
            mbox: "me@example.org".into(),
            ttl: 60,
            ns_ttl: 40000,
            rate_per_sec: 10.0,
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        encode_name(&mut q, name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn counts(r: &[u8]) -> (u8, u16, u16) {
        (
            r[3] & 0x0f,
            u16::from_be_bytes([r[6], r[7]]),
            u16::from_be_bytes([r[8], r[9]]),
        )
    }

    fn nodes(n: u32, services: u64) -> Answers {
        Answers {
            nodes: (0..n)
                .map(|i| {
                    (
                        format!("{}.{}.1.1:8333", 20 + i / 200, i % 200)
                            .parse()
                            .unwrap(),
                        services,
                    )
                })
                .collect(),
            serial: 1,
        }
    }

    const FORK: u64 = 1 | 1 << 3 | 1 << 28;

    #[test]
    fn apex_a_answers_are_authoritative_and_fit_udp() {
        let r = answer(
            &query("seed.example.org", TYPE_A),
            &cfg(),
            &nodes(500, FORK),
            7,
        )
        .unwrap();
        let (rcode, an, _) = counts(&r);
        assert_eq!(rcode, RCODE_OK);
        assert!(r[2] & 0x04 != 0, "AA set");
        assert_eq!(an as usize, MAX_A);
        assert!(r.len() <= 512, "{}", r.len());
        assert_eq!(&r[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn answers_are_one_per_slash16() {
        let r = answer(
            &query("seed.example.org", TYPE_A),
            &cfg(),
            &nodes(500, FORK),
            3,
        )
        .unwrap();
        let (_, an, _) = counts(&r);
        let start = r.len() - an as usize * 16;
        let mut groups = HashSet::new();
        for i in 0..an as usize {
            let rec = &r[start + i * 16..start + (i + 1) * 16];
            assert!(groups.insert((rec[12], rec[13])), "two answers in one /16");
        }
    }

    #[test]
    fn filters_select_by_services() {
        let mut a = nodes(10, FORK);
        a.nodes
            .push(("99.1.1.1:8333".parse().unwrap(), FORK | 1 << 11)); // has P2P_V2
        let r = answer(&query("x10000809.seed.example.org", TYPE_A), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).1, 1);
        assert_eq!(&r[r.len() - 4..], &[99, 1, 1, 1]);
        let r = answer(&query("X10000009.SEED.example.org", TYPE_A), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).0, RCODE_OK, "case-insensitive (DNS 0x20)");
        assert!(counts(&r).1 >= 10);
    }

    #[test]
    fn nodata_nxdomain_and_refused() {
        let a = nodes(10, FORK);
        let r = answer(&query("seed.example.org", TYPE_AAAA), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r), (RCODE_OK, 0, 1), "NODATA with SOA");
        let r = answer(&query("www.seed.example.org", TYPE_A), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).0, RCODE_NXDOMAIN);
        let r = answer(&query("a.b.seed.example.org", TYPE_A), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).0, RCODE_NXDOMAIN);
        let r = answer(&query("example.com", TYPE_A), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).0, RCODE_REFUSED);
    }

    #[test]
    fn ns_and_soa_at_the_apex() {
        let a = nodes(0, FORK);
        let r = answer(&query("seed.example.org", TYPE_NS), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).1, 1);
        let r = answer(&query("seed.example.org", TYPE_SOA), &cfg(), &a, 1).unwrap();
        assert_eq!(counts(&r).1, 1);
    }

    #[test]
    fn garbage_never_panics() {
        let c = cfg();
        let a = nodes(5, FORK);
        let base = query("seed.example.org", TYPE_A);
        for cut in 0..base.len() {
            let _ = answer(&base[..cut], &c, &a, 1);
        }
        let mut x: u64 = 0x1234_5678;
        for _ in 0..20_000 {
            let len = (x % 80) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf.push(x as u8);
            }
            let _ = answer(&buf, &c, &a, x);
        }
    }

    #[test]
    fn rate_limiter_caps_a_burst() {
        let rl = RateLimiter::new(5.0);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let allowed = (0..100).filter(|_| rl.allow(ip)).count();
        assert!((10..=11).contains(&allowed), "{allowed}");
        assert!(
            rl.allow("203.0.113.10".parse().unwrap()),
            "other sources unaffected"
        );
    }
}
