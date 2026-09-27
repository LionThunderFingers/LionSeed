//! The Bitcoin P2P wire format, only as much of it as a seeder needs.
//!
//! LionSeed decodes exactly five messages (version, verack, ping, addr, addrv2) and skips every other
//! message by its length without looking inside it. An unfamiliar or fork-specific message therefore
//! can never break a crawl, and a malformed one is a decode error for that single attempt, never a
//! panic. Every length read from the network is bounded before anything is allocated.

use crate::addr::{Host, NetAddr};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Mainnet network magic. The BLAKE2b fork kept Bitcoin's magic and port.
pub const MAGIC_MAIN: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
/// testnet4 magic.
pub const MAGIC_TESTNET4: [u8; 4] = [0x1c, 0x16, 0x3f, 0x28];

pub const PROTOCOL_VERSION: u32 = 70016;
pub const HEADER_LEN: usize = 24;
/// Largest payload we will read. An addr/addrv2 message of 1000 entries is well under 64 KiB; a
/// peer claiming more than this is dropped rather than buffered.
pub const MAX_PAYLOAD: u32 = 1 << 20;
/// Most addresses a single addr or addrv2 message may carry (the protocol limit).
pub const MAX_ADDR_PER_MSG: u64 = 1000;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadMagic,
    BadChecksum,
    TooLarge(u64),
    Invalid(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// A little cursor over a payload. Every read checks bounds.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16_be(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn compact_size(&mut self) -> Result<u64, WireError> {
        Ok(match self.u8()? {
            0xfd => u16::from_le_bytes(self.array()?) as u64,
            0xfe => self.u32()? as u64,
            0xff => self.u64()?,
            n => n as u64,
        })
    }
}

fn put_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// A parsed 24-byte message header.
#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub command: String,
    pub length: u32,
    pub checksum: [u8; 4],
}

pub fn parse_header(magic: [u8; 4], h: &[u8; HEADER_LEN]) -> Result<Header, WireError> {
    if h[0..4] != magic {
        return Err(WireError::BadMagic);
    }
    let cmd = &h[4..16];
    let end = cmd.iter().position(|&b| b == 0).unwrap_or(12);
    if cmd[end..].iter().any(|&b| b != 0) || !cmd[..end].iter().all(|b| b.is_ascii_graphic()) {
        return Err(WireError::Invalid("command"));
    }
    let command = String::from_utf8_lossy(&cmd[..end]).into_owned();
    let length = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
    if length > MAX_PAYLOAD {
        return Err(WireError::TooLarge(length as u64));
    }
    Ok(Header {
        command,
        length,
        checksum: [h[20], h[21], h[22], h[23]],
    })
}

pub fn check_payload(header: &Header, payload: &[u8]) -> Result<(), WireError> {
    if sha256d(payload)[..4] != header.checksum {
        return Err(WireError::BadChecksum);
    }
    Ok(())
}

/// A whole message: header plus payload.
pub fn frame(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&magic);
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

/// Our version message. We advertise no services, relay nothing, and describe ourselves honestly.
pub fn version_payload(user_agent: &str, now: u64, nonce: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(128);
    p.extend_from_slice(&(PROTOCOL_VERSION as i32).to_le_bytes());
    p.extend_from_slice(&0u64.to_le_bytes()); // our services
    p.extend_from_slice(&(now as i64).to_le_bytes());
    for _ in 0..2 {
        // addr_recv and addr_from: services, IPv6-mapped address, port. Zeroed, as a crawler.
        p.extend_from_slice(&[0u8; 26]);
    }
    p.extend_from_slice(&nonce.to_le_bytes());
    put_compact_size(&mut p, user_agent.len() as u64);
    p.extend_from_slice(user_agent.as_bytes());
    p.extend_from_slice(&0i32.to_le_bytes()); // start height
    p.push(0); // relay: false
    p
}

#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub protocol_version: u32,
    pub services: u64,
    pub user_agent: String,
    pub start_height: i32,
}

pub fn parse_version(payload: &[u8]) -> Result<Version, WireError> {
    let mut r = Reader::new(payload);
    let version = r.i32()?;
    let services = r.u64()?;
    let _timestamp = r.u64()?;
    let _recv = r.bytes(26)?;
    // Very old peers stop here; anything we would serve is far newer.
    let _from = r.bytes(26)?;
    let _nonce = r.u64()?;
    let ua_len = r.compact_size()?;
    if ua_len > 256 {
        return Err(WireError::TooLarge(ua_len));
    }
    let user_agent = String::from_utf8_lossy(r.bytes(ua_len as usize)?).into_owned();
    let start_height = r.i32()?;
    if version < 0 {
        return Err(WireError::Invalid("version"));
    }
    Ok(Version {
        protocol_version: version as u32,
        services,
        user_agent,
        start_height,
    })
}

fn ipv6_to_host(b: [u8; 16]) -> Host {
    let ip = Ipv6Addr::from(b);
    match ip.to_ipv4_mapped() {
        Some(v4) => Host::Ipv4(v4),
        None => Host::Ipv6(ip),
    }
}

/// An address learned from gossip, with the services it was said to have.
pub type Gossip = (NetAddr, u64);

/// Parse an `addr` message (the original format: IPv4 and IPv6 only).
pub fn parse_addr(payload: &[u8]) -> Result<Vec<Gossip>, WireError> {
    let mut r = Reader::new(payload);
    let n = r.compact_size()?;
    if n > MAX_ADDR_PER_MSG {
        return Err(WireError::TooLarge(n));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let _time = r.u32()?;
        let services = r.u64()?;
        let ip: [u8; 16] = r.array()?;
        let port = r.u16_be()?;
        out.push((
            NetAddr {
                host: ipv6_to_host(ip),
                port,
            },
            services,
        ));
    }
    Ok(out)
}

const TORV3_CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// The 56-character name of a Tor v3 service from its 32-byte public key.
pub fn onion_name(pubkey: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(TORV3_CHECKSUM_PREFIX);
    h.update(pubkey);
    h.update([3u8]);
    let checksum = h.finalize();
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(pubkey);
    raw.extend_from_slice(&checksum[..2]);
    raw.push(3);
    base32_lower(&raw)
}

/// RFC 4648 base32, lowercase, no padding (as used for .onion and .b32.i2p names).
pub fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Parse an `addrv2` message (BIP155). Networks we do not crawl (Tor v2, unknown ids) are skipped,
/// not errors, as BIP155 requires.
pub fn parse_addrv2(payload: &[u8]) -> Result<Vec<Gossip>, WireError> {
    let mut r = Reader::new(payload);
    let n = r.compact_size()?;
    if n > MAX_ADDR_PER_MSG {
        return Err(WireError::TooLarge(n));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let _time = r.u32()?;
        let services = r.compact_size()?;
        let net_id = r.u8()?;
        let len = r.compact_size()?;
        if len > 512 {
            return Err(WireError::TooLarge(len));
        }
        let raw = r.bytes(len as usize)?;
        let port = r.u16_be()?;
        let host = match (net_id, raw.len()) {
            (1, 4) => Some(Host::Ipv4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
            (2, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(raw);
                Some(ipv6_to_host(b))
            }
            (4, 32) => {
                let mut k = [0u8; 32];
                k.copy_from_slice(raw);
                Some(Host::Onion(onion_name(&k)))
            }
            (5, 32) => Some(Host::I2p(base32_lower(raw))),
            (6, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(raw);
                let ip = Ipv6Addr::from(b);
                (ip.octets()[0] == 0xfc).then_some(Host::Ipv6(ip))
            }
            _ => None, // Tor v2, wrong length, or an id we do not know: skip
        };
        if let Some(host) = host {
            out.push((NetAddr { host, port }, services));
        }
    }
    Ok(out)
}

pub fn parse_ping(payload: &[u8]) -> Result<u64, WireError> {
    Reader::new(payload).u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(m: &[u8]) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h.copy_from_slice(&m[..HEADER_LEN]);
        h
    }

    #[test]
    fn frame_and_header_round_trip() {
        let m = frame(MAGIC_MAIN, "verack", &[]);
        assert_eq!(m.len(), 24);
        let h = parse_header(MAGIC_MAIN, &header_bytes(&m)).unwrap();
        assert_eq!(h.command, "verack");
        assert_eq!(h.length, 0);
        check_payload(&h, &[]).unwrap();
        // the well-known checksum of an empty payload
        assert_eq!(h.checksum, [0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn bad_headers_are_errors() {
        let m = frame(MAGIC_MAIN, "verack", &[]);
        assert_eq!(
            parse_header(MAGIC_TESTNET4, &header_bytes(&m)),
            Err(WireError::BadMagic)
        );
        let mut big = header_bytes(&m);
        big[16..20].copy_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        assert!(matches!(
            parse_header(MAGIC_MAIN, &big),
            Err(WireError::TooLarge(_))
        ));
        let mut junk = header_bytes(&m);
        junk[4] = 0xff;
        assert!(parse_header(MAGIC_MAIN, &junk).is_err());
        let h = parse_header(MAGIC_MAIN, &header_bytes(&m)).unwrap();
        assert_eq!(check_payload(&h, b"x"), Err(WireError::BadChecksum));
    }

    #[test]
    fn our_version_parses_back() {
        let p = version_payload("/LionSeed:0.1.0/", 1_790_000_000, 42);
        let v = parse_version(&p).unwrap();
        assert_eq!(v.protocol_version, PROTOCOL_VERSION);
        assert_eq!(v.services, 0);
        assert_eq!(v.user_agent, "/LionSeed:0.1.0/");
        assert_eq!(v.start_height, 0);
    }

    #[test]
    fn truncated_or_hostile_version_is_an_error() {
        let p = version_payload("/x/", 1, 1);
        for cut in 0..p.len() - 1 {
            // every truncation short of the start height must fail cleanly
            if cut < p.len() - 5 {
                assert!(parse_version(&p[..cut]).is_err(), "cut at {cut}");
            }
        }
        let mut huge_ua = version_payload("", 1, 1);
        let ua_pos = 4 + 8 + 8 + 26 + 26 + 8;
        huge_ua[ua_pos] = 0xfe; // claims a 4-byte length
        huge_ua.splice(ua_pos + 1..ua_pos + 1, [0xff, 0xff, 0xff, 0x7f]);
        assert!(matches!(
            parse_version(&huge_ua),
            Err(WireError::TooLarge(_))
        ));
    }

    #[test]
    fn addr_v1_parses_ipv4_mapped_and_ipv6() {
        let mut p = vec![2];
        for (ip, port) in [
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
                8333u16,
            ),
            (
                Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1).octets(),
                8333,
            ),
        ] {
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&(1u64 | 1 << 28).to_le_bytes());
            p.extend_from_slice(&ip);
            p.extend_from_slice(&port.to_be_bytes());
        }
        let got = parse_addr(&p).unwrap();
        assert_eq!(got[0].0.to_string(), "1.2.3.4:8333");
        assert_eq!(got[1].0.to_string(), "[2001:4860::1]:8333");
        assert_eq!(got[0].1, 1 | 1 << 28);
    }

    #[test]
    fn addr_count_over_limit_is_refused_before_allocating() {
        let mut p = Vec::new();
        put_compact_size(&mut p, 1_000_000);
        assert!(matches!(parse_addr(&p), Err(WireError::TooLarge(_))));
        assert!(matches!(parse_addrv2(&p), Err(WireError::TooLarge(_))));
    }

    fn v2_entry(p: &mut Vec<u8>, net: u8, raw: &[u8], port: u16) {
        p.extend_from_slice(&1u32.to_le_bytes());
        put_compact_size(p, 1 | 1 << 28);
        p.push(net);
        put_compact_size(p, raw.len() as u64);
        p.extend_from_slice(raw);
        p.extend_from_slice(&port.to_be_bytes());
    }

    #[test]
    fn addrv2_parses_every_network_and_skips_unknown() {
        let mut p = vec![6];
        v2_entry(&mut p, 1, &[5, 6, 7, 8], 8333);
        v2_entry(
            &mut p,
            2,
            &Ipv6Addr::new(0x2a01, 0, 0, 0, 0, 0, 0, 2).octets(),
            8333,
        );
        v2_entry(&mut p, 4, &[7u8; 32], 8333);
        v2_entry(&mut p, 5, &[9u8; 32], 0);
        v2_entry(&mut p, 3, &[1u8; 10], 8333); // Tor v2: skipped
        v2_entry(&mut p, 99, &[1, 2, 3], 1); // unknown network: skipped
        let got = parse_addrv2(&p).unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].0.to_string(), "5.6.7.8:8333");
        assert_eq!(got[1].0.to_string(), "[2a01::2]:8333");
        assert_eq!(
            got[2].0.to_string(),
            "a4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dwc6ad.onion:8333"
        );
        assert!(got[2].0.is_routable());
        assert_eq!(
            got[3].0.to_string(),
            "beeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeq.b32.i2p:0"
        );
        assert!(got[3].0.is_routable());
    }

    #[test]
    fn onion_name_matches_independent_vectors() {
        // Expected values computed separately with Python's hashlib.sha3_256 and base64.b32encode
        // (key || sha3(".onion checksum" || key || 0x03)[..2] || 0x03, base32, lowercase).
        assert_eq!(
            onion_name(&[0u8; 32]),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
        );
        assert_eq!(
            onion_name(&[7u8; 32]),
            "a4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dwc6ad"
        );
        assert_eq!(
            base32_lower(&[9u8; 32]),
            "beeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeq"
        );
    }

    #[test]
    fn truncated_addrv2_is_an_error_not_a_panic() {
        let mut p = vec![1];
        v2_entry(&mut p, 4, &[7u8; 32], 8333);
        for cut in 1..p.len() {
            assert!(parse_addrv2(&p[..cut]).is_err(), "cut at {cut}");
        }
    }
}
