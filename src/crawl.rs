//! One crawl attempt: connect, handshake, optionally ask for addresses, disconnect.
//!
//! Every step runs against a hard deadline and every piece of network input is bounded and checked,
//! so an attempt always ends, and ends as either a success or a described failure. Nothing here can
//! panic on anything a peer sends.

use crate::addr::{Host, Net, NetAddr};
use crate::node::Handshake;
use crate::socks;
use crate::wire::{self, Gossip, HEADER_LEN};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

#[derive(Clone, Debug)]
pub struct CrawlConfig {
    pub magic: [u8; 4],
    pub user_agent: String,
    pub connect_timeout: Duration,
    pub proxied_connect_timeout: Duration,
    /// From connection to receiving the peer's version (and verack).
    pub handshake_timeout: Duration,
    pub proxied_handshake_timeout: Duration,
    /// How long to wait for an addr/addrv2 reply after sending getaddr.
    pub getaddr_wait: Duration,
    pub onion_proxy: Option<SocketAddr>,
    pub i2p_proxy: Option<SocketAddr>,
    /// Most gossip addresses accepted from one attempt.
    pub max_gossip: usize,
}

impl Default for CrawlConfig {
    fn default() -> CrawlConfig {
        CrawlConfig {
            magic: wire::MAGIC_MAIN,
            user_agent: format!("/LionSeed:{}/", env!("CARGO_PKG_VERSION")),
            connect_timeout: Duration::from_secs(10),
            proxied_connect_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(20),
            proxied_handshake_timeout: Duration::from_secs(40),
            getaddr_wait: Duration::from_secs(15),
            onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            i2p_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 4447))),
            max_gossip: 2000,
        }
    }
}

#[derive(Debug)]
pub enum Outcome {
    Success {
        handshake: Handshake,
        gossip: Vec<Gossip>,
        asked_for_addrs: bool,
    },
    Failure(String),
}

async fn open(addr: &NetAddr, cfg: &CrawlConfig) -> Result<TcpStream, String> {
    let proxied = addr.net().is_proxied();
    let limit = if proxied {
        cfg.proxied_connect_timeout
    } else {
        cfg.connect_timeout
    };
    let fut = async {
        match &addr.host {
            Host::Ipv4(ip) => TcpStream::connect(SocketAddr::new(IpAddr::V4(*ip), addr.port))
                .await
                .map_err(|e| format!("connect: {e}")),
            Host::Ipv6(ip) => TcpStream::connect(SocketAddr::new(IpAddr::V6(*ip), addr.port))
                .await
                .map_err(|e| format!("connect: {e}")),
            Host::Onion(name) => {
                let proxy = cfg.onion_proxy.ok_or("no onion proxy configured")?;
                socks::connect(proxy, &format!("{name}.onion"), addr.port)
                    .await
                    .map_err(|e| format!("tor: {e}"))
            }
            Host::I2p(name) => {
                let proxy = cfg.i2p_proxy.ok_or("no i2p proxy configured")?;
                socks::connect(proxy, &format!("{name}.b32.i2p"), addr.port)
                    .await
                    .map_err(|e| format!("i2p: {e}"))
            }
        }
    };
    match timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err("connect: timed out".into()),
    }
}

struct Msg {
    command: String,
    payload: Vec<u8>,
}

async fn read_msg(s: &mut TcpStream, magic: [u8; 4]) -> Result<Msg, String> {
    let mut h = [0u8; HEADER_LEN];
    s.read_exact(&mut h)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let header = wire::parse_header(magic, &h).map_err(|e| format!("header: {e}"))?;
    let mut payload = vec![0u8; header.length as usize];
    s.read_exact(&mut payload)
        .await
        .map_err(|e| format!("read: {e}"))?;
    wire::check_payload(&header, &payload).map_err(|e| format!("payload: {e}"))?;
    Ok(Msg {
        command: header.command,
        payload,
    })
}

async fn send(s: &mut TcpStream, magic: [u8; 4], cmd: &str, payload: &[u8]) -> Result<(), String> {
    s.write_all(&wire::frame(magic, cmd, payload))
        .await
        .map_err(|e| format!("write: {e}"))
}

/// Crawl `addr` once. `want_addrs` asks the peer for addresses after the handshake.
pub async fn crawl(addr: &NetAddr, want_addrs: bool, cfg: &CrawlConfig, now: u64) -> Outcome {
    let mut stream = match open(addr, cfg).await {
        Ok(s) => s,
        Err(e) => return Outcome::Failure(e),
    };
    let limit = if addr.net().is_proxied() {
        cfg.proxied_handshake_timeout
    } else {
        cfg.handshake_timeout
    };
    let handshake_deadline = Instant::now() + limit;
    let nonce = now ^ ((addr.port as u64) << 48) ^ 0x4c69_6f6e_5365_6564;
    if let Err(e) = send(
        &mut stream,
        cfg.magic,
        "version",
        &wire::version_payload(&cfg.user_agent, now, nonce),
    )
    .await
    {
        return Outcome::Failure(e);
    }

    let mut version: Option<wire::Version> = None;
    let mut got_verack = false;
    let mut asked = false;
    let mut addr_deadline: Option<Instant> = None;
    let mut gossip: Vec<Gossip> = Vec::new();

    loop {
        let deadline = match (version.is_some() && got_verack, addr_deadline) {
            (true, Some(d)) => d,
            (true, None) => break, // handshake done and not waiting for addresses
            (false, _) => handshake_deadline,
        };
        let msg = match tokio::time::timeout_at(deadline, read_msg(&mut stream, cfg.magic)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                if version.is_some() && got_verack {
                    break; // peer hung up while we waited for addresses: the handshake still counts
                }
                return Outcome::Failure(e);
            }
            Err(_) => {
                if version.is_some() && got_verack {
                    break; // no (more) addresses in time: fine
                }
                return Outcome::Failure(if version.is_some() {
                    "handshake: no verack in time".into()
                } else {
                    "handshake: no version in time".into()
                });
            }
        };
        match msg.command.as_str() {
            "version" if version.is_none() => {
                let v = match wire::parse_version(&msg.payload) {
                    Ok(v) => v,
                    Err(e) => return Outcome::Failure(format!("version: {e}")),
                };
                version = Some(v);
                // sendaddrv2 must come before verack (BIP155).
                if let Err(e) = send(&mut stream, cfg.magic, "sendaddrv2", &[]).await {
                    return Outcome::Failure(e);
                }
                if let Err(e) = send(&mut stream, cfg.magic, "verack", &[]).await {
                    return Outcome::Failure(e);
                }
            }
            "verack" => got_verack = true,
            "ping" => {
                if let Ok(n) = wire::parse_ping(&msg.payload) {
                    let _ = send(&mut stream, cfg.magic, "pong", &n.to_le_bytes()).await;
                }
            }
            "addr" | "addrv2" if asked => {
                let parsed = if msg.command == "addr" {
                    wire::parse_addr(&msg.payload)
                } else {
                    wire::parse_addrv2(&msg.payload)
                };
                if let Ok(list) = parsed {
                    let big = list.len() > 1;
                    let room = cfg.max_gossip.saturating_sub(gossip.len());
                    gossip.extend(list.into_iter().take(room));
                    // A reply to getaddr is a batch; a single entry is usually the peer announcing
                    // itself, so keep waiting for the batch.
                    if big || gossip.len() >= cfg.max_gossip {
                        break;
                    }
                }
            }
            _ => {} // everything else is skipped by length
        }
        if version.is_some() && got_verack && want_addrs && !asked {
            if let Err(e) = send(&mut stream, cfg.magic, "getaddr", &[]).await {
                // The handshake succeeded; losing the connection now only costs the addresses.
                let _ = e;
                break;
            }
            asked = true;
            addr_deadline = Some(Instant::now() + cfg.getaddr_wait);
        }
    }

    // The loop only leaves normally once a version has arrived; say so rather than assume it.
    let Some(v) = version else {
        return Outcome::Failure("handshake: ended without a version".into());
    };
    Outcome::Success {
        handshake: Handshake {
            services: v.services,
            height: v.start_height,
            protocol_version: v.protocol_version,
            user_agent: v.user_agent,
        },
        gossip,
        asked_for_addrs: asked,
    }
}

/// Whether a network can be crawled with this configuration.
pub fn reachable(net: Net, cfg: &CrawlConfig) -> bool {
    match net {
        Net::Onion => cfg.onion_proxy.is_some(),
        Net::I2p => cfg.i2p_proxy.is_some(),
        _ => true,
    }
}
