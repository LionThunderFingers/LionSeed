//! A simulated network on loopback: fake peers that behave well, badly or not at all, and the real
//! crawler and engine run against them.

use lionseed::addr::NetAddr;
use lionseed::crawl::{crawl, CrawlConfig, Outcome};
use lionseed::engine::{lock, Engine, EngineConfig};
use lionseed::node::{Class, NODE_BLAKE2B, NODE_NETWORK, NODE_WITNESS};
use lionseed::scheduler::RetryPolicy;
use lionseed::store::Store;
use lionseed::wire::{self, MAGIC_MAIN};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Clone)]
enum Peer {
    /// Completes a handshake with these services; answers getaddr with `gossip`.
    Good { services: u64, gossip: Vec<NetAddr> },
    /// Accepts and never says anything.
    Hang,
    /// Sends random-looking bytes.
    Garbage,
    /// Sends a header claiming a 16 MiB payload.
    Oversize,
    /// Sends its version, then closes.
    CloseAfterVersion,
    /// Waits before answering at all.
    Slow(Duration),
}

fn version_from_peer(services: u64) -> Vec<u8> {
    let mut p = wire::version_payload("/Satoshi:29.4.2/Knots:20260508/", 1_790_000_000, 7);
    p[4..12].copy_from_slice(&services.to_le_bytes());
    let n = p.len();
    p[n - 5..n - 1].copy_from_slice(&974_000i32.to_le_bytes());
    p
}

fn addrv2_payload(list: &[NetAddr]) -> Vec<u8> {
    let mut p = vec![list.len() as u8];
    for a in list {
        p.extend_from_slice(&1u32.to_le_bytes());
        p.push(9); // compact size services
        match &a.host {
            lionseed::addr::Host::Ipv4(ip) => {
                p.push(1);
                p.push(4);
                p.extend_from_slice(&ip.octets());
            }
            _ => panic!("sim only gossips IPv4"),
        }
        p.extend_from_slice(&a.port.to_be_bytes());
    }
    p
}

async fn read_msg(s: &mut TcpStream) -> Option<String> {
    let mut h = [0u8; 24];
    s.read_exact(&mut h).await.ok()?;
    let len = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    let end = h[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    Some(String::from_utf8_lossy(&h[4..4 + end]).into_owned())
}

async fn serve_one(mut s: TcpStream, peer: Peer) {
    match peer {
        Peer::Hang => {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        Peer::Garbage => {
            let junk: Vec<u8> = (0..200u32).map(|i| (i * 37 % 251) as u8).collect();
            let _ = s.write_all(&junk).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Peer::Oversize => {
            let mut h = wire::frame(MAGIC_MAIN, "addr", &[]);
            h[16..20].copy_from_slice(&(16u32 << 20).to_le_bytes());
            let _ = s.write_all(&h).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Peer::CloseAfterVersion => {
            let _ = read_msg(&mut s).await;
            let _ = s
                .write_all(&wire::frame(
                    MAGIC_MAIN,
                    "version",
                    &version_from_peer(NODE_NETWORK | NODE_BLAKE2B),
                ))
                .await;
        }
        Peer::Slow(d) => {
            tokio::time::sleep(d).await;
        }
        Peer::Good { services, gossip } => {
            if read_msg(&mut s).await.as_deref() != Some("version") {
                return;
            }
            let _ = s
                .write_all(&wire::frame(
                    MAGIC_MAIN,
                    "version",
                    &version_from_peer(services),
                ))
                .await;
            let _ = s.write_all(&wire::frame(MAGIC_MAIN, "verack", &[])).await;
            // Some chatter a real node sends, which the crawler must skip.
            let _ = s
                .write_all(&wire::frame(MAGIC_MAIN, "sendcmpct", &[0u8; 9]))
                .await;
            let _ = s
                .write_all(&wire::frame(MAGIC_MAIN, "ping", &5u64.to_le_bytes()))
                .await;
            while let Some(cmd) = read_msg(&mut s).await {
                if cmd == "getaddr" {
                    let _ = s
                        .write_all(&wire::frame(MAGIC_MAIN, "addrv2", &addrv2_payload(&gossip)))
                        .await;
                }
            }
        }
    }
}

/// Start a fake peer; returns its address.
async fn spawn_peer(peer: Peer) -> NetAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(serve_one(s, peer.clone()));
        }
    });
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn fast_cfg() -> CrawlConfig {
    CrawlConfig {
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(2),
        getaddr_wait: Duration::from_secs(2),
        onion_proxy: None,
        i2p_proxy: None,
        ..CrawlConfig::default()
    }
}

const FORK: u64 = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B;

#[tokio::test]
async fn good_fork_peer_handshakes_and_gossips() {
    let other: NetAddr = "8.8.4.4:8333".parse().unwrap();
    let p = spawn_peer(Peer::Good {
        services: FORK,
        gossip: vec![other.clone()],
    })
    .await;
    match crawl(&p, true, &fast_cfg(), 1_790_000_000).await {
        Outcome::Success {
            handshake,
            gossip,
            asked_for_addrs,
        } => {
            assert_eq!(handshake.services, FORK);
            assert_eq!(handshake.height, 974_000);
            assert!(asked_for_addrs);
            assert_eq!(gossip, vec![(other, 9)]);
        }
        Outcome::Failure(e) => panic!("{e}"),
    }
}

#[tokio::test]
async fn no_getaddr_when_not_wanted_and_it_returns_promptly() {
    let p = spawn_peer(Peer::Good {
        services: FORK,
        gossip: vec![],
    })
    .await;
    let t = Instant::now();
    match crawl(&p, false, &fast_cfg(), 1).await {
        Outcome::Success {
            asked_for_addrs, ..
        } => assert!(!asked_for_addrs),
        Outcome::Failure(e) => panic!("{e}"),
    }
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn every_bad_peer_fails_cleanly_and_within_its_deadline() {
    for peer in [
        Peer::Hang,
        Peer::Garbage,
        Peer::Oversize,
        Peer::CloseAfterVersion,
        Peer::Slow(Duration::from_secs(10)),
    ] {
        let p = spawn_peer(peer).await;
        let t = Instant::now();
        let out = crawl(&p, true, &fast_cfg(), 1).await;
        assert!(matches!(out, Outcome::Failure(_)), "{out:?}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }
}

#[tokio::test]
async fn refused_connection_is_a_failure() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a: NetAddr = format!("127.0.0.1:{}", l.local_addr().unwrap().port())
        .parse()
        .unwrap();
    drop(l);
    assert!(matches!(
        crawl(&a, false, &fast_cfg(), 1).await,
        Outcome::Failure(_)
    ));
}

/// The whole engine against a small network: fork nodes are re-checked on schedule, gossip leads
/// to new nodes, bad peers never block anything, nothing stays in flight after shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_rechecks_forks_follows_gossip_and_survives_bad_peers() {
    let hidden = spawn_peer(Peer::Good {
        services: FORK,
        gossip: vec![],
    })
    .await; // only reachable via gossip
    let f1 = spawn_peer(Peer::Good {
        services: FORK,
        gossip: vec![hidden.clone()],
    })
    .await;
    let f2 = spawn_peer(Peer::Good {
        services: FORK,
        gossip: vec![],
    })
    .await;
    let plain = spawn_peer(Peer::Good {
        services: NODE_NETWORK | NODE_WITNESS,
        gossip: vec![],
    })
    .await;
    let hang = spawn_peer(Peer::Hang).await;
    let junk = spawn_peer(Peer::Garbage).await;

    let cfg = EngineConfig {
        crawl: fast_cfg(),
        policy: RetryPolicy {
            fork_secs: 2,
            unknown_retry_secs: 3600,
            nonfork_secs: 3600,
        },
        direct_workers: 3,
        tor_workers: 0,
        i2p_workers: 0,
        allow_unroutable: true,
        getaddr_interval_secs: 0,
        max_idle: Duration::from_millis(200),
        ..EngineConfig::default()
    };
    let engine = Engine::new(Store::new(), cfg);
    engine.add_seeds(&[
        f1.clone(),
        f2.clone(),
        plain.clone(),
        hang.clone(),
        junk.clone(),
    ]);
    let (tx, rx) = watch::channel(false);
    let e = engine.clone();
    let run = tokio::spawn(async move { e.run(rx).await });
    tokio::time::sleep(Duration::from_secs(9)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("engine stops promptly")
        .unwrap();

    let st = lock(&engine.state);
    let get = |a: &NetAddr| st.store.get(a).cloned().expect("known");
    for f in [&f1, &f2] {
        let n = get(f);
        assert_eq!(n.class, Class::Fork);
        assert!(
            n.tries >= 3,
            "{f} tried {} times in 9s with a 2s fork interval",
            n.tries
        );
    }
    let h = get(&hidden);
    assert_eq!(h.class, Class::Fork, "found through gossip and crawled");
    assert_eq!(get(&plain).class, Class::NonFork);
    assert_eq!(
        get(&plain).tries,
        1,
        "non-fork nodes are not re-checked on the fork interval"
    );
    for bad in [&hang, &junk] {
        let n = get(bad);
        assert_eq!(n.class, Class::Unknown);
        assert_eq!(n.successes, 0);
        assert!(n.tries >= 1);
    }
    assert_eq!(
        st.sched.in_flight(lionseed::scheduler::Pool::Direct),
        0,
        "nothing left in flight"
    );
    assert_eq!(
        engine
            .counters
            .panics
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    drop(st); // stats_line takes the lock itself
    println!("{}", engine.stats_line());
}
