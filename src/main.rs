use clap::Parser;
use lionseed::addr::NetAddr;
use lionseed::crawl::CrawlConfig;
use lionseed::engine::{lock, unix_now, Engine, EngineConfig};
use lionseed::node::ChainRules;
use lionseed::scheduler::{RetryPolicy, Tier};
use lionseed::store::Store;
use lionseed::wire;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(version, about = "A DNS seeder for the Bitcoin network")]
struct Args {
    /// Network: main or testnet4
    #[arg(long, default_value = "main")]
    chain: String,
    /// Where the crawl state is kept between runs
    #[arg(long, default_value = "lionseed.snapshot")]
    snapshot: PathBuf,
    /// A node to start crawling from (repeatable), e.g. 1.2.3.4:8333
    #[arg(long = "seed")]
    seeds: Vec<String>,
    /// A DNS name to resolve for starting addresses (repeatable). Defaults to the two existing
    /// BLAKE2b seeds when the crawl state is nearly empty.
    #[arg(long = "bootstrap-dns")]
    bootstrap_dns: Vec<String>,
    /// Concurrent direct (IPv4/IPv6/CJDNS) crawls
    #[arg(long, default_value_t = 128)]
    direct_workers: usize,
    /// Concurrent onion crawls through tor (each costs tor several circuits; keep this small)
    #[arg(long, default_value_t = 8)]
    tor_workers: usize,
    /// Concurrent I2P crawls through i2pd
    #[arg(long, default_value_t = 16)]
    i2p_workers: usize,
    /// Tor SOCKS proxy; "none" to skip onion addresses
    #[arg(long, default_value = "127.0.0.1:9050")]
    onion_proxy: String,
    /// I2P SOCKS proxy; "none" to skip I2P addresses
    #[arg(long, default_value = "127.0.0.1:4447")]
    i2p_proxy: String,
    /// Minutes between checks of a fork node
    #[arg(long, default_value_t = 15)]
    fork_retry_mins: u64,
    /// Hours before retrying an address that has never answered
    #[arg(long, default_value_t = 6)]
    unknown_retry_hours: u64,
    /// Hours between checks of a non-fork node
    #[arg(long, default_value_t = 24)]
    nonfork_retry_hours: u64,
    /// Upper bound on addresses kept
    #[arg(long, default_value_t = 200_000)]
    max_nodes: usize,
    /// Seconds between stats lines
    #[arg(long, default_value_t = 60)]
    stats_every: u64,
    /// Where to write the seeder dump (makeseeds.py / census format)
    #[arg(long, default_value = "lionseed.dump")]
    dump: PathBuf,
    /// Minutes between dumps
    #[arg(long, default_value_t = 15)]
    dump_every_mins: u64,
    /// Serve DNS on this address (UDP and TCP), e.g. 203.0.113.10:53. Without it LionSeed only crawls.
    #[arg(long)]
    dns_bind: Option<SocketAddr>,
    /// The seed's own name, e.g. seed.example.org (required with --dns-bind)
    #[arg(long)]
    host: Option<String>,
    /// The name of this nameserver, which the seed name is delegated to (required with --dns-bind)
    #[arg(long)]
    ns: Option<String>,
    /// Contact email published in the SOA record (required with --dns-bind)
    #[arg(long)]
    mbox: Option<String>,
    /// DNS queries per second allowed per source address
    #[arg(long, default_value_t = 10.0)]
    dns_rate: f64,
}

fn proxy(s: &str) -> Result<Option<SocketAddr>, String> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .map_err(|_| format!("bad proxy address: {s}"))
}

/// CPU seconds used by this process so far and its resident memory in MB (Linux /proc).
fn self_usage() -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = stat.rsplit_once(')')?.1;
    let f: Vec<&str> = after.split_whitespace().collect();
    let ticks: f64 = f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?;
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some((ticks / 100.0, rss_pages * 4096 / (1024 * 1024)))
}

async fn resolve(names: &[String], port: u16) -> Vec<NetAddr> {
    let mut out = Vec::new();
    for name in names {
        match tokio::time::timeout(
            Duration::from_secs(20),
            tokio::net::lookup_host((name.as_str(), port)),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                let before = out.len();
                out.extend(addrs.filter_map(|a| a.to_string().parse::<NetAddr>().ok()));
                println!("bootstrap: {name} gave {} addresses", out.len() - before);
            }
            Ok(Err(e)) => println!("bootstrap: {name} failed: {e}"),
            Err(_) => println!("bootstrap: {name} timed out"),
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let (magic, port, min_height, default_dns): (_, _, _, &[&str]) = match args.chain.as_str() {
        "main" => (
            wire::MAGIC_MAIN,
            8333,
            961_640,
            &[
                "x10000009.dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
                "x10000009.seed.bitcoin.haf.ovh",
            ],
        ),
        other => {
            eprintln!("unsupported chain: {other} (only main for now)");
            std::process::exit(2);
        }
    };
    let (onion_proxy, i2p_proxy) = match (proxy(&args.onion_proxy), proxy(&args.i2p_proxy)) {
        (Ok(o), Ok(i)) => (o, i),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let store = match Store::load(&args.snapshot) {
        Ok(s) => s,
        Err(e) => {
            // Keep the unreadable file for inspection and start fresh rather than crash-loop.
            let aside = args.snapshot.with_extension("snapshot.unreadable");
            let _ = std::fs::rename(&args.snapshot, &aside);
            eprintln!(
                "snapshot unreadable ({e}); moved to {} and starting empty",
                aside.display()
            );
            Store::new()
        }
    };
    println!(
        "loaded {} addresses from {}",
        store.len(),
        args.snapshot.display()
    );
    let small = store.len() < 100;

    let cfg = EngineConfig {
        crawl: CrawlConfig {
            magic,
            onion_proxy,
            i2p_proxy,
            ..CrawlConfig::default()
        },
        policy: RetryPolicy {
            fork_secs: args.fork_retry_mins * 60,
            unknown_retry_secs: args.unknown_retry_hours * 3600,
            nonfork_secs: args.nonfork_retry_hours * 3600,
        },
        rules: ChainRules {
            default_port: port,
            min_height,
            max_silence_secs: 3600,
        },
        direct_workers: args.direct_workers,
        tor_workers: args.tor_workers,
        i2p_workers: args.i2p_workers,
        max_nodes: args.max_nodes,
        snapshot_path: Some(args.snapshot.clone()),
        ..EngineConfig::default()
    };
    let engine = Engine::new(store, cfg);

    let mut seeds: Vec<NetAddr> = Vec::new();
    for s in &args.seeds {
        match s.parse() {
            Ok(a) => seeds.push(a),
            Err(e) => eprintln!("ignoring --seed {s}: {e}"),
        }
    }
    let dns: Vec<String> = if !args.bootstrap_dns.is_empty() {
        args.bootstrap_dns.clone()
    } else if small {
        default_dns.iter().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };
    seeds.extend(resolve(&dns, port).await);
    engine.add_seeds(&seeds);
    {
        // Seeds already known but never tried get queued now too.
        let mut st = lock(&engine.state);
        for s in &seeds {
            if st.store.get(s).is_some_and(|n| n.last_try == 0) {
                st.sched.schedule(s.clone(), Tier::NewUnknown, 0);
            }
        }
    }

    let (tx, rx) = watch::channel(false);
    let e = engine.clone();
    let stats_every = Duration::from_secs(args.stats_every.max(5));
    let mut stats_rx = rx.clone();
    let stats = tokio::spawn(async move {
        let mut last = self_usage().map(|u| u.0).unwrap_or(0.0);
        let mut last_t = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(stats_every) => {}
                _ = stats_rx.changed() => return,
            }
            let (cpu_pct, rss) = match self_usage() {
                Some((cpu, rss)) => {
                    let pct = (cpu - last) / last_t.elapsed().as_secs_f64() * 100.0;
                    last = cpu;
                    last_t = std::time::Instant::now();
                    (pct, rss)
                }
                None => (0.0, 0),
            };
            println!(
                "{} stats {} cpu={cpu_pct:.1}% rss={rss}MB",
                unix_now(),
                e.stats_line()
            );
        }
    });

    // Dumps on a timer (and once more on the way out, below).
    let e = engine.clone();
    let dump_path = args.dump.clone();
    let dump_every = Duration::from_secs(args.dump_every_mins.max(1) * 60);
    let mut dump_rx = rx.clone();
    let dumper = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(dump_every) => {}
                _ = dump_rx.changed() => return,
            }
            e.dump_now(dump_path.clone()).await;
        }
    });

    // DNS: an answer snapshot refreshed every minute, served over UDP and TCP.
    if let Some(bind) = args.dns_bind {
        let (Some(host), Some(ns), Some(mbox)) =
            (args.host.clone(), args.ns.clone(), args.mbox.clone())
        else {
            eprintln!("--dns-bind needs --host, --ns and --mbox");
            std::process::exit(2);
        };
        let dns_cfg = std::sync::Arc::new(lionseed::dns::DnsConfig {
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            ns: ns.trim_end_matches('.').to_ascii_lowercase(),
            mbox,
            ttl: 60,
            ns_ttl: 40000,
            rate_per_sec: args.dns_rate,
        });
        let answers: lionseed::dns::SharedAnswers =
            std::sync::Arc::new(std::sync::RwLock::new(engine.good_answers()));
        let e = engine.clone();
        let a = answers.clone();
        let mut refresh_rx = rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                    _ = refresh_rx.changed() => return,
                }
                let fresh = e.good_answers();
                *a.write().unwrap_or_else(|p| p.into_inner()) = fresh;
            }
        });
        let limiter = std::sync::Arc::new(lionseed::dns::RateLimiter::new(args.dns_rate));
        for udp in [true, false] {
            let (c, a, l) = (dns_cfg.clone(), answers.clone(), limiter.clone());
            tokio::spawn(async move {
                let res = if udp {
                    lionseed::dns::serve_udp(bind, c, a, l).await
                } else {
                    lionseed::dns::serve_tcp(bind, c, a, l).await
                };
                if let Err(e) = res {
                    eprintln!(
                        "dns {}: cannot serve on {bind}: {e}",
                        if udp { "udp" } else { "tcp" }
                    );
                    std::process::exit(1);
                }
            });
        }
        println!("serving DNS for {} on {bind}", dns_cfg.host);
    } else {
        println!("crawl only: no --dns-bind given");
    }

    let run_engine = engine.clone();
    let run = tokio::spawn(async move { run_engine.run(rx).await });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending::<()>().await } } => {}
    }
    println!("stopping: finishing in-flight crawls and saving state");
    let _ = tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(90), run).await;
    let _ = stats.await;
    let _ = dumper.await;
    engine.dump_now(args.dump.clone()).await;
    println!("stopped. {}", engine.stats_line());
}
