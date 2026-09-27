//! The crawler engine: worker pools pulling from the scheduler, results applied to the store.
//!
//! Concurrency rules, learned the hard way:
//! - All shared state (store and scheduler) sits behind one `std::sync::Mutex` that is only ever held
//!   for short in-memory updates. It is never held across an `.await`, and no I/O happens under it.
//! - Workers pull work. When nothing is due they sleep until it is (capped, so new work is noticed
//!   within seconds). Nothing polls in a tight loop.
//! - Each crawl runs in its own task, so even an unexpected panic inside it becomes an ordinary
//!   failed attempt for that address and the worker carries on.

use crate::addr::{Net, NetAddr};
use crate::crawl::{self, CrawlConfig, Outcome};
use crate::node::{ChainRules, Class};
use crate::scheduler::{due_for, Next, Pool, RetryPolicy, Scheduler, Tier};
use crate::store::Store;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub crawl: CrawlConfig,
    pub policy: RetryPolicy,
    pub rules: ChainRules,
    pub direct_workers: usize,
    /// Concurrent onion crawls. Each one costs tor several circuits; tor allows 32 pending by
    /// default, and 32 onion crawls at once kept it permanently overloaded.
    pub tor_workers: usize,
    pub i2p_workers: usize,
    /// Ask a node for addresses at most this often.
    pub getaddr_interval_secs: u64,
    /// Upper bound on the address table.
    pub max_nodes: usize,
    /// Accept loopback/private addresses (tests, private networks). Never for a public seed.
    pub allow_unroutable: bool,
    pub snapshot_path: Option<PathBuf>,
    pub snapshot_every: Duration,
    /// Longest a worker sleeps before asking for work again.
    pub max_idle: Duration,
}

impl Default for EngineConfig {
    fn default() -> EngineConfig {
        EngineConfig {
            crawl: CrawlConfig::default(),
            policy: RetryPolicy::default(),
            rules: ChainRules {
                default_port: 8333,
                min_height: 961640,
                max_silence_secs: 3600,
            },
            direct_workers: 128,
            tor_workers: 8,
            i2p_workers: 16,
            getaddr_interval_secs: 24 * 3600,
            max_nodes: 200_000,
            allow_unroutable: false,
            snapshot_path: None,
            snapshot_every: Duration::from_secs(300),
            max_idle: Duration::from_secs(2),
        }
    }
}

pub struct State {
    pub store: Store,
    pub sched: Scheduler,
}

/// Counters for the stats line, cheap to update from any task.
#[derive(Default)]
pub struct Counters {
    pub attempts: AtomicU64,
    pub successes: AtomicU64,
    pub panics: AtomicU64,
    pub gossip_new: AtomicU64,
}

#[derive(Clone)]
pub struct Engine {
    pub state: Arc<Mutex<State>>,
    pub cfg: Arc<EngineConfig>,
    pub counters: Arc<Counters>,
}

/// Lock the state, recovering it if a previous holder panicked (the data is plain values and every
/// update is a small, self-contained step, so it is safe to keep using).
pub fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Engine {
    /// Build an engine from a loaded store, queueing every known address by its class.
    pub fn new(store: Store, cfg: EngineConfig) -> Engine {
        let mut sched = Scheduler::new();
        for (addr, node) in store.iter() {
            if crawl::reachable(addr.net(), &cfg.crawl) {
                let (tier, due) = due_for(node, &cfg.policy);
                sched.schedule(addr.clone(), tier, due);
            }
        }
        Engine {
            state: Arc::new(Mutex::new(State { store, sched })),
            cfg: Arc::new(cfg),
            counters: Arc::new(Counters::default()),
        }
    }

    /// Add operator-given seed addresses. New ones are crawled first thing.
    pub fn add_seeds(&self, seeds: &[NetAddr]) {
        let now = unix_now();
        let mut st = lock(&self.state);
        for a in seeds {
            if st.store.add(a.clone(), 0, now, self.cfg.allow_unroutable) {
                st.sched.schedule(a.clone(), Tier::NewUnknown, 0);
            }
        }
    }

    /// Run until `shutdown` becomes true. Spawns the worker pools and the snapshot task.
    pub async fn run(&self, shutdown: watch::Receiver<bool>) {
        let mut handles = Vec::new();
        let tor = if self.cfg.crawl.onion_proxy.is_some() {
            self.cfg.tor_workers
        } else {
            0
        };
        let i2p = if self.cfg.crawl.i2p_proxy.is_some() {
            self.cfg.i2p_workers
        } else {
            0
        };
        for (pool, n) in [
            (Pool::Direct, self.cfg.direct_workers),
            (Pool::Tor, tor),
            (Pool::I2p, i2p),
        ] {
            for _ in 0..n {
                let e = self.clone();
                let sd = shutdown.clone();
                handles.push(tokio::spawn(async move { e.worker(pool, sd).await }));
            }
        }
        let e = self.clone();
        let sd = shutdown.clone();
        handles.push(tokio::spawn(async move { e.snapshot_loop(sd).await }));
        for h in handles {
            let _ = h.await;
        }
        // Final snapshot on the way out so a clean stop loses nothing.
        self.snapshot_now().await;
    }

    async fn worker(&self, pool: Pool, mut shutdown: watch::Receiver<bool>) {
        loop {
            // A dropped sender counts as a stop: otherwise `changed()` would return at once on
            // every sleep and the worker would spin.
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return;
            }
            let now = unix_now();
            let next = lock(&self.state).sched.next(pool, now);
            match next {
                Next::Crawl(addr) => self.crawl_one(addr).await,
                Next::WaitUntil(t) => {
                    let wait = Duration::from_secs(t.saturating_sub(now)).min(self.cfg.max_idle);
                    self.sleep_or_stop(wait.max(Duration::from_millis(200)), &mut shutdown)
                        .await;
                }
                Next::Idle => self.sleep_or_stop(self.cfg.max_idle, &mut shutdown).await,
            }
        }
    }

    async fn sleep_or_stop(&self, d: Duration, shutdown: &mut watch::Receiver<bool>) {
        tokio::select! {
            _ = tokio::time::sleep(d) => {}
            _ = shutdown.changed() => {}
        }
    }

    async fn crawl_one(&self, addr: NetAddr) {
        let start = unix_now();
        let want_addrs = {
            let st = lock(&self.state);
            st.store
                .get(&addr)
                .map(|n| start.saturating_sub(n.last_getaddr) >= self.cfg.getaddr_interval_secs)
                .unwrap_or(false)
        };
        self.counters.attempts.fetch_add(1, Ordering::Relaxed);
        let cfg = self.cfg.clone();
        let a = addr.clone();
        let outcome = match tokio::spawn(async move {
            crawl::crawl(&a, want_addrs, &cfg.crawl, start).await
        })
        .await
        {
            Ok(o) => o,
            Err(e) => {
                self.counters.panics.fetch_add(1, Ordering::Relaxed);
                Outcome::Failure(format!("crawl task ended abnormally: {e}"))
            }
        };
        self.apply(addr, outcome, start);
    }

    /// Record the result and put the address back in the queue. Always runs, whatever happened.
    fn apply(&self, addr: NetAddr, outcome: Outcome, start: u64) {
        let now = unix_now();
        let mut st = lock(&self.state);
        let State { store, sched } = &mut *st;
        sched.finished(&addr);
        let mut new_addrs = Vec::new();
        {
            let Some(node) = store.get_mut(&addr) else {
                return; // pruned while in flight
            };
            match outcome {
                Outcome::Success {
                    handshake,
                    gossip,
                    asked_for_addrs,
                } => {
                    self.counters.successes.fetch_add(1, Ordering::Relaxed);
                    node.record_success(start, handshake);
                    if asked_for_addrs {
                        node.last_getaddr = start;
                    }
                    new_addrs = gossip;
                }
                Outcome::Failure(_) => node.record_failure(start),
            }
            let (tier, due) = due_for(node, &self.cfg.policy);
            sched.schedule(addr, tier, due);
        }
        for (a, services) in new_addrs {
            if crawl::reachable(a.net(), &self.cfg.crawl)
                && store.add(a.clone(), services, now, self.cfg.allow_unroutable)
            {
                self.counters.gossip_new.fetch_add(1, Ordering::Relaxed);
                sched.schedule(a, Tier::NewUnknown, 0);
            }
        }
    }

    async fn snapshot_loop(&self, mut shutdown: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.cfg.snapshot_every) => {}
                _ = shutdown.changed() => return,
            }
            self.snapshot_now().await;
        }
    }

    /// Prune if over the cap, encode the snapshot under the lock (no copy of the table), then write
    /// it to disk off the async workers.
    pub async fn snapshot_now(&self) {
        let bytes = {
            let mut st = lock(&self.state);
            let dropped = st.store.prune(self.cfg.max_nodes);
            for a in &dropped {
                st.sched.forget(a);
            }
            if self.cfg.snapshot_path.is_none() {
                return;
            }
            st.store.encode()
        };
        let (Some(path), Ok(bytes)) = (self.cfg.snapshot_path.clone(), bytes) else {
            eprintln!("snapshot: encoding failed");
            return;
        };
        let res =
            tokio::task::spawn_blocking(move || crate::store::write_snapshot(&path, &bytes)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("snapshot: write failed: {e}"),
            Err(e) => eprintln!("snapshot: task failed: {e}"),
        }
    }

    /// The nodes to hand out right now, for the DNS server.
    pub fn good_answers(&self) -> crate::dns::Answers {
        let now = unix_now();
        let st = lock(&self.state);
        let nodes = st
            .store
            .iter()
            .filter(|(a, n)| n.is_good(a, &self.cfg.rules, now))
            .map(|(a, n)| (a.clone(), n.services))
            .collect();
        crate::dns::Answers {
            nodes,
            serial: (now & 0xffff_ffff) as u32,
        }
    }

    /// Write the dump. Rows are copied under the lock and written off the async workers.
    pub async fn dump_now(&self, path: PathBuf) {
        let rows: Vec<(NetAddr, crate::node::NodeRecord)> = {
            let st = lock(&self.state);
            st.store
                .iter()
                .filter(|(_, n)| n.tries > 0)
                .map(|(a, n)| (a.clone(), n.clone()))
                .collect()
        };
        let rules = self.cfg.rules.clone();
        let now = unix_now();
        let res = tokio::task::spawn_blocking(move || {
            crate::dump::write(&path, rows.iter().map(|(a, n)| (a, n)), &rules, now)
        })
        .await;
        match res {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("dump: write failed: {e}"),
            Err(e) => eprintln!("dump: task failed: {e}"),
        }
    }

    /// One line of numbers for the log.
    pub fn stats_line(&self) -> String {
        let now = unix_now();
        let st = lock(&self.state);
        let (mut unknown, mut nonfork, mut fork, mut good, mut fork_fresh) = (0, 0, 0, 0, 0);
        let (mut good_onion, mut good_i2p) = (0, 0);
        for (a, n) in st.store.iter() {
            match n.class {
                Class::Unknown => unknown += 1,
                Class::NonFork => nonfork += 1,
                Class::Fork => {
                    fork += 1;
                    if now.saturating_sub(n.last_try) <= self.cfg.policy.fork_secs + 120 {
                        fork_fresh += 1;
                    }
                }
            }
            if n.is_good(a, &self.cfg.rules, now) {
                good += 1;
                match a.net() {
                    Net::Onion => good_onion += 1,
                    Net::I2p => good_i2p += 1,
                    _ => {}
                }
            }
        }
        format!(
            "nodes={} unknown={unknown} nonfork={nonfork} fork={fork} fork_checked_on_time={fork_fresh} good={good} \
             good_onion={good_onion} good_i2p={good_i2p} queued={} inflight_direct={} inflight_tor={} inflight_i2p={} attempts={} successes={} new_from_gossip={} panics={}",
            st.store.len(),
            st.sched.queued(),
            st.sched.in_flight(Pool::Direct),
            st.sched.in_flight(Pool::Tor),
            st.sched.in_flight(Pool::I2p),
            self.counters.attempts.load(Ordering::Relaxed),
            self.counters.successes.load(Ordering::Relaxed),
            self.counters.gossip_new.load(Ordering::Relaxed),
            self.counters.panics.load(Ordering::Relaxed),
        )
    }
}
