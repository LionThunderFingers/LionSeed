# LionSeed

A DNS seeder for the Bitcoin network.

A new node asks a few DNS seeds for addresses before it knows any peers. LionSeed crawls the
network, keeps track of which nodes are really post-fork and reliably up, and answers
those DNS queries with them. It also writes a dump that Knots' `contrib/seeds/makeseeds.py` can use
to build the fixed seed list, including Tor and I2P nodes.

It is a new program written for this network, not a patch to an older seeder. Its design draws on
lessons from Pieter Wuille's bitcoin-seeder and Ava Chow's dnsseedrs; no code from either is used.

## Running live

LionSeed runs `seed.thelionpool.org`:

- How that seed is operated: https://lionthunderfingers.github.io/Bitcoin-Node-census/seed/
- A census of the network built from its crawl data: https://lionthunderfingers.github.io/Bitcoin-Node-census/

## What it does

- **Serves only proven post-fork nodes.** A node counts as post-fork only if its own VERSION handshake
  advertised the BLAKE2b service bit (bit 28) and a height past the fork. Bits claimed in address
  gossip never count. User agents are never looked at.
- **Keeps answers fresh.** Post-fork nodes are re-checked every 15 minutes, and a node that has not
  answered for an hour is not served, whatever its history.
- **Spends its effort where it matters.** Post-fork nodes first, then addresses never tried, then failed
  ones every 6 hours, then pre-fork nodes once a day. It asks each node for addresses at most once a
  day.
- **Crawls clearnet, Tor v3 and I2P** (the last two through a local tor or i2pd).
- **Stays small.** State lives in memory and is saved to disk every 5 minutes with an atomic rename.
  On a live crawl of about 200k addresses across clearnet, Tor and I2P it uses about 2% of a CPU
  core and around 200 MB of memory. The address table is capped (`--max-nodes`).
- **Standard DNS.** A, AAAA, NS and SOA for the seed name and `x<hex>` service-flag names such as
  `x10000009`, over UDP and TCP, with per-source rate limiting. One answer per /16 (or /32 for
  IPv6) so answers are spread across networks.

## Requirements

- A VPS with a static public IPv4 address, directly reachable on UDP and TCP port 53.
- A domain where you can create an A record and an NS record.
- Debian 13 with 2 GB of RAM (building the program needs it; running it uses far less).

Do not run a seed on a home connection: it publishes the address permanently, and home addresses
change.

## Installing

```
git clone <this repository> lionseed
cd lionseed
sudo CONTACT_EMAIL=you@example.org SEED_HOST=seed.example.org NS_HOST=ns-seed.example.org \
     WITH_TOR=1 WITH_I2P=1 ./deploy/deploy.sh
```

The script installs the build tools and a pinned Rust toolchain, builds LionSeed, creates a
`lionseed` system user and a hardened systemd unit, and optionally installs tor and i2pd. It does not
start the service.

Then create the delegation at your DNS provider:

```
ns-seed.example.org   A    <your VPS address>
seed.example.org      NS   ns-seed.example.org
```

and start it:

```
sudo systemctl start lionseed
journalctl -u lionseed -f
```

A new seed needs about half an hour before nodes have been checked enough times to be served. The
log prints a stats line every minute: addresses known, post-fork nodes, how many were re-checked on time,
how many are good enough to serve, and the process's own CPU and memory.

Only one program can answer on port 53 of an address. Stop any other seeder on the same address
first.

## Monitoring

With `HEALTHCHECK_PING_URL=https://hc-ping.com/<uuid>` set, the deploy script installs a timer that
checks every 5 minutes that the service is running, the dump is recent, it has good nodes (and good
onion and I2P nodes, when those are enabled), and DNS answers, and pings the URL only when all of
that is true. On healthchecks.io set the period to
5 minutes and the grace to 15. The check never restarts or repairs anything.

## Options

`lionseed --help` lists everything. The main ones:

| Option | Default | Meaning |
| --- | --- | --- |
| `--dns-bind` | none | Address to serve DNS on. Without it LionSeed only crawls. |
| `--host`, `--ns`, `--mbox` | | Seed name, nameserver name, contact email (needed with `--dns-bind`). |
| `--snapshot` | `lionseed.snapshot` | Crawl state kept between runs. |
| `--dump` | `lionseed.dump` | Dump for makeseeds.py and census tools, rewritten every 15 minutes. |
| `--direct-workers` | 128 | Concurrent clearnet crawls. |
| `--tor-workers` / `--i2p-workers` | 8 / 16 | Concurrent onion / I2P crawls. Keep Tor low: each onion connection costs tor several circuits, and too many at once overload it. |
| `--onion-proxy` / `--i2p-proxy` | 127.0.0.1:9050 / 127.0.0.1:4447 | `none` skips that network. |
| `--fork-retry-mins` | 15 | How often post-fork nodes are re-checked. |
| `--max-nodes` | 200000 | Cap on tracked addresses. Over it, addresses that never answered are dropped, most failed first. |
| `--seed` / `--bootstrap-dns` | the two existing post-fork-serving seeds | Where a fresh crawl starts. |

## Running it responsibly

Seed operators are trusted with a new node's first view of the network. Follow the Knots policy:
https://github.com/bitcoinknots/bitcoin/blob/29.x-knots/doc/dnsseed-policy.md

In short, the policy asks you to: follow good host security practice and keep control of the seed
(do not sell or hand it over), hand out a fair selection of working nodes (LionSeed does not filter
by implementation or user agent), keep TTLs at 60 seconds or more, only log DNS queries as far as
running the service needs and never share them (LionSeed does not log them at all), and publish a
contact address you actually read. Publishing your crawl data is allowed, and documenting how you
run the seed is encouraged.

Some advice beyond the policy: keep the host patched and do not run other public services on it,
since whoever controls the host controls what new nodes are told about the network. If you want to
publish the dump, push it somewhere else (a static site works) rather than serving it from the
seed. And pick a hosting provider other seed operators do not already use.

## Development

```
cargo test
```

The tests include a simulated network of well-behaved, hanging, garbage-sending, oversized and slow
peers that the real crawler and engine run against.
