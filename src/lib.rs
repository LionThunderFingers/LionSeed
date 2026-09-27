//! LionSeed: a DNS seeder for the Bitcoin Knots BLAKE2b network.
//!
//! The crate is split so the parts that decide what gets served can be tested without a network:
//! `addr` (addresses on every network we crawl), `node` (what we know about one address and whether
//! it is good), `scheduler` (when each address is crawled next) and `store` (the table of all of
//! them and its snapshot on disk).

pub mod addr;
pub mod node;
pub mod scheduler;
pub mod store;
