//! Networking layer for IONA.
//!
//! This module provides the P2P networking stack, peer management, state sync,
//! and simulation utilities.
//!
//! # Submodules
//!
//! - `p2p` – Production P2P networking (libp2p‑based).
//! - `state_sync` – Fast state sync over the network.
//! - `peer_score` – Peer scoring and reputation management.
//! - `inmem` – In‑memory network for integration testing.
//! - `simnet` – Simulated network for chaos testing.
//! - `eclipse_profiles` – Eclipse attack protection profiles.
//! - `peerstore` – Persistent peer address storage.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::net::p2p::P2pNetwork;
//! use iona::net::peer_score::PeerScore;
//! use iona::net::peerstore::PeerStore;
//! ```

pub mod p2p;
pub mod state_sync;
pub mod peer_score;
pub mod inmem;
pub mod simnet;
pub mod eclipse_profiles;
pub mod peerstore;

// Re‑export core types from submodules for convenience.
pub use inmem::InMemNet;
pub use peer_score::PeerScore;
pub use peerstore::PeerStore;
