//! anchorwatch-core holds the upkeep engine's deterministic core.
//!
//! The engine runs scheduled upkeep passes over OKF v0.3 knowledge
//! bundles. It recomputes verification lapses past each concept's
//! review date, applies and audits declared supersessions,
//! regenerates bundle indexes and the bundle log, and maintains a
//! re-verification queue for a human or agent to work.
//!
//! The core never writes meaning, never stamps verification events,
//! never sets review dates, and never chooses supersession targets.
//! Judging whether content is still true belongs to the trust
//! auditor, reached through a versioned interface. This crate holds
//! no state of its own and performs no network or model calls, so a
//! pass over the same bundle with the same pinned date always
//! produces the same result.

pub mod auditor;
pub mod bundle;
pub mod drift;
pub mod frontmatter;
pub mod json;
pub mod migrate;
pub mod perishables;
pub mod queue;
pub mod sha256;
pub mod time;
pub mod upkeep;

/// The version of the upkeep contract this build implements.
pub const CONTRACT_VERSION: &str = "0.1.0";
