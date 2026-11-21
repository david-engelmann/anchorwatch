//! The anchorwatch command line entry point.
//!
//! Subcommands arrive with the engine milestones. The scaffold build
//! reports its name and contract version and nothing more.

fn main() {
    println!(
        "anchorwatch {} (contract {})",
        env!("CARGO_PKG_VERSION"),
        anchorwatch_core::CONTRACT_VERSION
    );
}
