//! The anchorwatch command line entry point.
//!
//! Two subcommands exist: `upkeep`, which runs one upkeep pass over
//! a bundle at a pinned as-of instant, and `drift`, which runs one
//! definition-versus-live-schema drift check over exported semantic
//! layer snapshots. Both are dry runs unless `--apply` is given,
//! and both print their report as JSON, or as Markdown with
//! `--format md`. The auditors are the sanctioned stubs until the
//! real trust auditor publishes its interfaces; every report names
//! the auditor it ran against.

use std::path::PathBuf;
use std::process::ExitCode;

use anchorwatch_core::auditor::StubAuditor;
use anchorwatch_core::drift::{StubDriftAuditor, run_drift_check};
use anchorwatch_core::upkeep::{Mode, run_pass};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("upkeep") => run_upkeep(&args[1..]),
        Some("drift") => run_drift(&args[1..]),
        Some("--version") | Some("version") => {
            println!(
                "anchorwatch {} (contract {})",
                env!("CARGO_PKG_VERSION"),
                anchorwatch_core::CONTRACT_VERSION
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "usage: anchorwatch upkeep --bundle <path> --as-of <rfc3339> [--apply] [--format json|md]\n       anchorwatch drift --definitions <path> --live <path> --state <dir> --as-of <rfc3339> [--apply] [--format json|md]"
            );
            ExitCode::FAILURE
        }
    }
}

fn run_upkeep(args: &[String]) -> ExitCode {
    let mut bundle: Option<PathBuf> = None;
    let mut as_of: Option<String> = None;
    let mut mode = Mode::DryRun;
    let mut markdown = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle = args.get(i).map(PathBuf::from);
            }
            "--as-of" => {
                i += 1;
                as_of = args.get(i).cloned();
            }
            "--apply" => mode = Mode::Apply,
            "--format" => {
                i += 1;
                markdown = args.get(i).map(String::as_str) == Some("md");
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let (Some(bundle), Some(as_of)) = (bundle, as_of) else {
        eprintln!("upkeep needs --bundle <path> and --as-of <rfc3339>");
        return ExitCode::FAILURE;
    };
    match run_pass(&bundle, &as_of, &StubAuditor, mode) {
        Ok(report) => {
            if markdown {
                print!("{}", report.to_markdown());
            } else {
                print!("{}", report.to_json());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("upkeep pass failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_drift(args: &[String]) -> ExitCode {
    let mut definitions: Option<PathBuf> = None;
    let mut live: Option<PathBuf> = None;
    let mut state: Option<PathBuf> = None;
    let mut as_of: Option<String> = None;
    let mut mode = Mode::DryRun;
    let mut markdown = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--definitions" => {
                i += 1;
                definitions = args.get(i).map(PathBuf::from);
            }
            "--live" => {
                i += 1;
                live = args.get(i).map(PathBuf::from);
            }
            "--state" => {
                i += 1;
                state = args.get(i).map(PathBuf::from);
            }
            "--as-of" => {
                i += 1;
                as_of = args.get(i).cloned();
            }
            "--apply" => mode = Mode::Apply,
            "--format" => {
                i += 1;
                markdown = args.get(i).map(String::as_str) == Some("md");
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let (Some(definitions), Some(live), Some(state), Some(as_of)) =
        (definitions, live, state, as_of)
    else {
        eprintln!(
            "drift needs --definitions <path>, --live <path>, --state <dir>, and --as-of <rfc3339>"
        );
        return ExitCode::FAILURE;
    };
    match run_drift_check(&definitions, &live, &state, &as_of, &StubDriftAuditor, mode) {
        Ok(report) => {
            if markdown {
                print!("{}", report.to_markdown());
            } else {
                print!("{}", report.to_json());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("drift check failed: {error}");
            ExitCode::FAILURE
        }
    }
}
