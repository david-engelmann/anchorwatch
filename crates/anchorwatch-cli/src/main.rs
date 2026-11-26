//! The anchorwatch command line entry point.
//!
//! Three subcommands exist: `upkeep`, which runs one upkeep pass
//! over a bundle at a pinned as-of instant, `drift`, which runs
//! one definition-versus-live-schema drift check over exported
//! semantic layer snapshots, and `migrate`, which converts a
//! memory-shaped tree into a bundle under a source profile and
//! ships a loss ledger with it. Upkeep and drift are dry runs
//! unless `--apply` is given, and every subcommand prints its
//! report as JSON, or as Markdown with `--format md`. The
//! auditors are the sanctioned stubs until the real trust auditor
//! publishes its interfaces; every report names the auditor it
//! ran against.

use std::path::PathBuf;
use std::process::ExitCode;

use anchorwatch_core::drift::{StubDriftAuditor, run_drift_check};
use anchorwatch_core::migrate::{ClaudeMemoryProfile, OkfNativeProfile, Profile, run_migration};
use anchorwatch_core::perishables::PerishablesAuditor;
use anchorwatch_core::upkeep::{Mode, run_pass};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("upkeep") => run_upkeep(&args[1..]),
        Some("drift") => run_drift(&args[1..]),
        Some("migrate") => run_migrate(&args[1..]),
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
                "usage: anchorwatch upkeep --bundle <path> --as-of <rfc3339> [--apply] [--format json|md]\n       anchorwatch drift --definitions <path> --live <path> --state <dir> --as-of <rfc3339> [--apply] [--format json|md]\n       anchorwatch migrate --profile <name> --source <dir> --out <dir> --as-of <rfc3339> [--format json|md]"
            );
            ExitCode::FAILURE
        }
    }
}

/// Reads a `--format` value as whether the report prints as
/// Markdown. The two known values are the two formats the tool
/// prints; anything else, or no value at all, is refused rather
/// than silently treated as JSON, so a mistyped format never
/// yields the wrong artefact under a success exit.
fn parse_format(value: Option<&String>) -> Result<bool, ExitCode> {
    match value.map(String::as_str) {
        Some("md") => Ok(true),
        Some("json") => Ok(false),
        Some(other) => {
            eprintln!("unknown format: {other} (known: json, md)");
            Err(ExitCode::FAILURE)
        }
        None => {
            eprintln!("--format needs a value (json or md)");
            Err(ExitCode::FAILURE)
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
                match parse_format(args.get(i)) {
                    Ok(md) => markdown = md,
                    Err(code) => return code,
                }
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
    match run_pass(&bundle, &as_of, &PerishablesAuditor, mode) {
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
                match parse_format(args.get(i)) {
                    Ok(md) => markdown = md,
                    Err(code) => return code,
                }
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

fn run_migrate(args: &[String]) -> ExitCode {
    let mut profile_name: Option<String> = None;
    let mut source: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut as_of: Option<String> = None;
    let mut markdown = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                i += 1;
                profile_name = args.get(i).cloned();
            }
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--as-of" => {
                i += 1;
                as_of = args.get(i).cloned();
            }
            "--format" => {
                i += 1;
                match parse_format(args.get(i)) {
                    Ok(md) => markdown = md,
                    Err(code) => return code,
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let (Some(profile_name), Some(source), Some(out), Some(as_of)) =
        (profile_name, source, out, as_of)
    else {
        eprintln!(
            "migrate needs --profile <name>, --source <dir>, --out <dir>, and --as-of <rfc3339>"
        );
        return ExitCode::FAILURE;
    };
    let profile: Box<dyn Profile> = match profile_name.as_str() {
        "claude-memory" => Box::new(ClaudeMemoryProfile),
        "okf-native" => Box::new(OkfNativeProfile),
        other => {
            eprintln!("unknown profile: {other} (known: claude-memory, okf-native)");
            return ExitCode::FAILURE;
        }
    };
    match run_migration(profile.as_ref(), &source, &out, &as_of) {
        Ok(report) => {
            if markdown {
                print!("{}", report.to_markdown());
            } else {
                print!("{}", report.to_json());
            }
            if report.gate_failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("migration failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_format;

    #[test]
    fn known_formats_parse_and_unknown_ones_refuse() {
        assert_eq!(parse_format(Some(&"md".to_string())).ok(), Some(true));
        assert_eq!(parse_format(Some(&"json".to_string())).ok(), Some(false));
        assert!(parse_format(Some(&"yaml".to_string())).is_err());
        assert!(parse_format(None).is_err());
    }
}
