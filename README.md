# anchorwatch

anchorwatch is a deterministic upkeep engine for knowledge bundles written in the Open Knowledge Format, OKF v0.3. A bundle that nobody maintains quietly goes stale. Facts pass their review dates, verification lapses, one document replaces another without the replacement being recorded, and the index drifts away from the files it lists. anchorwatch runs the scheduled pass that catches all of that and writes down what it did.

## The upkeep pass

An upkeep pass walks a bundle and performs the maintenance the OKF spec leaves to the bundle owner. It recomputes which concepts have passed their `stale_after` review date, working from the trust auditor's freshness findings. It checks the currency of each concept's verification against the auditor and queues anything lapsed for re-verification. It audits the supersessions the bundle declares for defects such as cycles, missing targets, and current documents pointing at deprecated ones. It checks declared provenance for sources that no longer resolve and for content that has drifted from its recorded hash. It regenerates bundle indexes whose link sets have drifted, leaving any index that carries hand-written prose untouched. And when a concept's type key has been stripped, it restores the key from the migrator's manifest and logs the repair, the one frontmatter change the engine is allowed to make on its own.

Everything the pass decides a human should look at lands in a re-verification queue, a Markdown file with a JSON twin kept in the bundle's own state directory, with a reason for every item and the evidence behind it. Items keep the date they were first raised across passes, keep any state a human has set on them, and close only when a later pass observes that the condition is gone.

The pass is deterministic. Run it twice over the same bundle with the same pinned date and the report is byte identical, so it can run unattended from cron or CI and its output can be diffed and reviewed like any other change. A dry run writes nothing. Apply mode writes the queue, the pass state, the regenerated indexes, any type restoration, and a dated entry in the bundle log, newest first as the spec requires.

The engine has hard limits it never crosses on its own. It never edits the meaning of a document, never stamps a verification event, never invents a review date, never chooses what supersedes what, and never deletes a file. Anything needing judgement becomes a queue item for a human or an agent to decide.

## The drift check

anchorwatch also checks semantic layer definitions against the live warehouse schema they describe, the upkeep half of a cross-ecosystem grading programme. Definitions drift from the warehouse quietly. A column a metric depends on is renamed or dropped, a declared type stops matching the live one, and nothing notices until a dashboard breaks. The check compares an exported definition against an exported live schema and queues every divergence as a drift item, with a rename proposal where exactly one plausible rename exists.

The engine never connects to a warehouse and never holds a vendor credential. Both sides are exported files. Definitions are read in the shapes the vendors export, dbt and Ossie semantic manifests, Snowflake semantic view definitions, Databricks metric views, and Genie space exports, routed by the document's own contents rather than its file name. The live side is one documented JSON shape listing relations and their columns.

## How it is used

```text
anchorwatch upkeep --bundle ./bundle --as-of 2026-11-24T00:00:00Z
anchorwatch upkeep --bundle ./bundle --as-of 2026-11-24T00:00:00Z --apply
anchorwatch upkeep --bundle ./bundle --as-of 2026-11-24T00:00:00Z --attest
anchorwatch drift --definitions ./manifest.json --live ./live-schema.json --state ./drift-state --as-of 2026-11-24T00:00:00Z --apply
anchorwatch migrate --profile claude-memory --source ./memory-tree --out ./bundle --as-of 2026-11-24T00:00:00Z
```

The upkeep command runs one pass over a bundle. Without --apply it reports and writes nothing. With --attest it also re-executes the bundle's declared computations through the auditor's executor and queues any claimed result that does not recompute; attestation is off by default, because a scheduled pass should not spawn an interpreter unattended. The drift command runs one comparison and keeps its own queue and state in the directory named by --state. The migrate command converts one tree with the named profile and prints its run report, listing the construct classes found against the ledger entries written. All three commands print a JSON report by default and a Markdown report with --format md. Scheduling is left to the owner, through cron, a CI schedule, or any other runner, because the engine itself is a single run that ends.

## The migrator

The programme's other half is a migrator that converts an existing knowledge tree into an OKF v0.3 bundle. Conversion is driven by a source profile, and every construct the profile finds is accounted for in a loss ledger that ships with the bundle in Markdown and JSON forms. Each entry names the construct, how often it occurred, what happened to it, and whether losing it was load-bearing. A run that cannot account for every construct it found fails before it writes anything. A ledger claiming nothing was lost fails the run's honesty gate, and a load-bearing construct recorded as lost fails it too, visibly, in the report and in the command's exit status.

Two profiles ship with the tool. The claude-memory profile converts a Muse memory tree, with people and groups mapped or preserved as extension keys and the curated memory file and the dated daily logs split into one concept per section at their own headings. The okf-native profile converts a bundle that is already OKF, at any declared version, carrying concepts, assets, log history, and bundle metadata across, and rewriting the path values whose meaning changed between 0.2 and 0.3 so they name the same targets under the new reading.

## Building

```text
cargo build --release
cargo test
```

The workspace holds two crates. anchorwatch-core carries the engine, the auditor contract, the drift check, and the migrator. anchorwatch-cli carries the command line entry point. The core's one dependency is the perishables core library, the trust auditor whose checks the engine consumes through the contract, pinned to a verified revision of its repository.
