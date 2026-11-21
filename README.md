# anchorwatch

anchorwatch is a deterministic upkeep engine for knowledge bundles written in the Open Knowledge Format, OKF v0.3. A bundle that nobody maintains quietly goes stale. Facts pass their review dates, verification lapses, one document replaces another without the replacement being recorded, and the index drifts away from the files it lists. anchorwatch runs the scheduled pass that catches all of that and writes down what it did.

## What it does

An upkeep pass walks a bundle and performs the maintenance the OKF spec leaves to the bundle owner. It recomputes which concepts have passed their `stale_after` review date. It checks the currency of each concept's verification against the trust auditor and queues anything lapsed for re-verification. It applies supersessions the bundle already declares and audits them for defects such as cycles, missing targets, and status mismatches. It regenerates the bundle indexes and the bundle log, preserving hand-written content the spec protects. Where a bundle carries a claim registry, it checks the registry for drift against the concepts it indexes.

The pass is deterministic. Run it twice over the same bundle with the same pinned date and the result is identical, so it can run unattended from cron or CI and its output can be diffed and reviewed like any other change.

The engine has hard limits it never crosses on its own. It never edits the meaning of a document, never stamps a verification event, never invents a review date, never chooses what supersedes what, and never deletes a file. Anything needing judgement becomes an item in the re-verification queue, with a reason code, for a human or an agent to decide.

## The migrator

anchorwatch also converts an existing knowledge tree into an OKF v0.3 bundle. Conversion is driven by a source profile, and every construct that cannot be carried across is written into a loss ledger that ships with the bundle. Each ledger entry names the construct, how often it occurred, what happened to it, and whether it was load-bearing. A migration that reports no loss has not been measured honestly, and the ledger format treats a zero-loss report as a failed run.

## How it is used

```text
anchorwatch migrate --profile claude-memory --source ~/memory --out ./bundle
anchorwatch upkeep --bundle ./bundle --as-of 2026-11-20
anchorwatch queue --bundle ./bundle
```

The migrator writes the bundle and its loss ledger. The upkeep command runs one pass and writes the pass results into the bundle log. The queue command prints the open re-verification items. Scheduling is left to the owner, through cron, a CI schedule, or any other runner, because the engine itself is a single run that ends.

## Current state

This repository is at the scaffold stage. The workspace, the two crates, and the command entry point are in place, and the design record behind the build has passed its gate review. The migrator is the first build milestone, followed by the upkeep pass. Nothing here is ready for use yet.
