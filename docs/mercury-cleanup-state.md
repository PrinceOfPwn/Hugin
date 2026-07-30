# Mercury stratified cleanup workflow

The Mercury audit remains offline and proposal-only. It never exposes Mercury to site users and never mutates the production graph automatically.

## Two-phase process

1. **Stratified sample**: select a deterministic percentage of nodes from every current node type, prioritizing representation of rare types. The default is 25% of currently unprocessed nodes with at least three nodes per type when capacity allows.
2. **Full resume**: after reviewing the sample quality, process every remaining or changed node without paying to audit unchanged nodes again.

The existing repository secret remains `INCEPTION_API_KEY`. Its value is only available to the `Audit graph` step.

## Persistent state

The dedicated `mercury-audit-state` branch stores machine-generated state separately from `main`:

- `state/audit.jsonl`: latest successful audit for each entity;
- `state/processed-index.json`: source hashes and current/stale status;
- `state/latest-summary.json`: latest run and cumulative coverage;
- `state/latest-sample-plan.json`: stratum populations and selected IDs;
- `state/latest-cleanup-plan.json`: proposed safe fixes and semantic-claim review;
- `state/runs/<run-id>.json`: compact run history.

API failures are included in the downloadable run artifact but are not marked as processed, so a later resume retries them.

## Cleanup safety

The workflow produces `cleanup-plan.json`, `review-queue.json`, and `candidates.json`. It does not apply them. No-op reclassifications such as `technique -> technique` are removed, embedded Markdown summaries prevent false `missing_summary` findings, and overly absolute EDR/ETW evasion claims are flagged for review.

## Final execution

Run the workflow with `mode=full`. It reads the state branch, skips unchanged source hashes, retries stale or failed entities, and updates cumulative coverage. A separate reviewed PR should apply accepted cleanup candidates to the production graph.
