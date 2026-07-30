# Mercury audit state

This branch contains machine-generated, resumable Mercury audit state. It is intentionally separate from `main` so generated audit history does not trigger the production graph or Pages pipelines.

- Do not store API keys or credentials here.
- `state/audit.jsonl` contains the latest successful result per entity.
- Failed API calls are not persisted as processed.
- Production graph changes must be proposed through a separate reviewed pull request.
