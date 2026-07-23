# Public data projection

`public-graph.json` is the versioned, sanitized projection used by GitHub Actions. It contains all 5,608 authorized entities and 3,795 valid original relations.

The original owner import remains at `hugin/vault-export/graph.json` and is intentionally ignored by Git. To refresh the projection:

```bash
npm run data:import
```

The importer removes absolute local paths and usernames, adds stable provenance keys and hashes, and quarantines invalid self-relations. It does not drop entities. Generated assets, embeddings, layouts, Pagefind indices, and release exports are built in CI.
