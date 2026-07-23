# Public data projection

`public-graph.json` is the versioned, anonymous projection consumed by GitHub Actions. The audited import contains 5,608 raw records, but the public product separates them by value:

- Core knowledge becomes catalog and graph entities.
- Anonymous source and documentation records form an optional graph layer.
- Useful extraction fragments become contextual evidence only.
- Administrative slides and invalid relations are quarantined.

The original owner import remains at `hugin/vault-export/graph.json` and is intentionally ignored by Git. To refresh the projection:

```bash
npm run data:import
```

The importer removes provider and course names, private paths, local usernames, source filenames, and promotional source links. It remaps raw evidence IDs, assigns neutral evidence identifiers, rejects low-value fragments, and quarantines invalid relations.

Generated assets, embeddings, layouts, Pagefind indices, browser tests, and release exports are produced in GitHub Actions.
