# HUGIN Knowledge Universe

HUGIN is a fully static technical research universe built for GitHub Pages. It publishes 5,608 owner-authorized entities as an accessible catalog, permanent HTML pages, and eight WebGL galaxies—without a backend, browser token, paid service, or runtime AI dependency.

## Explore

- Dashboard: <https://princeofpwn.github.io/Hugin/>
- Catalog: <https://princeofpwn.github.io/Hugin/explore/>
- Knowledge universe: <https://princeofpwn.github.io/Hugin/graph/>
- Dataset contract: <https://princeofpwn.github.io/Hugin/dataset/>
- Quality report: <https://princeofpwn.github.io/Hugin/quality/>

## Architecture

- Astro generates real static HTML under the `/Hugin/` base path.
- React is limited to search, catalog filters, and the Sigma.js WebGL graph.
- GitHub Actions performs normalization, q8 MiniLM embeddings, neighbor generation, layout, Pagefind indexing, Playwright, Axe, Lighthouse, and bundle checks.
- GitHub Pages only serves the verified artifact.
- The owner import is ignored. The tracked `data/source/public-graph.json` is a sanitized public projection containing every entity.

## Relation semantics

- `curated`: original valid research relation; rendered solid.
- `membership`: structural galaxy placement; not a technical claim.
- `similarity`: build-generated exploratory relation with score, rank, corpus hash, model, and pinned revision; rendered as a separate generated layer.

The two invalid original self-relations are quarantined and reported. No node is removed because it lacks an original relation.

## Reproduce

The supported runtime is Node.js 24 LTS.

```bash
npm ci
npm run data:import   # only with the owner-supplied local import present
npm run build
npm run check
npm run test:e2e
```

The normal project workflow performs the expensive commands in GitHub Actions. See `data/source/README.md` for the publication boundary.

## Publication boundary

The Raven identity and public corpus are supplied and authorized by the repository owner. Absolute local paths, local usernames, backup files, error outputs, prompts, and internal build artifacts are excluded from publication. Raven checksums and authorization are recorded in `hugin/assets/asset-manifest.json`.
