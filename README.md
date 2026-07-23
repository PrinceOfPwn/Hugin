# HUGIN Knowledge Universe

HUGIN is a fully static technical knowledge graph built for GitHub Pages. It publishes a curated knowledge layer, anonymous supporting evidence, permanent HTML records, and eight WebGL galaxies without a backend, browser token, paid service, or runtime AI dependency.

## Explore

- Dashboard: <https://princeofpwn.github.io/Hugin/>
- Catalog: <https://princeofpwn.github.io/Hugin/explore/>
- Knowledge graph: <https://princeofpwn.github.io/Hugin/graph/>
- Dataset contract: <https://princeofpwn.github.io/Hugin/dataset/>
- Quality report: <https://princeofpwn.github.io/Hugin/quality/>

## Public projection

- 1,845 core knowledge entities.
- 317 optional source and documentation records.
- 3,256 anonymous evidence records, loaded only in context.
- 190 administrative or low-value fragments quarantined.
- 2,806 curated graph relations.
- Eight generated semantic neighbors for every core entity.

Raw extraction fragments are not standalone pages or graph nodes. Provider names, course identifiers, local paths, filenames, and private usernames are excluded from every public artifact.

## Architecture

- Astro generates real static HTML under the `/Hugin/` base path.
- React is limited to search, catalog filters, and the Sigma.js WebGL graph.
- GitHub Actions performs validation, pinned q8 MiniLM embeddings, neighbor generation, layout, Pagefind indexing, Playwright, Axe, Lighthouse, and bundle checks.
- GitHub Pages only serves the verified artifact.
- The owner import remains ignored. The tracked public projection is sanitized and anonymous.

## Relationship semantics

- `curated`: owner-authorized knowledge relation.
- `membership`: structural galaxy placement, not a technical claim.
- `similarity`: build-generated exploratory relation with score, rank, corpus hash, model, and pinned revision.

## Reproduce

The supported runtime is Node.js 24 LTS.

```bash
npm ci
npm run data:import   # only when the owner-supplied local import is present
npm run build
npm run check
npm run test:e2e
```

The expensive model and browser work runs in GitHub Actions.
