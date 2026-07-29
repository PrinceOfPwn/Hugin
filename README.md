# HUGIN Knowledge Universe

**HUGIN** is a fully static technical knowledge graph engineered for GitHub Pages. It compiles curated intelligence, anonymized evidence, and immutable HTML records into a cinematic WebGL universe — no backend, no runtime AI dependencies, no browser tokens. Blazing fast, purely static, and reproducible from source.

---

## The Hugin & Munin Ecosystem

In Norse mythology, Odin relied on his two ravens, **Hugin** (Thought) and **Munin** (Memory), who flew across the world to bring back hidden knowledge. Our architecture mirrors the legend:

- **Munin (The Memory):** upstream harvester — autonomously explores, collects, and structures raw artifacts from diverse unstructured sources.
- **Hugin (The Thought — this repository):** ingests Munin's output, sanitizes it, enriches it through embeddings and LLMs, and projects it into an interactive 3D universe.

Together they form an end-to-end pipeline for gathering, securing, and visualizing technical intelligence.

---

## Explore the Universe

- **Dashboard:** [princeofpwn.github.io/Hugin/](https://princeofpwn.github.io/Hugin/)
- **Explore:** [Catalog](https://princeofpwn.github.io/Hugin/explore/) — 3-column master/detail/preview
- **Graph:** [Cinematic 3D](https://princeofpwn.github.io/Hugin/graph/) — Kepler orbits, spacetime fabric, 
- **Latest:** [50 most recent](https://princeofpwn.github.io/Hugin/latest/)
- **MITRE:** [ATT&CK matrix](https://princeofpwn.github.io/Hugin/mitre/) — coverage row-per-tactic
- **Dataset:** [Contract](https://princeofpwn.github.io/Hugin/dataset/)
- **Quality:** [Telemetry](https://princeofpwn.github.io/Hugin/quality/)

---

## Scale

Live corpus (auto-updated by the ingest workflow):

- **5,518** nodes across 10 kind categories
- **3,919** typed relations
- **137** windows-internals structures · **213** attack chains · **344** LGTM cluster notes · **224** attack patterns · **149** documentation atoms · **524** detection surfaces · **3,256** evidence excerpts
- **8** curated semantic neighbors per entity
- Absolute privacy: provider names, local paths, and private usernames are stripped from every public artifact

---

## Architecture

**Runtime (browser):**
- **Astro 5** — static HTML compilation under `/Hugin/`
- **React 19 islands** — hydrated only where interactivity requires it (`⌘K` palette, filters, minimap, spacetime playground)
- **@react-three/fiber + drei** — WebGL universe with Kepler orbital mechanics (satellites orbit attractors in ~30-45 s), sparse SDF labels, beam-of-light selection, interactive gravity grid
- **Pagefind** — static full-text search index

**Build (GitHub Actions):**
- **Qwen 3.5-4B-Instruct-ONNX q4** — local inference for simple extractions (titles, tags, single-record summaries)
- **GLM-5.2** via NVIDIA Integrate — high-tier reasoning for cross-document synthesis, technique candidates, ATT&CK mapping, conflict resolution. DeepSeek V4 Pro as automatic fallback.
- **MiniLM q8 (all-MiniLM-L6-v2 ONNX)** — pinned embeddings for semantic neighbors + similarity
- **Gemini 3.6 Flash** — optional multimodal video ingest (`.mp4`/`.mov`/`.mkv`/`.webm` dropped in `data/incoming/`)

**Deploy:** GitHub Pages serves the deterministic `dist/` artifact.

Full architecture and pipeline reference: **[docs/PIPELINE.md](docs/PIPELINE.md)**.

---

## Automated Knowledge Ingest

Hugin ingests continuously. Five workflows own distinct responsibilities and chain automatically:

```
   ┌─────────────────────────┐   cron 4h    ┌─────────────────────────┐
   │  Push to data/incoming/ │     │        │  expand-cards.yml       │
   │  (raw code, docs, video)│     ▼        │  (GLM-5.2 → new cards)  │
   └───────────┬─────────────┘              └───────────┬─────────────┘
               │                                        │
               └──────────────┬─────────────────────────┘
                              ▼
                    ┌───────────────────────┐
                    │  ingest-v2.yml        │
                    │  wrap → detect → map  │
                    │  → enrich → compile   │
                    │  → purge intermediates│
                    └───────────┬───────────┘
                                ▼
                    ┌───────────────────────┐
                    │  pages.yml            │
                    │  build → validate     │
                    │  → deploy to Pages    │
                    └───────────────────────┘

  Side workflows: quality.yml (PR gate) · release.yml (versioned snapshots)
```

The `expand-cards.yml` scheduled cron generates fresh technique cards from LGTM clusters via GLM-5.2 exclusively, commits them into `data/incoming/expand-<UTC>/`, and dispatches the ingest chain automatically.

See [docs/PIPELINE.md](docs/PIPELINE.md) for the ingest architecture, LLM routing policy, bundle-preservation semantics, and how to add new data.

---

## Relationship Semantics

- **`curated`** — owner-authorized, verified knowledge relation
- **`membership`** — structural galaxy placement (taxonomic grouping)
- **`similarity`** — build-generated exploratory relation backed by scoring, ranks, corpus hashing, and pinned models

---

## Training Data Factory (QA Pipeline)

Hugin doubles as an autonomous factory for supervised fine-tuning datasets. The QA pipeline extracts, sanitizes, and normalizes intelligence into strictly formatted question-answer pairs:

- **`npm run qa:normalize`** — aggregate heterogeneous records into a canonical schema; redact private URLs, absolute paths, and secrets
- **`npm run qa:enrich`** / **`qa:import`** — LLM-supervised augmentation + integration
- **`npm run qa:ingest`** — orchestrator that weaves raw fine-tuning traces into the global layer

---

## Reproduce Locally

Runtime: **Node.js 24 LTS**.

```bash
npm ci
npm run data:build      # build canonical graph + embeddings
npm run data:mitre      # generate MITRE matrix index
npm run data:validate   # validate the compiled dataset
npm run site:build      # Astro + Pagefind
npm run check           # type + lint
npm run test:budgets    # perf budgets
```

All expensive model inference (Qwen, GLM, Gemini) is offloaded to GitHub Actions — local development only exercises the deterministic build path.
