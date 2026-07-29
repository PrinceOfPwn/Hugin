# Pipeline Reference

Deep dive into how Hugin turns raw evidence into a compiled 3D universe.

- [Workflow catalog](#workflow-catalog)
- [Ingest chain (end-to-end)](#ingest-chain-end-to-end)
- [Chain-trigger safety fix](#chain-trigger-safety-fix)
- [LLM routing policy](#llm-routing-policy)
- [Directory contract (`data/`)](#directory-contract-data)
- [wrap-inputs behavior](#wrap-inputs-behavior)
- [Bundle preservation](#bundle-preservation)
- [Adding new data](#adding-new-data)
- [Debugging a failed ingest](#debugging-a-failed-ingest)

---

## Workflow catalog

Five workflows, each owning one responsibility.

| Workflow | Trigger | Writes graph | Deploys | Secrets |
|---|---|:---:|:---:|---|
| `ingest-v2.yml` | push on `data/incoming/**` + pipeline scripts; manual; dispatched by expand-cards | yes | via dispatch | `NVIDIA_API_KEY`, optional `GEMINI_API_KEY` |
| `pages.yml` | push on non-jsonl paths; manual; dispatched by ingest-v2 | no | yes | — |
| `quality.yml` | pull_request; manual | no | no | — |
| `release.yml` | manual only (input `version`) | no | no (creates GitHub Release) | — |
| `expand-cards.yml` | cron `15 */4 * * *`; manual | yes (as input) | via dispatch | `NVIDIA_API_KEY` |

### `ingest-v2.yml` — motor del conocimiento

Universal pipeline: cualquier input crudo → nodos del grafo.

Steps in order:
1. **Setup** — Node 24, npm ci with 3× retry (transient ONNX downloads), warm caches `.hf-cache` + `.cache/nvidia-models`
2. **Test ingestion contracts** — `tests/ingest-v2-pipeline.test.mjs` guards the shape
3. **Ingest video notes** — `scripts/ingest-video.mjs` uploads `.mp4`/`.mov` to Gemini 3.6 Flash. Skips gracefully without `GEMINI_API_KEY`.
4. **Wrap missing bundled technique cards** — `scripts/wrap-bundle-techniques.mjs` walks `data/incoming/bundle-*/{techniques,techniques-generated}/*.md`, extracts each YAML frontmatter `id: T-NNN`, and emits `data/incoming/tech-T-NNN.jsonl` **only if that ID is missing from the compiled graph**. Idempotent, non-destructive.
5. **Wrap raw inputs** — `scripts/wrap-inputs.mjs` converts loose `.rs`/`.md`/`.py`/`.c`/etc to JSONL, protecting bundles via `SKIP_DIR_PATTERNS`. See [wrap-inputs behavior](#wrap-inputs-behavior).
6. **Discover inputs** — combines `git diff HEAD~1 HEAD` + untracked working-tree JSONLs, minus quarantined ones
7. **Universal ingestion** — per JSONL:
   - `detect-format.v2.mjs` — schema routing (LLM fallback if unknown)
   - `apply-mapping.v2.mjs` — deterministic normalize → `data/normalized/*.jsonl`
   - `enrich-records.mjs` — Qwen local for simple / GLM cloud for complex → `data/enriched/*.jsonl`
   - `compile-canonical.mjs` — merge into `data/source/public-graph.json` + update `ingest-manifest.json`
   - `build-data.mjs` — Barnes-Hut N-body + Kepler positions
   - `validate-data.mjs` — schema + integrity checks
8. **Purge safely-ingested sources** — deletes only sources with `manifest.sources[key].node_ids.length > 0`. Failed ingests preserved for retry. Protected: `data/incoming/.wrapped/**` and `data/incoming/bundle-*/**`.
9. **Commit generated knowledge** — hugin-bot commits the compiled artifacts and pushes with 3× rebase-retry
10. **Dispatch pages.yml** — explicit `gh workflow run pages.yml --ref main` (see [chain-trigger safety fix](#chain-trigger-safety-fix))

### `pages.yml` — deploy pipeline

Three sequential jobs: `data → build → deploy`. Compiles Barnes-Hut layout + Kepler orbital elements + MiniLM embeddings, builds Astro + Pagefind, validates, deploys via `actions/deploy-pages`.

Triggered by: any push that isn't purely `data/incoming/**/*.jsonl` (that path is owned by ingest), manual dispatch, or explicit dispatch from ingest-v2.

### `quality.yml` — PR gate

Same data + build steps as pages.yml, then adds Playwright E2E + Lighthouse CI. Never commits, never deploys.

### `release.yml` — versioned dataset publisher

Manual only. Input `version` (e.g. `v2.1.0`). Builds dataset, exports canonical bundle, creates immutable GitHub Release with `gh release create`.

### `expand-cards.yml` — autonomous knowledge growth

Generates fresh technique cards from LGTM clusters using GLM-5.2 exclusively.

Inputs (manual dispatch):
- `mode` — `pending` | `gaps` | `cluster` | `refresh` (default `pending`)
- `priority` — `high` | `medium` | `low` | `any` (default `high`)
- `limit` — max cards per run (default `2`; cron runs 6×/day → ≤12 cards/day)
- `cluster_id` — specific cluster (used when `mode=cluster`)
- `dry_run` — bool; calls GLM but doesn't commit (artifacts uploaded)

Cron: `15 */4 * * *` (every 4 h at :15 UTC, offset from top-of-hour runner spikes).

After successful commit → dispatches `ingest-v2.yml` explicitly with `all_inputs=true` so the freshly-generated cards land in the graph in the same cycle.

---

## Ingest chain (end-to-end)

```
┌────────────────────────────────────────────────────────────────────────┐
│  EXTERNAL TRIGGERS                                                     │
│                                                                        │
│  cron 4h @ :15  ─────► expand-cards.yml                                │
│                          │                                             │
│                          │ workflow_dispatch                           │
│                          ▼                                             │
│  push data/     ─────► ingest-v2.yml                                   │
│  push scripts/  ─────►    │                                            │
│                          │ workflow_dispatch                           │
│                          ▼                                             │
│  push src/, layouts/,  pages.yml                                       │
│  package.json  ─────►    │                                             │
│                          ▼                                             │
│                        GitHub Pages deploy                             │
│                                                                        │
│  PR opened      ─────► quality.yml     (validation only)               │
│  workflow_dispatch                                                     │
│    "release"    ─────► release.yml     (GitHub Release only)           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Chain-trigger safety fix

GitHub's documented safety: **pushes made via `GITHUB_TOKEN` do NOT trigger dependent workflows**, with two exceptions: `workflow_dispatch` and `repository_dispatch`.

Before this fix the chain was silently broken:
- `expand-cards.yml` cron committed new T-NNN cards as `hugin-bot` (using `GITHUB_TOKEN`) → `ingest-v2.yml` never fired on that push → cards sat in `data/incoming/expand-*/` forever
- `ingest-v2.yml` committed the compiled graph as `hugin-bot` → `pages.yml` never fired → the site stayed stale until someone pushed a non-data file

Fix: at the end of both producer workflows, an explicit `gh workflow run` step dispatches the downstream workflow. Both dispatches are guarded by a `steps.commit.outputs.pushed == 'true'` output — if the commit step found no diff, no downstream run is fired.

Requirements:
- Producer workflows need `permissions: actions: write` (added to `ingest-v2.yml` and `expand-cards.yml`)
- `github.actor` gate on ingest (`!= 'hugin-bot'`) is compatible with dispatch — the resulting run's actor is `github-actions[bot]`, which passes the gate

---

## LLM routing policy

Defined in `scripts/ingest-model-policy.json`. Enforced by `scripts/enrich-records.mjs` per record.

| Tier | Model | Runs where | Use for |
|---|---|---|---|
| **local** | `onnx-community/Qwen3.5-4B-Instruct-ONNX` (q4) | CI runner (transformers.js) | single-record summary, title/tag generation, explicit entity extraction |
| **complex** | `z-ai/glm-5.2` | NVIDIA Integrate cloud | technical abstraction, cross-document synthesis, conceptual graph generation, technique candidates, MITRE mapping, chain extraction, multi-file relationships, conflicting-claim resolution, ambiguous-concept resolution |

**Batch caps:** 6 records / 20k chars for general; 2 records / 16k chars for complex.

**Thresholds:** `claim: 0.68`, `technique: 0.76`, `entity: 0.64`, `relation: 0.76`, `mitre: 0.86`.

**Fallback ladder** (from the same policy file):
1. On rate-limit / timeout / content-filter → next model in ladder (GLM-5.2 → DeepSeek V4 Pro)
2. On invalid schema → repair once, then next model
3. On all-remote failures → deterministic enrichment (no LLM, degraded quality)
4. `manual_review: false` — never blocks the pipeline

**Shared client:** `scripts/lib/nvidia-models.mjs` — 50 s request timeout, retries `(attempt+1)*10s` on 429/5xx/network, on-disk SHA256 cache at `HUGIN_NVIDIA_CACHE`.

**expand-cards uses raw fetch** (needs markdown, not JSON), but mirrors the same guarantees: 90 s `AbortController` timeout, SHA256 cache, 3× retries with `30s/60s/120s` backoff, no fallback (GLM-5.2 exclusive by user request).

**Video ingest** (`scripts/ingest-video.mjs`) uses Gemini 3.6 Flash via `@google/genai`. Skipped gracefully without `GEMINI_API_KEY`.

---

## Directory contract (`data/`)

```
data/
├── incoming/                       inputs the pipeline consumes
│   ├── <name>.jsonl                # source JSONL (deleted post-ingest)
│   ├── <name>.mapping.json         # schema router output (deleted post-ingest)
│   ├── .wrapped/                   # originals moved here by wrap-inputs (preserved)
│   ├── bundle-<YYYYMMDD>/          # CURATED evidence — never touched by wrap-inputs
│   │   ├── techniques/             # curated T-NNN.md
│   │   ├── techniques-generated/   # auto-generated T-NNN.md
│   │   ├── vault-export/           # LGTM clusters (input for expand-cards)
│   │   ├── source-extracts/        # raw .rs samples (destination for auto-routed uploads)
│   │   ├── analysis/               # analysis docs
│   │   ├── converted/              # converted source docs
│   │   ├── cluster-specs/          # cluster spec templates
│   │   └── ...
│   ├── expand-<UTC>/               # auto-generated cards (deleted post-ingest)
│   └── tech-T-NNN.jsonl            # per-card wrappers from wrap-bundle-techniques (deleted post-ingest)
├── normalized/                     # normalized JSONL (deleted post-ingest)
├── enriched/                       # LLM-enriched JSONL + reports (deleted post-ingest)
└── source/
    ├── public-graph.json           # THE canonical graph (Barnes-Hut positions, Kepler orbits, all nodes+edges)
    ├── ingest-manifest.json        # source → node_ids mapping (retained forever)
    └── ...
```

The compiled graph in `data/source/public-graph.json` is the single source of truth for the deployed site. Everything under `data/normalized/`, `data/enriched/`, and non-bundle `data/incoming/*.jsonl` is intermediate — regenerable and auto-purged post-ingest.

---

## wrap-inputs behavior

`scripts/wrap-inputs.mjs` transforms loose raw files at `data/incoming/*` into JSONL for the ingest pipeline.

### Protected directories (`SKIP_DIR_PATTERNS`)

Never wrapped, never moved:
- `.wrapped/` — the wrap-inputs destination itself
- `quarantine/` — malformed inputs kept for triage
- `bundle-<digits>/` — curated evidence bundles (matches `/^bundle-\d+$/`)
- `expand-*/` — auto-generated cards from `expand-cards.mjs`
- `tech-*/` and `src-*/` — per-card wrappers from `wrap-bundle-techniques.mjs` and auto-routed source snippets

### Loose file handling

For a loose file `data/incoming/foo.<ext>`:

| Ext category | Kind | Wrapped to | Original moved to |
|---|---|---|---|
| `.rs .py .go .c .cc .cpp .h .ts .tsx .js .mjs .cjs .java .kt .swift .rb .php .cs .scala .sh …` | `source_code` | `data/incoming/foo.jsonl` | `bundle-<latest>/source-extracts/foo.<ext>` (if a bundle exists) else `.wrapped/foo.<ext>` |
| `.md .markdown .txt .rst .adoc` | `documentation` | `data/incoming/foo.jsonl` | `.wrapped/foo.<ext>` |
| `.jsonl .mapping.json .report.json` | skipped (already ingest format) | — | — |
| Anything else | skipped | — | — |

**Auto-routing to `source-extracts/`** was introduced in v3: loose raw code lands as authoritative evidence inside the latest curated bundle instead of being buried in `.wrapped/`. After the post-ingest purge deletes the JSONL wrapper, the source file remains as citable evidence.

### Directory handling

Top-level directories that are NOT in `SKIP_DIR_PATTERNS` are treated as "projects" — walked recursively, all supported files bundled into one JSONL keyed by `project_manifest.role` = `readme` / `walkthrough` / `documentation` / `source_code`. The whole directory is then moved to `.wrapped/`.

---

## Bundle preservation

The curated `bundle-<YYYYMMDD>/` directories under `data/incoming/` are the **library of source evidence**. They hold:
- Hand-curated technique cards (T-NNN.md)
- LGTM clustering inputs and outputs
- Analysis-atlas / atlas-synthesized / analysis-curated documents
- Raw code source-extracts
- Cluster specifications

The pipeline treats them as **authoritative and immutable**:
- `wrap-inputs.mjs` never walks into them (SKIP_DIR_PATTERNS)
- `wrap-bundle-techniques.mjs` reads them but never writes to them
- The post-ingest purge preserves them (explicit `! -path '*/bundle-*'` guard)
- `expand-cards.mjs` reads `bundle-*/vault-export/lgtm-clusters-*.json` as input, never modifies

If a card's YAML frontmatter `id: T-NNN` is not yet in the compiled graph, `wrap-bundle-techniques.mjs` emits a per-card JSONL wrapper at `data/incoming/tech-T-NNN.jsonl`. That wrapper flows through the standard pipeline and gets purged post-ingest. The original card in the bundle stays untouched.

---

## Adding new data

### Drop a loose file

```bash
# From your clone
cp my-technique-writeup.md ~/Hugin/data/incoming/
cd ~/Hugin && git add data/incoming/my-technique-writeup.md \
             && git commit -m "data: add my technique writeup" \
             && git push origin main
```

Push triggers `ingest-v2.yml`, which chains automatically to `pages.yml`. Site updated in ~10-15 min.

### Drop a raw code sample

```bash
cp ~/exploits/my_shellcode.rs ~/Hugin/data/incoming/
# ... commit + push
```

`wrap-inputs.mjs` will move `my_shellcode.rs` into the latest `bundle-*/source-extracts/` and emit a JSONL for the pipeline. The source file survives the purge as citable evidence.

### Drop a video

```bash
cp talk.mp4 ~/Hugin/data/incoming/
# ... commit + push
```

`ingest-video.mjs` (Gemini 3.6 Flash) will transcribe + structure notes. Requires `GEMINI_API_KEY` secret configured in the repo settings.

### Backfill missing technique cards

```
Actions → Ingest HUGIN knowledge (v3) → Run workflow → all_inputs: true
```

`wrap-bundle-techniques.mjs` scans every `bundle-*/{techniques,techniques-generated}/*.md`, filters to those whose `id: T-NNN` is missing from the current graph, and emits per-card wrappers. First run of this step after bundle-20260728 lands surfaces ~60-70 previously-orphaned cards.

### Auto-generate new cards from LGTM clusters

Runs automatically every 4 h. To trigger manually:

```
Actions → Expand LGTM clusters into technique cards (GLM-5.2) → Run workflow
  mode: pending    priority: high    limit: 5    dry_run: false
```

Requires `NVIDIA_API_KEY` secret.

---

## Debugging a failed ingest

1. **Check the run summary** — the workflow's `Run summary` step appends per-source reports from `data/enriched/*.report.json` to the GitHub Actions summary.
2. **Check the diagnostics artifact** — `Upload diagnostics` retains 14 days of `.mapping.json` + `.report.json`.
3. **Check `data/incoming/`** — sources that failed are NOT purged (guard on `node_ids.length > 0`). They remain for retry.
4. **Check `data/source/ingest-manifest.json`** — `.sources[key].node_ids` shows what compiled; `.node_history[id]` shows first-seen / last-updated timestamps.
5. **Common failures:**
   - **Missing `NVIDIA_API_KEY`** → complex-tier records silently degrade to deterministic enrichment (visible in `report.remote_errors`)
   - **GLM 5xx / 429** → 3 retries with backoff, then DeepSeek V4 Pro fallback, then deterministic
   - **Non-JSON response** → `NvidiaModelsClient` runs one repair pass, then falls through
   - **Bundle collision** — if `wrap-bundle-techniques.mjs` sees a card whose T-NNN is already in the graph, it skips (idempotent). If you WANT to reingest, delete the node from `public-graph.json` and re-run.

---

## Env vars reference

Set as GitHub Actions secrets, or export locally for reproducing.

| Var | Required for | Notes |
|---|---|---|
| `NVIDIA_API_KEY` | complex-tier enrichment, expand-cards | Without it, complex records degrade silently |
| `NVIDIA_API_BASE_URL` | optional | Defaults `https://integrate.api.nvidia.com/v1` |
| `HUGIN_NVIDIA_MODEL` | override GLM model id | Fallback ladder still runs (DeepSeek last) |
| `HUGIN_NVIDIA_CACHE` | cache path | Defaults `.cache/nvidia-models` |
| `HUGIN_SIMPLE_MODEL` | local ONNX model id | Defaults `onnx-community/Qwen3.5-4B-Instruct-ONNX` |
| `HUGIN_SIMPLE_DTYPE` | ONNX quant | Defaults `q4` |
| `HUGIN_MODEL_CACHE` | HF cache path | Defaults `.hf-cache` |
| `HUGIN_SIMILARITY_ENGINE` | build-data engine | `transformers` in CI |
| `GEMINI_API_KEY` | video ingest only | Optional. Missing = video step skipped |
| `HUGIN_BUNDLE_SUBDIRS` | wrap-bundle-techniques scope | Comma-list. Default `techniques,techniques-generated` |
