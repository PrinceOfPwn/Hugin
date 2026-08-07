# External PDF and Web Knowledge Distillation

HUGIN can ingest public PDF collections, individual PDFs, ordinary web pages, and GitHub repositories that contain PDFs without publishing the source documents themselves.

The external pipeline is intentionally different from the universal JSONL pipeline. Source text is staging evidence only. GLM-5.2 turns overlapping source windows into operator-grade knowledge units, performs a document-level merge, and then runs a collection-level synthesis that deduplicates techniques and preserves meaningful variants.

## Why this is not chunk ingestion

Raw chunks are never treated as the final graph product. They exist transiently under `.cache/hugin-external/` and are discarded after the run. The published graph receives synthesized `playbook` records containing:

- operational objective and applicability;
- prerequisites and attack surface;
- ordered operator flow;
- decision points and validation signals;
- pivots, variants, and failure modes;
- tool roles and concrete testing patterns supported by the source;
- concepts, techniques, entities, MITRE candidates, and evidence-grounded relations;
- clickable source URLs, exact PDF page ranges, source SHA-256 hashes, and short evidence fragments.

The distiller is deliberately offensive/operator-oriented for authorized bug-bounty research. It is instructed not to turn the corpus into a defensive checklist, not to emit generic chapter summaries, and not to invent payloads, bypasses, targets, or prerequisites that are absent from the sources.

## Grounding and publication policy

Every published knowledge unit must carry at least one `source_ref`. Evidence snippets are exact matches against staged chunks and are capped at 220 characters. A source reference is accepted only when its URL and page range match the metadata of the chunk IDs it cites; the canonical projection derives the final title, URL, page range, source ID, and source SHA-256 from those chunks rather than trusting model output.

Long source passages and raw PDF text are not committed or uploaded as Actions artifacts. Raw external documents are never versioned by HUGIN.

Publication is **fail closed**:

- a collection run must stage every resolved document;
- the production workflow refuses a `max_documents` or `max_pages` value that truncates the collection;
- any fetch/extraction failure prevents publication rather than replacing a complete graph projection with partial data;
- every source document must yield at least one high-value GLM candidate and one document-level unit;
- the final collection synthesis must contain at least one unit;
- malformed GLM structures are rejected into the repair path before rendering/compilation;
- GLM is strict: the external pipeline does not fall back to another model.

Canonical ownership uses the stable collection ID (`external:<collection-id>`), not a transient output path or source URL. Custom URL workflows derive their collection ID from a SHA-256 prefix of the URL so independent custom sources cannot overwrite one another.

## BugBountyBooks preset

The bundled preset targets:

`https://github.com/akr3ch/BugBountyBooks/tree/main`

Run the **Distill external knowledge with GLM** workflow with `preset=bug-bounty-books`. The ingestor enumerates the complete PDF tree through the GitHub API, fetches Git blobs transiently, extracts text with `pdftotext`, and feeds bounded overlapping page windows into GLM-5.2 through the existing NVIDIA client.

The preset intentionally has headroom (`max_documents=25`, `max_pages_per_document=1500`) above the current corpus. PR preflight queries the live GitHub tree and fails if the preset can no longer cover all PDFs.

## Custom source

Choose `preset=custom` and provide `source_url` as one of:

- a public PDF URL;
- a normal HTTP/HTTPS web page;
- a GitHub repository URL containing PDFs;
- a GitHub tree URL, including branches containing `/`;
- a GitHub PDF blob URL.

Only public HTTP(S) provenance is publishable. Local `file://` sources are intentionally rejected because their links would be meaningless in the public graph.

The workflow requires `NVIDIA_API_KEY`. GitHub access uses the workflow `GITHUB_TOKEN`; custom public web/PDF sources are streamed with a hard byte cap before buffering.

## CI/CD behavior

`External knowledge ingestion CI` runs deterministic contracts. The production workflow itself also has a PR-only `preflight` job, so GitHub validates the exact workflow definition before merge without spending NVIDIA tokens.

Full GLM distillation remains an explicit `workflow_dispatch`. On `main`, a successful complete run commits only the graph projection and manifest, then dispatches `pages.yml`. External distillation shares the same concurrency group as the universal ingest workflow so both canonical writers cannot race.

## Local commands

A GitHub token is recommended for repository enumeration to avoid unauthenticated API rate limits:

```bash
GITHUB_TOKEN=... node scripts/ingest-external-knowledge.mjs \
  data/external-sources/bug-bounty-books.json \
  --out=.cache/hugin-external/bug-bounty-books.chunks.jsonl \
  --require-complete

NVIDIA_API_KEY=... node scripts/distill-external-knowledge.mjs \
  .cache/hugin-external/bug-bounty-books.chunks.jsonl \
  --collection=data/external-sources/bug-bounty-books.json \
  --out=.cache/hugin-external/bug-bounty-books.distilled.jsonl

node scripts/compile-canonical.mjs .cache/hugin-external/bug-bounty-books.distilled.jsonl
```

For deterministic validation without network or model calls:

```bash
node tests/external-knowledge.test.mjs
node tests/nvidia-model-strict.test.mjs
```
