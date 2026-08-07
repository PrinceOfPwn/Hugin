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
- clickable source URLs, PDF page ranges, hashes, and short evidence fragments.

The distiller is deliberately offensive/operator-oriented for authorized bug-bounty research. It is instructed not to turn the corpus into a defensive checklist, not to emit generic chapter summaries, and not to invent payloads, bypasses, targets, or prerequisites that are absent from the sources.

## Grounding and publication policy

Every published knowledge unit must carry at least one `source_ref`. Evidence snippets are exact matches against staged chunks and are capped at 220 characters. Long source passages and raw PDF text are not committed or uploaded as Actions artifacts.

This makes the graph auditable while keeping the published artifact focused on derived knowledge rather than reproducing source books.

## BugBountyBooks preset

The bundled preset targets:

`https://github.com/akr3ch/BugBountyBooks/tree/main`

Run the **Distill external knowledge with GLM** workflow with `preset=bug-bounty-books`. The ingestor enumerates PDFs through the GitHub API, downloads them transiently, extracts text with `pdftotext`, and feeds overlapping multi-page windows into GLM-5.2 through the existing NVIDIA client.

## Custom source

Choose `preset=custom` and provide `source_url` as one of:

- a public PDF URL;
- a normal HTTP/HTTPS web page;
- a GitHub repository URL containing PDFs;
- a GitHub PDF blob URL.

The workflow requires `NVIDIA_API_KEY`. GitHub access uses the workflow `GITHUB_TOKEN`; custom public web/PDF sources are fetched directly.

## Local commands

```bash
node scripts/ingest-external-knowledge.mjs data/external-sources/bug-bounty-books.json \
  --out=.cache/hugin-external/bug-bounty-books.chunks.jsonl

NVIDIA_API_KEY=... node scripts/distill-external-knowledge.mjs \
  .cache/hugin-external/bug-bounty-books.chunks.jsonl \
  --collection=data/external-sources/bug-bounty-books.json \
  --out=.cache/hugin-external/bug-bounty-books.distilled.jsonl

node scripts/compile-canonical.mjs .cache/hugin-external/bug-bounty-books.distilled.jsonl
```

For deterministic validation without network or model calls:

```bash
node tests/external-knowledge.test.mjs
```
