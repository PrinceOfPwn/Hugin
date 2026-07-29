// tests/pipeline-e2e.test.mjs
// End-to-end pipeline smoke test — no cloud LLM.
// Runs the deterministic path through: wrap-bundle-techniques → wrap-inputs
// → detect-format.v2 → apply-mapping.v2 in an isolated temp directory.
// Verifies the three critical routing shapes that regressed today:
//   1. Bundle technique-card wrappers (tech-*.jsonl → kind=documentation)
//   2. Loose top-level docs (kind=documentation)
//   3. Project source-code bundles (kind=project_source_code + nested facets)
// Also asserts wrap-inputs preserves curated bundles (never moves bundle-*).
// The final fixture verifies that multi-file enrichment keeps one shared model
// lifecycle while preserving one output/report pair per source.
//
// Run: node tests/pipeline-e2e.test.mjs
// Exit non-zero on any assertion failure — safe to wire into CI.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const SCRIPTS = path.join(REPO, "scripts");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-e2e-"));
console.log(`[e2e] tmp: ${TMP}`);

function fixtureLayout() {
  fs.mkdirSync(path.join(TMP, "data/incoming/bundle-19700101/techniques"), { recursive: true });
  fs.mkdirSync(path.join(TMP, "data/incoming/mini-project"), { recursive: true });
  fs.mkdirSync(path.join(TMP, "data/source"), { recursive: true });
  fs.mkdirSync(path.join(TMP, "data/normalized"), { recursive: true });
  fs.mkdirSync(path.join(TMP, "data/enriched"), { recursive: true });

  // Fixture 1: technique card inside a curated bundle
  fs.writeFileSync(
    path.join(TMP, "data/incoming/bundle-19700101/techniques/T-999-fixture-card.md"),
    `---
id: T-999
name: 'E2E Fixture Card'
category: syscalls
tier: A
mitre: T1055
tags: [test, fixture]
---

# E2E Fixture Card

Body used only by the pipeline E2E test.

## Summary
Deterministic content — no LLM calls needed.
`,
  );
  fs.writeFileSync(
    path.join(TMP, "data/incoming/bundle-19700101/techniques/T-998-degraded-card.md"),
    `---
id: T-998
name: 'E2E Degraded Card'
category: syscalls
tier: A
---

# E2E Degraded Card

This existing card must be emitted again when its manifest-owned graph node is degraded.
`,
  );

  // Fixture 2: loose top-level markdown doc
  fs.writeFileSync(
    path.join(TMP, "data/incoming/loose-note.md"),
    `# Loose Test Note

Body of a loose top-level document.
`,
  );

  // Fixture 3: mini-project directory (walks recursively via wrap-inputs)
  fs.writeFileSync(
    path.join(TMP, "data/incoming/mini-project/README.md"),
    `# mini-project

Sample readme.
`,
  );
  fs.writeFileSync(
    path.join(TMP, "data/incoming/mini-project/helper.rs"),
    `// helper.rs
pub fn hello() { println!("hi"); }
`,
  );

  // T-999 is missing; T-998 exists but must be repaired because its owned
  // graph node carries a degraded enrichment status.
  fs.writeFileSync(
    path.join(TMP, "data/source/public-graph.json"),
    JSON.stringify({
      nodes: [{
        id: "documentation:fixture-degraded",
        label: "E2E Degraded Card",
        enrichment_status: "degraded",
      }],
      edges: [],
    }),
  );
  fs.writeFileSync(
    path.join(TMP, "data/source/ingest-manifest.json"),
    JSON.stringify({
      version: 2,
      sources: {
        "data/incoming/tech-T-998.jsonl": {
          node_ids: ["documentation:fixture-degraded"],
          edge_ids: [],
        },
      },
    }),
  );
}

function run(scriptRel, ...args) {
  return execFileSync(
    "node",
    [path.join(SCRIPTS, scriptRel), ...args],
    {
      cwd: TMP,
      encoding: "utf8",
      env: {
        ...process.env,
        NVIDIA_API_KEY: "",
        GEMINI_API_KEY: "",
      },
    },
  );
}

let passed = 0;
function step(name, fn) {
  process.stdout.write(`[e2e] ${name} ... `);
  try {
    fn();
    console.log("OK");
    passed++;
  } catch (e) {
    console.log("FAIL");
    console.error(e?.stack || e?.message || e);
    process.exit(1);
  }
}

// ── Setup ─────────────────────────────────────────────────────────────────
fixtureLayout();

// ── Step 1: wrap-bundle-techniques emits tech-T-999.jsonl ────────────────
step("wrap-bundle-techniques emits missing card as tech-T-999.jsonl", () => {
  const out = run("wrap-bundle-techniques.mjs");
  assert.match(out, /emit T-999/, "expected emit log for T-999");
  assert.match(out, /repair T-998/, "expected degraded T-998 to be repaired");
  assert.ok(fs.existsSync(path.join(TMP, "data/incoming/tech-T-998.jsonl")), "tech-T-998 repair JSONL not created");
  const wrap = path.join(TMP, "data/incoming/tech-T-999.jsonl");
  assert.ok(fs.existsSync(wrap), "tech-T-999.jsonl not created");
  const rec = JSON.parse(fs.readFileSync(wrap, "utf8").trim());
  assert.equal(rec.id, "T-999");
  assert.equal(rec.title, "E2E Fixture Card");
  assert.ok(rec.body.includes("Deterministic content"), "body content missing");
  assert.equal(rec.source_bundle, "bundle-19700101");
  assert.deepEqual(rec.tags.slice(0, 2), ["technique-card", "origin:bundle-19700101"]);
  assert.ok(!("project_manifest" in rec), "must not emit project_manifest (routes through plain documentationMapping)");
});

// ── Step 2: wrap-inputs preserves the bundle + wraps loose files + project
step("wrap-inputs preserves bundle-*, wraps loose doc + mini-project", () => {
  run("wrap-inputs.mjs");
  // Bundle intact — SKIP_DIR_PATTERNS should not touch it
  const card = path.join(TMP, "data/incoming/bundle-19700101/techniques/T-999-fixture-card.md");
  assert.ok(fs.existsSync(card), "bundle was moved/destroyed — SKIP_DIR_PATTERNS regression");
  // Loose doc wrapped + moved to .wrapped/
  assert.ok(fs.existsSync(path.join(TMP, "data/incoming/loose-note.jsonl")), "loose-note.jsonl missing");
  assert.ok(!fs.existsSync(path.join(TMP, "data/incoming/loose-note.md")), "loose-note.md still in incoming root");
  assert.ok(fs.existsSync(path.join(TMP, "data/incoming/.wrapped/loose-note.md")), "loose-note.md not moved to .wrapped/");
  // Mini-project wrapped as project bundle → mini-project.jsonl at top level
  assert.ok(fs.existsSync(path.join(TMP, "data/incoming/mini-project.jsonl")), "mini-project.jsonl missing");
  const projLines = fs.readFileSync(path.join(TMP, "data/incoming/mini-project.jsonl"), "utf8")
    .split("\n").filter(Boolean);
  assert.equal(projLines.length, 2, "expected 2 project records (README + helper.rs)");
  const parsed = projLines.map((l) => JSON.parse(l));
  const hasReadme = parsed.some((r) => r.project_manifest?.role === "readme");
  const hasCode = parsed.some((r) => r.file_type === "rs");
  assert.ok(hasReadme, "readme record missing project_manifest.role=readme");
  assert.ok(hasCode, "rs record missing file_type=rs");
});

// ── Step 3: detect-format on tech-T-999.jsonl passes validation ─────────
step("detect-format.v2 accepts tech-T-999.jsonl (kind=documentation)", () => {
  run("detect-format.v2.mjs", "data/incoming/tech-T-999.jsonl");
  const mapPath = path.join(TMP, "data/incoming/tech-T-999.mapping.json");
  assert.ok(fs.existsSync(mapPath), "mapping.json not created");
  const mapping = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  assert.equal(mapping.kind, "documentation", "tech-*.jsonl must route to plain documentation");
});

// ── Step 4: detect-format on mini-project.jsonl (project_source_code) ────
step("detect-format.v2 accepts mini-project.jsonl (project bundle, nested facets)", () => {
  run("detect-format.v2.mjs", "data/incoming/mini-project.jsonl");
  const mapPath = path.join(TMP, "data/incoming/mini-project.mapping.json");
  assert.ok(fs.existsSync(mapPath), "mapping.json not created");
  const mapping = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  // Order in wrap-inputs may pick either record first; both project shapes
  // are valid — assert one of them.
  const validKinds = new Set(["project_source_code", "project_documentation"]);
  assert.ok(
    validKinds.has(mapping.kind),
    `expected project_* kind, got ${mapping.kind}`,
  );
  // Facet spec check: nested project object must NOT contain literal strings
  // (that was the bug — projectName as plain string failed isValidFacetSpec).
  const proj = mapping.facets?.project;
  assert.ok(proj && typeof proj === "object", "facets.project missing");
  for (const [k, v] of Object.entries(proj)) {
    assert.ok(
      v == null || (typeof v === "object" && Array.isArray(v.path)),
      `facets.project.${k} must be null or {path, join}; got ${JSON.stringify(v)}`,
    );
  }
});

// ── Step 5: detect-format on loose-note.jsonl ─────────────────────────────
step("detect-format.v2 accepts loose-note.jsonl (kind=documentation)", () => {
  run("detect-format.v2.mjs", "data/incoming/loose-note.jsonl");
  const mapping = JSON.parse(fs.readFileSync(path.join(TMP, "data/incoming/loose-note.mapping.json"), "utf8"));
  assert.equal(mapping.kind, "documentation");
});

// ── Step 6: apply-mapping produces canonical records with resolved facets
step("apply-mapping.v2 produces canonical records with resolved facets", () => {
  run("apply-mapping.v2.mjs", "data/incoming/tech-T-999.jsonl");
  run("apply-mapping.v2.mjs", "data/incoming/mini-project.jsonl");
  run("apply-mapping.v2.mjs", "data/incoming/loose-note.jsonl");
  const techNorm = path.join(TMP, "data/normalized/tech-T-999.jsonl");
  const projNorm = path.join(TMP, "data/normalized/mini-project.jsonl");
  const looseNorm = path.join(TMP, "data/normalized/loose-note.jsonl");
  assert.ok(fs.existsSync(techNorm), "tech normalized missing");
  assert.ok(fs.existsSync(projNorm), "project normalized missing");
  assert.ok(fs.existsSync(looseNorm), "loose normalized missing");

  const techRec = JSON.parse(fs.readFileSync(techNorm, "utf8").trim());
  assert.equal(techRec.kind, "documentation");
  assert.equal(techRec.title, "E2E Fixture Card");
  assert.ok(techRec.content.includes("Deterministic content"));

  const projLines = fs.readFileSync(projNorm, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  assert.ok(projLines.length >= 1);
  // The routing.semantic_complexity survives; and if project_source_code was
  // picked, the resolved facets should have concrete strings (not path specs).
  const anyProjectRec = projLines.find((r) => r.kind?.startsWith("project_"));
  if (anyProjectRec) {
    const proj = anyProjectRec.facets?.project;
    assert.ok(proj, "canonical project facet missing");
    assert.equal(typeof proj.name, "string", "facets.project.name should resolve to a string");
  }
});

// ── Step 7: multi-file enrichment preserves independent outputs ─────────────
step("enrich-records batches files without merging their outputs", () => {
  const canonical = (id, title) => ({
    id,
    title,
    content: `${title} fixture content`,
    kind: "training_preference",
    category: "fixture",
    language: "en",
    routing: { semantic_complexity: "simple", requested_enrichment: [] },
  });
  const first = path.join(TMP, "data/normalized/batch-a.jsonl");
  const second = path.join(TMP, "data/normalized/batch-b.jsonl");
  fs.writeFileSync(first, `${JSON.stringify(canonical("batch-a", "Batch A"))}\n`);
  fs.writeFileSync(second, `${JSON.stringify(canonical("batch-b", "Batch B"))}\n`);

  const out = run("enrich-records.mjs", first, second);
  assert.match(out, /batch start: 2 file\(s\); shared local model=not needed/);
  for (const name of ["batch-a", "batch-b"]) {
    const enrichedPath = path.join(TMP, `data/enriched/${name}.jsonl`);
    const reportPath = path.join(TMP, `data/enriched/${name}.report.json`);
    assert.ok(fs.existsSync(enrichedPath), `${name} enriched output missing`);
    assert.ok(fs.existsSync(reportPath), `${name} report missing`);
    const enriched = JSON.parse(fs.readFileSync(enrichedPath, "utf8").trim());
    assert.equal(enriched.id, name);
    assert.equal(enriched.enrichment.status, "not_requested");
  }
});

// ── Done ───────────────────────────────────────────────────────────────────
console.log(`\n[e2e] all ${passed} steps passed`);
console.log(`[e2e] cleaning up: ${TMP}`);
fs.rmSync(TMP, { recursive: true, force: true });
