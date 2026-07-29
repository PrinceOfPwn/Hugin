#!/usr/bin/env node
// wrap-bundle-techniques.mjs
// Surgical wrapper: walks curated technique cards under
// data/incoming/bundle-*/{techniques,techniques-generated}/, extracts each
// card id: T-NNN from YAML frontmatter, and — if that ID is NOT already in
// the compiled graph (data/source/public-graph.json) — emits a per-card JSONL
// at data/incoming/tech-T-NNN.jsonl for the ingest pipeline to pick up.
// Never touches the bundle. Idempotent. Post-ingest purge deletes only the
// emitted JSONL; the bundle stays intact.
// Env: HUGIN_BUNDLE_SUBDIRS comma-separated (default techniques,techniques-generated)
import fs from "node:fs";
import path from "node:path";

const INCOMING = path.resolve("data/incoming");
const GRAPH_PATH = path.resolve("data/source/public-graph.json");
const MANIFEST_PATH = path.resolve("data/source/ingest-manifest.json");
const DRY_RUN = process.env.HUGIN_BUNDLE_DRY_RUN === "true";
const SUBDIRS = (process.env.HUGIN_BUNDLE_SUBDIRS || "techniques,techniques-generated")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const now = new Date().toISOString();

function readGraphState() {
  const existingIds = new Set();
  const repairIds = new Set();
  if (!fs.existsSync(GRAPH_PATH)) return { existingIds, repairIds };
  try {
    const g = JSON.parse(fs.readFileSync(GRAPH_PATH, "utf8"));
    const nodes = new Map();
    for (const n of g.nodes || []) {
      const id = String(n?.id || "").trim();
      if (id) nodes.set(id, n);
      if (/^T-\d{3}$/.test(id)) existingIds.add(id);
      const label = String(n?.label || n?.title || "");
      const m = label.match(/^T-(\d{3})/);
      if (m) existingIds.add(`T-${m[1]}`);
    }
    if (fs.existsSync(MANIFEST_PATH)) {
      const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
      for (const [source, details] of Object.entries(manifest.sources || {})) {
        const match = source.match(/^data\/incoming\/tech-(T-\d{3})\.jsonl$/);
        if (!match) continue;
        const techniqueId = match[1];
        const ownedNodes = (details?.node_ids || []).map((id) => nodes.get(id)).filter(Boolean);
        if (ownedNodes.length > 0) existingIds.add(techniqueId);
        if (ownedNodes.some((node) => node.enrichment_status === "degraded")) repairIds.add(techniqueId);
      }
    }
    return { existingIds, repairIds };
  } catch (e) {
    console.warn(`could not parse public-graph.json: ${e.message}`);
    return { existingIds, repairIds };
  }
}

function extractFrontmatter(text) {
  const m = text.match(/^---\s*\n([\s\S]*?)\n---\s*\n?/);
  return m ? m[1] : null;
}

function parseId(fm) {
  const m = fm && fm.match(/^\s*id\s*:\s*["']?(T-\d{3})["']?\s*$/m);
  return m ? m[1] : null;
}

function parseCategory(fm) {
  const m = fm && fm.match(/^\s*category\s*:\s*["']?([^"'\n]+?)["']?\s*$/m);
  return m ? m[1].trim() : null;
}

function parseTier(fm) {
  const m = fm && fm.match(/^\s*tier\s*:\s*["']?([SABC])["']?\s*$/m);
  return m ? m[1] : null;
}

function parseTitle(text) {
  const m = text.match(/^#\s+(.+?)\s*$/m);
  return m ? m[1].trim() : null;
}

function findBundles() {
  try {
    return fs.readdirSync(INCOMING, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^bundle-\d+$/.test(e.name))
      .map((e) => path.join(INCOMING, e.name));
  } catch { return []; }
}

function collectCardFiles() {
  const files = [];
  for (const bundle of findBundles()) {
    for (const sub of SUBDIRS) {
      const dir = path.join(bundle, sub);
      if (!fs.existsSync(dir)) continue;
      for (const name of fs.readdirSync(dir)) {
        if (!name.endsWith(".md")) continue;
        if (name.endsWith(".bak")) continue;
        files.push({ full: path.join(dir, name), bundle: path.basename(bundle), sub, name });
      }
    }
  }
  return files;
}

function emitCard(entry, existingIds, repairIds) {
  const text = fs.readFileSync(entry.full, "utf8");
  const fm = extractFrontmatter(text);
  const id = parseId(fm);
  if (!id) return { action: "skip-no-id", src: entry.name };
  if (existingIds.has(id) && !repairIds.has(id)) return { action: "skip-already-in-graph", src: entry.name, id };
  const outPath = path.join(INCOMING, `tech-${id}.jsonl`);
  if (fs.existsSync(outPath)) return { action: "skip-existing-jsonl", src: entry.name, id, out: path.basename(outPath) };

  // NB: keep the record shape aligned with the validator's allowed `kind`
  // whitelist in detect-format.v2 — we intentionally do NOT emit
  // `project_manifest` so the deterministic router picks documentationMapping
  // (kind: "documentation") instead of the extended `project_documentation`
  // kind (not yet whitelisted downstream). Bundle provenance survives in
  // `tags` and `source_bundle` for cross-reference.
  const record = {
    id,
    title: parseTitle(text) || id,
    body: text,
    category: parseCategory(fm),
    tier: parseTier(fm),
    language: "en",
    tags: [
      "technique-card",
      `origin:${entry.bundle}`,
      `role:${entry.sub === "techniques" ? "curated" : "generated"}`,
    ],
    source_bundle: entry.bundle,
    source_relative_path: `${entry.sub}/${entry.name}`,
    wrapped_from: "bundle_technique_card",
    wrapped_at: now,
  };
  if (!DRY_RUN) fs.writeFileSync(outPath, JSON.stringify(record) + "\n");
  return { action: repairIds.has(id) ? "repair" : "emit", src: entry.name, id, out: path.basename(outPath) };
}

const files = collectCardFiles();
if (files.length === 0) {
  console.log("[bundle-tech] no bundle techniques found — nothing to emit");
  process.exit(0);
}

const { existingIds, repairIds } = readGraphState();
console.log(`[bundle-tech] scanning ${files.length} cards; ${existingIds.size} present; ${repairIds.size} degraded`);

const stats = { emit: 0, repair: 0, skipped: 0 };
for (const entry of files) {
  const r = emitCard(entry, existingIds, repairIds);
  if (r.action === "emit" || r.action === "repair") {
    stats[r.action]++;
    console.log(`[bundle-tech] ${r.action} ${r.id} -> ${r.out}`);
  } else {
    stats.skipped++;
  }
}
console.log(`[bundle-tech] summary: emitted=${stats.emit} repaired=${stats.repair} skipped=${stats.skipped}`);
