#!/usr/bin/env node
// backfill-node-history.mjs
// One-shot self-healing: populates manifest.node_history for graph nodes that
// were compiled before compile-canonical.mjs learned to stamp firstSeenAt /
// lastUpdatedAt. Idempotent — nodes with an existing history entry are left
// untouched, so it's safe to run repeatedly (e.g. from the ingest workflow).
//
// Timestamp source: earliest git commit that touched data/source/public-graph.json
// (best-effort). Falls back to `now` if git history is unavailable.

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const GRAPH_PATH = path.resolve("data/source/public-graph.json");
const MANIFEST_PATH = path.resolve("data/source/ingest-manifest.json");

if (!fs.existsSync(GRAPH_PATH)) {
  console.log("[backfill-node-history] no public-graph.json; nothing to do");
  process.exit(0);
}

function earliestCommitTsForGraph() {
  try {
    const out = execSync(
      "git log --reverse --format=%aI -- data/source/public-graph.json",
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    const first = out.split("\n").map((s) => s.trim()).find(Boolean);
    return first || null;
  } catch { return null; }
}

const graph = JSON.parse(fs.readFileSync(GRAPH_PATH, "utf8"));
const nodes = graph.nodes ?? [];
const nodeIds = new Set(nodes.map((n) => n?.id).filter(Boolean));
console.log(`[backfill-node-history] graph has ${nodeIds.size} node ids`);

let manifest = {};
if (fs.existsSync(MANIFEST_PATH)) {
  try { manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8")); }
  catch { manifest = {}; }
}
manifest.node_history ??= {};

const stampTs = earliestCommitTsForGraph() ?? new Date().toISOString();
console.log(`[backfill-node-history] stamp ts = ${stampTs}`);

let stamped = 0, skipped = 0;
for (const id of nodeIds) {
  if (manifest.node_history[id]) { skipped++; continue; }
  manifest.node_history[id] = { firstSeenAt: stampTs, lastUpdatedAt: stampTs };
  stamped++;
}

// Also prune history for ids no longer in the graph
let pruned = 0;
for (const id of Object.keys(manifest.node_history)) {
  if (!nodeIds.has(id)) { delete manifest.node_history[id]; pruned++; }
}

if (stamped === 0 && pruned === 0) {
  console.log(`[backfill-node-history] no changes needed (${skipped} already stamped)`);
  process.exit(0);
}

fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + "\n");
console.log(`[backfill-node-history] stamped=${stamped} skipped=${skipped} pruned=${pruned}`);
