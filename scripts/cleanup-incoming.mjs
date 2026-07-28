#!/usr/bin/env node
// Removes data/incoming/**/*.jsonl inputs once their derived output has been
// durably compiled into the graph (manifest entry with node_ids + an enriched
// artifact on disk). Dry-run by default so this is safe to wire into CI
// without risking an accidental mass delete of not-yet-ingested inputs.
import fs from "node:fs";
import path from "node:path";

const args = new Set(process.argv.slice(2));
const CONFIRM = args.has("--confirm");
const INCLUDE_WRAPPED = args.has("--include-wrapped");
const PRUNE_CACHES = args.has("--prune-caches");
// --dry-run is accepted explicitly but dry-run is also the default when no
// flag is passed at all, so we only ever gate behavior on CONFIRM.

const repoRoot = process.cwd();
const incomingDir = path.resolve(repoRoot, "data/incoming");
const wrappedDir = path.resolve(incomingDir, ".wrapped");
const normalizedDir = path.resolve(repoRoot, "data/normalized");
const enrichedDir = path.resolve(repoRoot, "data/enriched");
const cacheDir = path.resolve(repoRoot, ".cache");
const publicGraphPath = path.resolve(repoRoot, "data/source/public-graph.json");
const manifestPath = path.resolve(repoRoot, "data/source/ingest-manifest.json");

function toPosix(p) {
  return p.split(path.sep).join("/");
}

function loadManifest() {
  if (!fs.existsSync(manifestPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    console.error(`Failed to parse manifest at ${manifestPath}: ${err.message}`);
    process.exitCode = 1;
    return null;
  }
}

// Recursively list *.jsonl files under data/incoming, skipping quarantine/
// staging dirs and the sibling metadata files that live next to real inputs.
function listIncomingJsonl(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    // Node's recursive readdir gives `parentPath` (or `path` on older 20.x) as
    // the absolute directory containing the entry.
    const parentPath = entry.parentPath ?? entry.path;
    const abs = path.join(parentPath, entry.name);
    const rel = toPosix(path.relative(dir, abs));
    if (rel.split("/").includes("quarantine")) continue;
    if (rel.split("/").includes(".wrapped")) continue;
    if (!entry.name.endsWith(".jsonl")) continue;
    if (entry.name.endsWith(".mapping.json") || entry.name.endsWith(".report.json")) continue;
    results.push(abs);
  }
  return results.sort();
}

// Mirrors the flattening logic in .github/workflows/ingest-v2.yml:
//   relative="${input#data/incoming/}"
//   name="$(echo "$relative" | tr '/' '_' | sed 's/\.jsonl$//')"
function flattenedBaseName(absJsonlPath) {
  const rel = toPosix(path.relative(incomingDir, absJsonlPath));
  return rel.replace(/\.jsonl$/, "").split("/").join("_");
}

function candidateSourceKeys(absJsonlPath) {
  const repoRelative = toPosix(path.relative(repoRoot, absJsonlPath));
  const baseNoExt = path.basename(absJsonlPath, ".jsonl");
  // repo-relative path first: this is what compile-canonical.mjs actually
  // stores as manifest.sources[key] (canonical[0].source.input_file, which
  // apply-mapping.v2.mjs sets to path.relative(process.cwd(), <incoming file>)).
  // basename-without-extension is a fallback for any legacy/alternate keying.
  return [...new Set([repoRelative, baseNoExt])];
}

function findManifestEntry(manifest, keys) {
  for (const key of keys) {
    const entry = manifest.sources?.[key];
    if (entry) return { key, entry };
  }
  return null;
}

function pad(str, width) {
  return str.length >= width ? str : str + " ".repeat(width - str.length);
}

// Recursively remove everything under `dir`, keeping `dir` itself.
// Returns count of entries removed (files + subdirs).
function rmContents(dir, dryRun) {
  let count = 0;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!dryRun) fs.rmSync(abs, { recursive: true, force: true });
      count += 1;
    } else {
      if (!dryRun) fs.unlinkSync(abs);
      count += 1;
    }
  }
  return count;
}

function loadPublicGraphIds() {
  if (!fs.existsSync(publicGraphPath)) return null;
  try {
    const g = JSON.parse(fs.readFileSync(publicGraphPath, "utf8"));
    const ids = new Set();
    for (const n of g.nodes ?? []) if (n?.id) ids.add(n.id);
    return ids;
  } catch (err) {
    console.error(`Failed to parse ${toPosix(path.relative(repoRoot, publicGraphPath))}: ${err.message}`);
    return null;
  }
}

// Prune stale entity-keyed entries in the vector-store cache.
// Shape: { engineTag, revision, byText?, byId?, ... }. We only touch id-keyed
// maps; text-keyed maps are left alone (their keys aren't entity ids).
function pruneVectorStore(file, liveIds, dryRun) {
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  let removed = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (!v || typeof v !== "object" || Array.isArray(v)) continue;
    if (!/^by[A-Z]/.test(k)) continue;
    if (k === "byText") continue;
    for (const id of Object.keys(v)) {
      if (!liveIds.has(id)) {
        delete v[id];
        removed += 1;
      }
    }
  }
  if (removed > 0 && !dryRun) fs.writeFileSync(file, JSON.stringify(raw));
  return removed;
}

function pruneEntitySimilarity(file, liveIds, dryRun) {
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  let removed = 0;
  if (raw && typeof raw.byId === "object" && raw.byId) {
    for (const id of Object.keys(raw.byId)) {
      if (!liveIds.has(id)) {
        delete raw.byId[id];
        removed += 1;
      }
    }
  }
  if (removed > 0 && !dryRun) fs.writeFileSync(file, JSON.stringify(raw));
  return removed;
}

function pruneVideoNotes(manifestText, dryRun) {
  const files = fs.readdirSync(cacheDir).filter((n) => /^video-notes-.+\.json$/.test(n));
  let removed = 0;
  for (const name of files) {
    const m = /^video-notes-(.+)\.json$/.exec(name);
    if (!m) continue;
    const fingerprint = m[1];
    if (manifestText.includes(fingerprint)) continue;
    const abs = path.join(cacheDir, name);
    if (!dryRun) fs.unlinkSync(abs);
    console.log(`[cache] pruned 1 stale entries from ${toPosix(path.relative(repoRoot, abs))}`);
    removed += 1;
  }
  return removed;
}

function pruneCaches(dryRun) {
  if (!fs.existsSync(cacheDir)) return;
  const liveIds = loadPublicGraphIds();
  if (liveIds === null) {
    console.warn(`[cache] no public-graph.json — skipping id-based prune of vector-store/entity-similarity`);
  }
  const manifestText = fs.existsSync(manifestPath) ? fs.readFileSync(manifestPath, "utf8") : "";

  const files = fs.readdirSync(cacheDir);
  for (const name of files) {
    const abs = path.join(cacheDir, name);
    const rel = toPosix(path.relative(repoRoot, abs));
    try {
      if (liveIds && /^vector-store-.+\.json$/.test(name)) {
        const n = pruneVectorStore(abs, liveIds, dryRun);
        if (n > 0) console.log(`[cache] pruned ${n} stale entries from ${rel}`);
      } else if (liveIds && /^entity-similarity-.+\.json$/.test(name)) {
        const n = pruneEntitySimilarity(abs, liveIds, dryRun);
        if (n > 0) console.log(`[cache] pruned ${n} stale entries from ${rel}`);
      }
    } catch (err) {
      console.error(`[cache] failed on ${rel}: ${err.message}`);
    }
  }
  // Video-notes cache is one-file-per-fingerprint; prune whole files not in manifest.
  try {
    pruneVideoNotes(manifestText, dryRun);
  } catch (err) {
    console.error(`[cache] failed on video-notes: ${err.message}`);
  }
}

function main() {
  const manifest = loadManifest();
  if (manifest === null) {
    if (process.exitCode === 1) return; // parse error already reported
    console.warn(`No manifest found at ${toPosix(path.relative(repoRoot, manifestPath))}; nothing to clean up.`);
    process.exit(0);
  }

  let jsonlFiles;
  try {
    jsonlFiles = listIncomingJsonl(incomingDir);
  } catch (err) {
    console.error(`Failed to list ${incomingDir}: ${err.message}`);
    process.exit(1);
  }

  const rows = [];
  for (const abs of jsonlFiles) {
    const repoRelative = toPosix(path.relative(repoRoot, abs));
    const keys = candidateSourceKeys(abs);
    const match = findManifestEntry(manifest, keys);

    let status = "KEEP";
    let details = "no manifest entry";
    let enrichedPath = null;

    if (match) {
      const nodeCount = Array.isArray(match.entry.node_ids) ? match.entry.node_ids.length : 0;
      if (nodeCount === 0) {
        details = "node_ids empty";
      } else {
        const flattened = flattenedBaseName(abs);
        enrichedPath = path.join(enrichedDir, `${flattened}.jsonl`);
        if (!fs.existsSync(enrichedPath)) {
          details = "no enriched output";
        } else {
          status = "SAFE-TO-DELETE";
          details = `manifest key "${match.key}", ${nodeCount} node(s), enriched present`;
        }
      }
    }

    rows.push({ abs, repoRelative, status, details });
  }

  const statusWidth = Math.max(6, ...rows.map((r) => r.status.length));
  const fileWidth = Math.max(4, ...rows.map((r) => r.repoRelative.length));
  const header = `${pad("STATUS", statusWidth)}  ${pad("FILE", fileWidth)}  DETAILS`;
  console.log(header);
  console.log("-".repeat(header.length));
  for (const row of rows) {
    console.log(`${pad(row.status, statusWidth)}  ${pad(row.repoRelative, fileWidth)}  ${row.details}`);
  }
  if (rows.length === 0) {
    console.log("(no data/incoming/**/*.jsonl files found)");
  }

  const safeRows = rows.filter((r) => r.status === "SAFE-TO-DELETE");

  if (!CONFIRM) {
    console.log("");
    console.log(`Dry-run: ${safeRows.length} of ${rows.length} file(s) would be deleted. Re-run with --confirm to delete.`);
    if (INCLUDE_WRAPPED && fs.existsSync(wrappedDir)) {
      try {
        const n = rmContents(wrappedDir, true);
        console.log(`[wrapped] would delete ${n} entries`);
      } catch (err) {
        console.error(`[wrapped] failed: ${err.message}`);
      }
    }
    if (PRUNE_CACHES) pruneCaches(true);
    process.exit(0);
  }

  console.log("");
  console.log(`Deleting ${safeRows.length} file(s)...`);
  for (const row of safeRows) {
    try {
      fs.unlinkSync(row.abs);
      console.log(`deleted ${row.repoRelative}`);
      const mappingSibling = row.abs.replace(/\.jsonl$/, ".mapping.json");
      if (fs.existsSync(mappingSibling)) {
        fs.unlinkSync(mappingSibling);
        console.log(`deleted ${toPosix(path.relative(repoRoot, mappingSibling))}`);
      }
    } catch (err) {
      console.error(`Failed to delete ${row.repoRelative}: ${err.message}`);
      process.exit(1);
    }
  }

  if (INCLUDE_WRAPPED && fs.existsSync(wrappedDir)) {
    try {
      const n = rmContents(wrappedDir, false);
      console.log(`[wrapped] deleted ${n} entries`);
    } catch (err) {
      console.error(`[wrapped] failed: ${err.message}`);
      process.exit(1);
    }
  }

  if (PRUNE_CACHES) pruneCaches(false);

  process.exit(0);
}

main();
