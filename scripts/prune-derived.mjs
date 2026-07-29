#!/usr/bin/env node
// Prunes orphaned files under data/normalized/ and data/enriched/ whose parent
// source key is no longer present in data/source/ingest-manifest.json.
import fs from "node:fs";
import path from "node:path";

const args = new Set(process.argv.slice(2));
const CONFIRM = args.has("--confirm");
// --dry-run is the implicit default.

const repoRoot = process.cwd();
const normalizedDir = path.resolve(repoRoot, "data/normalized");
const enrichedDir = path.resolve(repoRoot, "data/enriched");
const manifestPath = path.resolve(repoRoot, "data/source/ingest-manifest.json");

function toPosix(p) {
  return p.split(path.sep).join("/");
}

function pad(str, width) {
  return str.length >= width ? str : str + " ".repeat(width - str.length);
}

// Mirrors flattening used elsewhere:
//   key = "data/incoming/foo/bar.jsonl"  ->  "foo_bar"
function flattenSourceKey(key) {
  return key
    .replace(/^data\/incoming\//, "")
    .replace(/\.jsonl$/, "")
    .replace(/\//g, "_");
}

// basename minus .jsonl / .report.json
function derivedBase(name) {
  if (name.endsWith(".report.json")) return name.slice(0, -".report.json".length);
  if (name.endsWith(".jsonl")) return name.slice(0, -".jsonl".length);
  return null;
}

function listDerived(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const base = derivedBase(entry.name);
    if (base === null) continue;
    out.push({ abs: path.join(dir, entry.name), base });
  }
  return out.sort((a, b) => a.abs.localeCompare(b.abs));
}

function main() {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    console.error(`Failed to read manifest ${toPosix(path.relative(repoRoot, manifestPath))}: ${err.message}`);
    process.exit(1);
  }

  const liveBases = new Set(Object.keys(manifest.sources ?? {}).map(flattenSourceKey));

  let derived;
  try {
    derived = [...listDerived(normalizedDir), ...listDerived(enrichedDir)];
  } catch (err) {
    console.error(`Failed to scan derived dirs: ${err.message}`);
    process.exit(1);
  }

  const rows = derived.map(({ abs, base }) => {
    const rel = toPosix(path.relative(repoRoot, abs));
    const live = liveBases.has(base);
    return {
      abs,
      rel,
      status: live ? "KEEP" : "ORPHAN",
      details: live ? `parent "${base}" in manifest` : `no manifest source flattens to "${base}"`,
    };
  });

  const statusW = Math.max(6, ...rows.map((r) => r.status.length));
  const fileW = Math.max(4, ...rows.map((r) => r.rel.length));
  const header = `${pad("STATUS", statusW)}  ${pad("FILE", fileW)}  DETAILS`;
  console.log(header);
  console.log("-".repeat(header.length));
  for (const r of rows) {
    console.log(`${pad(r.status, statusW)}  ${pad(r.rel, fileW)}  ${r.details}`);
  }
  if (rows.length === 0) console.log("(no derived files found)");

  const orphans = rows.filter((r) => r.status === "ORPHAN");

  if (!CONFIRM) {
    console.log("");
    console.log(`Dry-run: ${orphans.length} of ${rows.length} file(s) would be deleted. Re-run with --confirm to delete.`);
    process.exit(0);
  }

  console.log("");
  console.log(`Deleting ${orphans.length} file(s)...`);
  for (const r of orphans) {
    try {
      fs.unlinkSync(r.abs);
      console.log(`deleted ${r.rel}`);
    } catch (err) {
      console.error(`Failed to delete ${r.rel}: ${err.message}`);
      process.exit(1);
    }
  }
  process.exit(0);
}

main();
