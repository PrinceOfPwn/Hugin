/**
 * import-qa.mjs
 *
 * Imports a .jsonl file of Q&A research records into the HUGIN knowledge graph
 * as `tradecraft_qa` nodes inside the dedicated `tradecraft_qa` galaxy.
 *
 * Usage:
 *   node scripts/import-qa.mjs <input.jsonl> [--dry-run]
 *
 * The script reads the enriched .jsonl produced by enrich-qa.mjs (which adds
 * `_hugin.summary`, `_hugin.mitre`, and `_hugin.tags` fields). If those fields
 * are missing, it falls back to safe defaults and the node is still imported.
 *
 * After running this script, run:
 *   npm run data:build && npm run data:validate
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { sanitizeString } from "./lib/sanitize.mjs";

// ── Config ────────────────────────────────────────────────────────────────────
const GRAPH_PATH = path.resolve("data/source/public-graph.json");
const GALAXY_ID = "tradecraft_qa";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const flags = new Set(process.argv.slice(2).filter((a) => a.startsWith("--")));
const DRY_RUN = flags.has("--dry-run");

if (args.length === 0) {
  console.error("Usage: node scripts/import-qa.mjs <input.jsonl> [--dry-run]");
  process.exit(1);
}

const inputPath = path.resolve(args[0]);
if (!fs.existsSync(inputPath)) {
  console.error(`Input file not found: ${inputPath}`);
  process.exit(1);
}

if (!fs.existsSync(GRAPH_PATH)) {
  console.error(`Graph not found: ${GRAPH_PATH}. Run npm run data:import first.`);
  process.exit(1);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const shortHash = (value, length = 16) => sha256(value).slice(0, length);

function sentence(value, length = 300) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (text.length <= length) return text;
  return `${text.slice(0, length).replace(/\s+\S*$/, "")}…`;
}

/**
 * Map task type → subgalaxy label for cleaner catalog browsing.
 */
function subgalaxyFor(task) {
  const map = {
    exploit_dev: "Exploit Development",
    evasion: "Evasion & Defense Bypass",
    web_exploit: "Web Exploitation",
    reversing: "Reverse Engineering",
    malware_analysis: "Malware Analysis",
    persistence: "Persistence Mechanisms",
    lateral_movement: "Lateral Movement",
    recon: "Reconnaissance",
    post_exploitation: "Post-Exploitation",
    forensics: "Forensics & DFIR",
    cryptography: "Cryptography",
    network: "Network Operations",
  };
  return map[task] || "Tradecraft Research";
}

/**
 * Build the full Markdown body preserved verbatim for the entity page.
 * Sanitizes all text blocks to remove local paths, usernames, and private source labels.
 */
function buildMarkdownBody(record) {
  const {
    prompt = "",
    answer = "",
    task = "",
    model = "",
    near_miss = [],
    _hugin = {},
  } = record;

  const cleanPrompt = sanitizeString(prompt);
  const cleanAnswer = sanitizeString(answer);

  const nearMissSection =
    Array.isArray(near_miss) && near_miss.length > 0
      ? `\n\n## ⚠️ Failure Modes & Alternatives Considered\n\n${near_miss
          .map((nm, i) => {
            if (typeof nm === "string") return `- ${sanitizeString(nm)}`;
            if (typeof nm === "object" && nm !== null) {
              const val = nm.value ?? nm.text ?? nm.answer ?? JSON.stringify(nm);
              return `- **Alternative ${i + 1}:** ${sanitizeString(val)}`;
            }
            return `- ${sanitizeString(String(nm))}`;
          })
          .join("\n")}`
      : "";

  const mitreSection =
    Array.isArray(_hugin.mitre) && _hugin.mitre.length > 0
      ? `\n\n## 📑 MITRE ATT&CK Coverage\n\n${_hugin.mitre.map((t) => `- \`${sanitizeString(t)}\``).join("\n")}`
      : "";

  const metaLine = [task && `**Task domain:** \`${sanitizeString(task)}\``, model && `**Model:** \`${sanitizeString(model)}\``]
    .filter(Boolean)
    .join("  ·  ");

  return `## 🎯 Research Context & Scenario

${cleanPrompt}

---

## 🔬 Full Technical Analysis

${cleanAnswer}${nearMissSection}${mitreSection}

---

*${metaLine}*
`.trim();
}

// ── Read JSONL ────────────────────────────────────────────────────────────────
console.log(`Reading: ${inputPath}`);
const rawLines = fs.readFileSync(inputPath, "utf8").split("\n").filter(Boolean);
const records = rawLines.map((line, i) => {
  try {
    return JSON.parse(line);
  } catch {
    console.warn(`  Line ${i + 1}: JSON parse error, skipping.`);
    return null;
  }
}).filter(Boolean);

console.log(`Parsed ${records.length} records.`);

// ── Load existing graph ───────────────────────────────────────────────────────
const graph = JSON.parse(fs.readFileSync(GRAPH_PATH, "utf8"));
const existingIds = new Set((graph.nodes || []).map((n) => String(n.id)));

const newNodes = [];
const newEdges = [];
const newContents = {};
let skipped = 0;

// ── Build nodes ───────────────────────────────────────────────────────────────
for (let index = 0; index < records.length; index++) {
  const record = records[index];
  // Guarantee unique stable ID even if input ID is missing or duplicate
  const rawId = record.id ?? sha256(`${index}:${record.prompt ?? ""}:${record.answer ?? ""}`).slice(0, 40);
  const publicId = `tradecraft_qa:${shortHash(rawId, 20)}`;

  if (existingIds.has(publicId)) {
    skipped++;
    continue;
  }

  const task = sanitizeString(record.task ?? "research");
  const model = sanitizeString(record.model ?? "");
  const hugin = record._hugin ?? {};

  const cleanPrompt = sanitizeString(record.prompt ?? "");
  const cleanAnswer = sanitizeString(record.answer ?? "");

  // Title: first 100 chars of the prompt (sanitized)
  const promptSnippet = sentence(cleanPrompt, 100);
  const title = `QA · ${subgalaxyFor(task)} · ${promptSnippet}`;

  // Summary: AI-generated if available, else first 240 chars of the answer (sanitized)
  const summary = sanitizeString(
    hugin.summary
      ? sentence(hugin.summary, 300)
      : sentence(cleanAnswer, 240)
  );

  // MITRE TTPs: AI-extracted or empty
  const mitre = Array.isArray(hugin.mitre) ? hugin.mitre.map((t) => sanitizeString(String(t))) : [];

  // Tags: AI keywords + task
  const aiTags = Array.isArray(hugin.tags) ? hugin.tags.map((t) => sanitizeString(String(t))) : [];
  const tags = [...new Set([task, ...aiTags])].map(sanitizeString).slice(0, 16);

  const body = buildMarkdownBody(record);
  const evidenceId = `QA-${shortHash(rawId, 10).toUpperCase()}`;

  const node = {
    id: publicId,
    type: "tradecraft_qa",
    publishState: "core",
    evidenceId,
    sourceClass: "operator-tradecraft-note",
    sourceHash: sha256(JSON.stringify(record)).slice(0, 16),
    label: title,
    name: title,
    summary,
    description: summary,
    category: subgalaxyFor(task),
    topic: task,
    tags,
    mitre,
    galaxyId: GALAXY_ID,
    qa_task: task,
    qa_model: model,
    qa_record_id: sanitizeString(rawId),
  };

  newNodes.push(node);
  newContents[publicId] = body;
  existingIds.add(publicId);
}

console.log(`New nodes: ${newNodes.length}  |  Skipped (already exist): ${skipped}`);

if (DRY_RUN) {
  console.log("\n-- DRY RUN: no files written --");
  console.log("Sample node (first):", JSON.stringify(newNodes[0], null, 2));
  process.exit(0);
}

if (newNodes.length === 0) {
  console.log("Nothing new to import. Exiting.");
  process.exit(0);
}

// ── Merge into graph ──────────────────────────────────────────────────────────
graph.nodes = [...(graph.nodes || []), ...newNodes];
graph.edges = [...(graph.edges || []), ...newEdges];
graph.contents = { ...(graph.contents || {}), ...newContents };

// Patch rawCounts so build-data.mjs doesn't reject the file
graph.rawCounts = {
  nodes: graph.nodes.length,
  relations: graph.edges.length,
};

fs.writeFileSync(GRAPH_PATH, `${JSON.stringify(graph)}\n`);

console.log(`\n✅ Imported ${newNodes.length} tradecraft_qa nodes into ${GRAPH_PATH}`);
console.log(`   Total nodes now: ${graph.nodes.length}`);
console.log(`\nNext steps:`);
console.log(`   npm run data:build && npm run data:validate`);
