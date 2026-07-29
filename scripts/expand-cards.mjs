#!/usr/bin/env node
/**
 * expand-cards.mjs
 *
 * Turn LGTM clusters (candidate technique clusters mined from raw notes) into
 * fresh T-NNN technique cards using GLM-5.2 exclusively (via the NVIDIA
 * Integrate cloud). The generated markdown lands under
 * `data/incoming/expand-<ISO>/T-NNN-*.md` where the existing ingest workflow
 * (ingest-v2.yml) will pick it up and compile it into the public graph on the
 * next scheduled run.
 *
 * Env vars:
 *   NVIDIA_API_KEY         (required unless dry-run + fake mode)
 *   EXPAND_MODE            pending | gaps | cluster | refresh   (default pending)
 *   EXPAND_PRIORITY        high | medium | low | any            (default high)
 *   EXPAND_LIMIT           integer                              (default 3)
 *   EXPAND_CLUSTER_ID      cluster id (used only when EXPAND_MODE=cluster)
 *   EXPAND_DRY_RUN         "true" to skip writing cards, dump payloads instead
 *
 * Exit codes:
 *   0  success (including "no clusters found; nothing to expand")
 *   1  hard failure (no API key when needed, etc.)
 */

import fs from "node:fs";
import path from "node:path";
import { NvidiaModelsClient } from "./lib/nvidia-models.mjs";

const REPO_ROOT = path.resolve(process.cwd());
const PROMPT_TEMPLATE_PATH = path.join(REPO_ROOT, "prompts/glm-expand-cluster-to-card.md");
const GRAPH_PATH = path.join(REPO_ROOT, "data/source/public-graph.json");
const TECHNIQUES_DIRS = [
  path.join(REPO_ROOT, "techniques"),
  path.resolve(REPO_ROOT, "..", "techniques"),
];
const OUT_ROOT = path.join(REPO_ROOT, "data/incoming");
const DRYRUN_PATH = path.join(REPO_ROOT, "expand-cards-dryrun.json");

const MODEL_ID = "z-ai/glm-5.2";
const RETRY_DELAYS_MS = [30_000, 60_000, 120_000];
const MAX_OUTPUT_TOKENS = 8192;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- args / env ----------
function readEnv() {
  const mode = (process.env.EXPAND_MODE || "pending").toLowerCase();
  const priority = (process.env.EXPAND_PRIORITY || "high").toLowerCase();
  const limit = Math.max(1, parseInt(process.env.EXPAND_LIMIT || "3", 10) || 3);
  const clusterId = process.env.EXPAND_CLUSTER_ID || "";
  const dryRun = String(process.env.EXPAND_DRY_RUN || "false").toLowerCase() === "true";
  if (!["pending", "gaps", "cluster", "refresh"].includes(mode)) {
    console.error(`unknown EXPAND_MODE=${mode}`);
    process.exit(1);
  }
  if (!["high", "medium", "low", "any"].includes(priority)) {
    console.error(`unknown EXPAND_PRIORITY=${priority}`);
    process.exit(1);
  }
  if (mode === "cluster" && !clusterId) {
    console.error("EXPAND_MODE=cluster requires EXPAND_CLUSTER_ID");
    process.exit(1);
  }
  return { mode, priority, limit, clusterId, dryRun };
}

// ---------- cluster discovery ----------
function existsFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

function* walkGlob(root, matcher, depth = 6) {
  if (depth < 0) return;
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      yield* walkGlob(full, matcher, depth - 1);
    } else if (entry.isFile() && matcher(full)) {
      yield full;
    }
  }
}

function collectClusterFiles(mode) {
  const roots = [
    path.join(REPO_ROOT, "data/incoming/.wrapped"),
    path.join(REPO_ROOT, "data/incoming"),
    path.resolve(REPO_ROOT, "..", "vault-export"),
    path.join(REPO_ROOT, "vault-export"),
  ];
  const preferredByMode = {
    pending: /(^|\/)lgtm-clusters-pending[^\/]*\.json$/,
    gaps:    /(^|\/)lgtm-clusters-gaps[^\/]*\.json$/,
    cluster: /(^|\/)lgtm-clusters[^\/]*\.json$/,
    refresh: /(^|\/)lgtm-clusters(\.json|-[^g][^\/]*\.json)$/,
  };
  const matcher = (p) => preferredByMode[mode].test(p) && p.endsWith(".json");
  const seen = new Set();
  const results = [];
  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    for (const f of walkGlob(root, matcher)) {
      if (!seen.has(f)) { seen.add(f); results.push(f); }
    }
  }
  // If nothing matched the mode-specific pattern, widen to any lgtm-clusters*.json
  if (results.length === 0) {
    const anyMatcher = (p) => /lgtm-clusters[^\/]*\.json$/.test(p);
    for (const root of roots) {
      if (!fs.existsSync(root)) continue;
      for (const f of walkGlob(root, anyMatcher)) {
        if (!seen.has(f)) { seen.add(f); results.push(f); }
      }
    }
  }
  return results;
}

function loadClusters(files) {
  const all = [];
  const seenIds = new Set();
  for (const file of files) {
    let doc;
    try { doc = JSON.parse(fs.readFileSync(file, "utf8")); }
    catch (e) { console.warn(`skip ${file}: ${e.message}`); continue; }
    const clusters = Array.isArray(doc?.clusters) ? doc.clusters : (Array.isArray(doc) ? doc : []);
    for (const c of clusters) {
      if (!c || !c.cluster_id) continue;
      if (seenIds.has(c.cluster_id)) continue;
      seenIds.add(c.cluster_id);
      all.push({ ...c, _source_file: file });
    }
  }
  return all;
}

// ---------- coverage detection ----------
function loadCoverageCorpus() {
  // Concatenate whatever card / graph data we can find and search it for
  // cluster_id / cluster name substrings.
  const chunks = [];
  if (existsFile(GRAPH_PATH)) {
    try { chunks.push(fs.readFileSync(GRAPH_PATH, "utf8")); } catch {}
  }
  for (const dir of TECHNIQUES_DIRS) {
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir)) {
      if (!entry.endsWith(".md")) continue;
      try { chunks.push(fs.readFileSync(path.join(dir, entry), "utf8")); } catch {}
    }
  }
  return chunks.join("\n\n");
}

function isCovered(cluster, corpus) {
  if (!corpus) return false;
  const needleId = cluster.cluster_id;
  const needleName = cluster.canonical_name;
  if (needleId && corpus.includes(needleId)) return true;
  if (needleName && corpus.includes(needleName)) return true;
  // Also flag if all member notes are already cited in existing cards
  const notes = Array.isArray(cluster.member_note_ids) ? cluster.member_note_ids : [];
  if (notes.length > 0 && notes.every((n) => corpus.includes(n))) return true;
  return false;
}

// ---------- next id ----------
function nextTechniqueId() {
  const ids = new Set();
  for (const dir of TECHNIQUES_DIRS) {
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir)) {
      const m = entry.match(/^T-(\d{3,})/);
      if (m) ids.add(parseInt(m[1], 10));
    }
  }
  // Also scan the graph for any id we may have missed
  if (existsFile(GRAPH_PATH)) {
    try {
      const txt = fs.readFileSync(GRAPH_PATH, "utf8");
      const re = /T-(\d{3,})/g;
      let m;
      while ((m = re.exec(txt)) !== null) ids.add(parseInt(m[1], 10));
    } catch {}
  }
  let max = 0;
  for (const id of ids) if (id > max) max = id;
  return max + 1;
}

// ---------- filtering ----------
function filterClusters(clusters, opts, corpus) {
  const { mode, priority, clusterId } = opts;
  let candidates = clusters.slice();

  if (mode === "cluster") {
    candidates = candidates.filter((c) => c.cluster_id === clusterId);
  } else if (mode === "refresh") {
    candidates = candidates.filter((c) => isCovered(c, corpus));
  } else {
    // pending / gaps → filter out already-covered clusters
    candidates = candidates.filter((c) => !isCovered(c, corpus));
  }

  if (priority !== "any") {
    candidates = candidates.filter((c) => (c.priority || "").toLowerCase() === priority);
  }

  // deterministic ordering: priority weight → cluster_id
  const pw = { high: 0, medium: 1, low: 2 };
  candidates.sort((a, b) => {
    const ap = pw[(a.priority || "").toLowerCase()] ?? 3;
    const bp = pw[(b.priority || "").toLowerCase()] ?? 3;
    if (ap !== bp) return ap - bp;
    return String(a.cluster_id).localeCompare(String(b.cluster_id));
  });

  return candidates;
}

// ---------- prompt rendering ----------
function renderEvidence(cluster) {
  const lines = [];
  lines.push(`proposed_category: ${cluster.proposed_category || "unknown"}`);
  lines.push(`proposed_tier: ${cluster.proposed_tier || "unknown"}`);
  lines.push(`rationale: ${cluster.rationale || ""}`);
  if (cluster.technical_anchor) lines.push(`technical_anchor: ${cluster.technical_anchor}`);
  if (Array.isArray(cluster.would_relate_to) && cluster.would_relate_to.length) {
    lines.push(`would_relate_to: ${cluster.would_relate_to.join(", ")}`);
  }
  if (cluster.priority) lines.push(`priority: ${cluster.priority} (${cluster.priority_reason || ""})`);
  const notes = Array.isArray(cluster.member_note_ids) ? cluster.member_note_ids : [];
  if (notes.length) {
    lines.push("member_note_ids:");
    for (const n of notes) lines.push(`  - ${n}`);
  }
  return lines.join("\n");
}

function renderPrompt(template, cluster, nextIdPadded) {
  return template
    .replaceAll("{{cluster_id}}", cluster.cluster_id)
    .replaceAll("{{cluster_name}}", cluster.canonical_name || cluster.cluster_id)
    .replaceAll("{{cluster_description}}", cluster.consolidated_description || "")
    .replaceAll("{{cluster_evidence}}", renderEvidence(cluster))
    .replaceAll("{{next_card_id}}", nextIdPadded);
}

// ---------- GLM call (markdown, not JSON) ----------
async function callGlmMarkdown({ apiKey, baseUrl, prompt }) {
  const url = `${baseUrl.replace(/\/$/, "")}/chat/completions`;
  const body = {
    model: MODEL_ID,
    messages: [
      { role: "system", content: "You are an expert offensive-security technical writer. Produce full markdown documents with YAML frontmatter as instructed." },
      { role: "user", content: prompt },
    ],
    temperature: 0.2,
    top_p: 1,
    max_tokens: MAX_OUTPUT_TOKENS,
    seed: 42,
  };
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) {
    return { ok: false, error: `${response.status} ${text.slice(0, 400)}` };
  }
  let parsed;
  try { parsed = JSON.parse(text); }
  catch (e) { return { ok: false, error: `non-JSON response: ${e.message}` }; }
  const content = parsed?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || content.trim().length === 0) {
    return { ok: false, error: "empty completion" };
  }
  return { ok: true, content };
}

async function callGlmWithRetry(prompt) {
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) return { ok: false, error: "NVIDIA_API_KEY not set" };
  const baseUrl = process.env.NVIDIA_API_BASE_URL || "https://integrate.api.nvidia.com/v1";
  let lastError = null;
  for (let attempt = 0; attempt < RETRY_DELAYS_MS.length + 1; attempt++) {
    const res = await callGlmMarkdown({ apiKey, baseUrl, prompt });
    if (res.ok) return res;
    lastError = res.error;
    if (attempt < RETRY_DELAYS_MS.length) {
      const delay = RETRY_DELAYS_MS[attempt];
      console.warn(`GLM attempt ${attempt + 1} failed: ${lastError}; sleeping ${delay}ms`);
      await sleep(delay);
    }
  }
  return { ok: false, error: lastError || "unknown error" };
}

// ---------- output helpers ----------
function slugify(s) {
  return String(s || "card")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "card";
}

function pad3(n) { return String(n).padStart(3, "0"); }

function extractCardMarkdown(raw) {
  // Strip any leading commentary or ```markdown fences the model may add.
  let s = raw.trim();
  const fence = s.match(/^```(?:markdown|md)?\s*\n([\s\S]*?)\n```\s*$/i);
  if (fence) s = fence[1].trim();
  const firstDelim = s.indexOf("---");
  if (firstDelim > 0) s = s.slice(firstDelim);
  return s;
}

// ---------- main ----------
async function main() {
  const opts = readEnv();
  console.log(`expand-cards mode=${opts.mode} priority=${opts.priority} limit=${opts.limit} dry_run=${opts.dryRun}`);

  const clusterFiles = collectClusterFiles(opts.mode);
  if (clusterFiles.length === 0) {
    console.log("no clusters found; nothing to expand");
    process.exit(0);
  }
  console.log(`cluster source files (${clusterFiles.length}):`);
  for (const f of clusterFiles) console.log(`  - ${path.relative(REPO_ROOT, f)}`);

  const clusters = loadClusters(clusterFiles);
  console.log(`loaded ${clusters.length} unique clusters`);
  if (clusters.length === 0) {
    console.log("no clusters found; nothing to expand");
    process.exit(0);
  }

  const corpus = loadCoverageCorpus();
  const candidates = filterClusters(clusters, opts, corpus);
  console.log(`${candidates.length} candidates after filtering`);
  if (candidates.length === 0) {
    console.log("nothing to expand under current filters");
    process.exit(0);
  }

  const selected = candidates.slice(0, opts.limit);
  console.log(`selected ${selected.length} cluster(s) to expand:`);
  for (const c of selected) console.log(`  - ${c.cluster_id} [${c.priority || "?"}] ${c.canonical_name}`);

  // Fail fast if we need the API key
  if (!opts.dryRun && !process.env.NVIDIA_API_KEY) {
    console.error("NVIDIA_API_KEY is required (set via secrets.NVIDIA_API_KEY)");
    process.exit(1);
  }
  if (opts.dryRun && !process.env.NVIDIA_API_KEY) {
    console.warn("NVIDIA_API_KEY not set — dry-run will exercise prompt rendering only");
  }

  const template = fs.readFileSync(PROMPT_TEMPLATE_PATH, "utf8");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = path.join(OUT_ROOT, `expand-${timestamp}`);

  let nextId = nextTechniqueId();
  const summary = {
    ran_at: new Date().toISOString(),
    mode: opts.mode,
    priority: opts.priority,
    limit: opts.limit,
    dry_run: opts.dryRun,
    model: MODEL_ID,
    out_dir: path.relative(REPO_ROOT, outDir),
    ran: [],
    generated: [],
    failed: [],
  };
  const dryPayloads = [];

  for (const cluster of selected) {
    const idPadded = pad3(nextId);
    const prompt = renderPrompt(template, cluster, idPadded);
    summary.ran.push(cluster.cluster_id);

    if (opts.dryRun) {
      let content = null;
      let error = null;
      if (process.env.NVIDIA_API_KEY) {
        const res = await callGlmWithRetry(prompt);
        if (res.ok) content = res.content;
        else error = res.error;
      }
      dryPayloads.push({
        cluster_id: cluster.cluster_id,
        canonical_name: cluster.canonical_name,
        next_id: `T-${idPadded}`,
        prompt_chars: prompt.length,
        content,
        error,
      });
      if (content) {
        summary.generated.push({ cluster_id: cluster.cluster_id, id: `T-${idPadded}` });
        nextId += 1;
      } else if (error) {
        summary.failed.push({ cluster_id: cluster.cluster_id, error });
      } else {
        summary.generated.push({ cluster_id: cluster.cluster_id, id: `T-${idPadded}`, note: "prompt only (no api key)" });
        nextId += 1;
      }
      continue;
    }

    console.log(`\n=== expanding ${cluster.cluster_id} -> T-${idPadded} ===`);
    const res = await callGlmWithRetry(prompt);
    if (!res.ok) {
      console.error(`FAILED ${cluster.cluster_id}: ${res.error}`);
      summary.failed.push({ cluster_id: cluster.cluster_id, error: res.error });
      continue;
    }
    const md = extractCardMarkdown(res.content);
    if (!md.startsWith("---")) {
      console.error(`FAILED ${cluster.cluster_id}: output does not start with YAML frontmatter`);
      summary.failed.push({ cluster_id: cluster.cluster_id, error: "no yaml frontmatter in response" });
      continue;
    }
    fs.mkdirSync(outDir, { recursive: true });
    const filename = `T-${idPadded}-${slugify(cluster.canonical_name || cluster.cluster_id)}.md`;
    const outPath = path.join(outDir, filename);
    fs.writeFileSync(outPath, md);
    console.log(`wrote ${path.relative(REPO_ROOT, outPath)} (${md.length} chars)`);
    summary.generated.push({
      cluster_id: cluster.cluster_id,
      id: `T-${idPadded}`,
      file: path.relative(REPO_ROOT, outPath),
    });
    nextId += 1;
  }

  if (opts.dryRun) {
    fs.writeFileSync(DRYRUN_PATH, JSON.stringify({ summary, payloads: dryPayloads }, null, 2));
    console.log(`dry-run payload written to ${path.relative(REPO_ROOT, DRYRUN_PATH)}`);
  }

  console.log("\n=== summary ===");
  console.log(JSON.stringify(summary, null, 2));

  if (summary.generated.length === 0 && summary.failed.length > 0) {
    // All attempted expansions failed; surface non-zero so operator sees it.
    process.exit(2);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("expand-cards fatal error:", err?.stack || err);
  process.exit(1);
});
