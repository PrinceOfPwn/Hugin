#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { auditJsonSchema, buildMessages, inspectHeuristically, normalizeAudit, stableHash, summarizeAudits } from "./lib/mercury-audit.mjs";

const API_URL = process.env.MERCURY_API_URL ?? "https://api.inceptionlabs.ai/v1/chat/completions";
const MODEL = process.env.MERCURY_MODEL ?? "mercury-2";
const EFFORT = process.env.MERCURY_REASONING_EFFORT ?? "instant";

function args(argv) {
  const out = { graph: "data/source/public-graph.json", outDir: "artifacts/mercury-audit", limit: 0, startAt: 0, concurrency: 6, resume: false, heuristicOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--graph") out.graph = argv[++i];
    else if (a === "--out-dir") out.outDir = argv[++i];
    else if (a === "--limit") out.limit = Number(argv[++i]);
    else if (a === "--start-at") out.startAt = Number(argv[++i]);
    else if (a === "--concurrency") out.concurrency = Number(argv[++i]);
    else if (a === "--resume") out.resume = true;
    else if (a === "--heuristic-only") out.heuristicOnly = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  out.limit = Math.max(0, Math.floor(out.limit || 0));
  out.startAt = Math.max(0, Math.floor(out.startAt || 0));
  out.concurrency = Math.min(24, Math.max(1, Math.floor(out.concurrency || 6)));
  return out;
}

function loadExisting(file) {
  const map = new Map();
  if (!fs.existsSync(file)) return map;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean)) {
    try { const item = JSON.parse(line); if (item.entity_id) map.set(String(item.entity_id), item); } catch {}
  }
  return map;
}

function fallbackTitle(node) {
  const label = String(node.label ?? node.name ?? "").replace(/^QA\s*(?:·|:)\s*/i, "").trim();
  const parts = label.split(/\s+·\s+/).map((part) => part.trim()).filter(Boolean);
  return (parts.at(-1) ?? label) || null;
}

function prepareNode(graph, node) {
  const content = String(graph.contents?.[String(node.id)] ?? node.content ?? node.body ?? "");
  const heuristic = inspectHeuristically(node, content);
  const sourceHash = stableHash(JSON.stringify({ node, content: heuristic.answer })).slice(0, 20);
  return { node, content, heuristic, sourceHash };
}

function fallback(node, h, reason = "heuristic-only") {
  const wrongQa = h.issues.includes("incorrect_qa_classification");
  return normalizeAudit({
    detected_content_type: wrongQa ? "source_code" : h.qaTyped ? "qa" : h.codeLike ? "code_snippet" : "unknown",
    current_type_valid: !wrongQa,
    language: h.language,
    suggested_title: wrongQa ? fallbackTitle(node) : null,
    summary: String(node.summary ?? node.description ?? ""),
    tags: Array.isArray(node.tags) ? node.tags : [],
    mitre_candidates: [], entities: [], relation_candidates: [],
    quality_issues: h.issues.length ? h.issues : ["none"],
    recommended_renderer: h.codeLike ? "code" : h.qaTyped ? "qa" : "markdown",
    safe_fixes: { remove_qa_prefix: wrongQa, extract_technical_answer: wrongQa, set_content_format: h.codeLike ? "code" : "markdown", replace_summary: false, reclassify_node: wrongQa },
    confidence: wrongQa ? 0.82 : 0.5, needs_review: true, rationale: reason,
  }, node, h);
}

async function callMercury(messages, requestId) {
  const key = process.env.INCEPTION_API_KEY;
  if (!key) throw new Error("INCEPTION_API_KEY is required unless --heuristic-only is used");
  const body = { model: MODEL, reasoning_effort: EFFORT, messages, response_format: { type: "json_schema", json_schema: auditJsonSchema }, max_tokens: 1800, stream: false };
  let last;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const response = await fetch(API_URL, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "X-Request-Id": requestId }, body: JSON.stringify(body), signal: AbortSignal.timeout(150000) });
      const text = await response.text();
      if (!response.ok) throw new Error(`Mercury HTTP ${response.status}: ${text.slice(0, 500)}`);
      const payload = JSON.parse(text);
      const content = payload?.choices?.[0]?.message?.content;
      return typeof content === "string" ? JSON.parse(content) : content;
    } catch (error) {
      last = error;
      if (attempt < 5) await new Promise((r) => setTimeout(r, 750 * 2 ** (attempt - 1)));
    }
  }
  throw last;
}

function writeReports(dir, results, meta) {
  const summary = { ...summarizeAudits(results), ...meta };
  fs.writeFileSync(path.join(dir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  const review = results.filter((x) => x.needs_review || x.quality_issues?.some((i) => i !== "none")).sort((a, b) => b.confidence - a.confidence);
  fs.writeFileSync(path.join(dir, "review-queue.json"), `${JSON.stringify(review, null, 2)}\n`);
  const candidates = {
    generated_at: new Date().toISOString(),
    mitre: results.flatMap((x) => (x.mitre_candidates ?? []).map((c) => ({ entity_id: x.entity_id, ...c }))),
    relations: results.flatMap((x) => (x.relation_candidates ?? []).map((c) => ({ entity_id: x.entity_id, ...c }))),
    reclassifications: results.filter((x) => x.safe_fixes?.reclassify_node).map((x) => ({ entity_id: x.entity_id, from: x.current_content_type, to: x.detected_content_type, language: x.language, confidence: x.confidence, evidence: x.rationale })),
  };
  fs.writeFileSync(path.join(dir, "candidates.json"), `${JSON.stringify(candidates, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "REPORT.md"), `# Mercury graph audit\n\n- Nodes audited: **${summary.total}**\n- Needs review: **${summary.needs_review}**\n- Incorrect QA candidates: **${summary.incorrect_qa_candidates}**\n- Reclassification candidates: **${summary.reclassification_candidates}**\n- Model: \`${summary.model}\`\n\nSee \`review-queue.json\` and \`candidates.json\`.\n`);
}

async function main() {
  const opt = args(process.argv.slice(2));
  const graphPath = path.resolve(opt.graph);
  const outDir = path.resolve(opt.outDir);
  const jsonl = path.join(outDir, "audit.jsonl");
  fs.mkdirSync(outDir, { recursive: true });
  const graph = JSON.parse(fs.readFileSync(graphPath, "utf8"));
  const nodes = (graph.nodes ?? []).slice(opt.startAt, opt.limit > 0 ? opt.startAt + opt.limit : undefined);
  const entries = nodes.map((node) => prepareNode(graph, node));
  const existing = opt.resume ? loadExisting(jsonl) : new Map();
  if (!opt.resume) fs.writeFileSync(jsonl, "");
  const queue = entries.filter(({ node, sourceHash }) => existing.get(String(node.id))?.source_hash !== sourceHash);
  let cursor = 0, ok = 0, failed = 0;

  async function worker() {
    while (true) {
      const i = cursor++;
      if (i >= queue.length) return;
      const { node, content, heuristic } = queue[i];
      try {
        const raw = opt.heuristicOnly ? null : await callMercury(buildMessages(node, content, heuristic), crypto.randomUUID());
        const audit = opt.heuristicOnly ? fallback(node, heuristic) : normalizeAudit(raw, node, heuristic);
        fs.appendFileSync(jsonl, `${JSON.stringify(audit)}\n`); existing.set(String(node.id), audit); ok++;
      } catch (error) {
        const audit = fallback(node, heuristic, `Mercury failed: ${error.message}`);
        fs.appendFileSync(jsonl, `${JSON.stringify(audit)}\n`); existing.set(String(node.id), audit); failed++;
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(opt.concurrency, Math.max(1, queue.length)) }, worker));
  const selected = new Set(nodes.map((node) => String(node.id)));
  const allResults = [...existing.values()];
  const results = allResults.filter((item) => selected.has(String(item.entity_id)));
  fs.writeFileSync(jsonl, allResults.length ? `${allResults.map((item) => JSON.stringify(item)).join("\n")}\n` : "");
  writeReports(outDir, results, { graph: opt.graph, model: opt.heuristicOnly ? "heuristic-only" : MODEL, reasoning_effort: opt.heuristicOnly ? null : EFFORT, success: ok, failed, skipped_unchanged: entries.length - queue.length });
  console.log(`Audit complete: ${results.length} entities; ${failed} Mercury failures; ${entries.length - queue.length} unchanged; artifact=${outDir}`);

  if (!opt.heuristicOnly && queue.length > 0 && ok === 0) {
    throw new Error(`Mercury failed for all ${failed} queued entities; inspect the uploaded artifact for HTTP/API errors`);
  }
}

main().catch((error) => { console.error(error.stack ?? error.message); process.exit(1); });
