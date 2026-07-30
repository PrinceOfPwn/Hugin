#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { auditJsonSchema, buildMessages, inspectHeuristically, normalizeAudit, stableHash } from "./lib/mercury-audit.mjs";
import {
  buildProcessedIndex,
  nodeStratum,
  reconcileAudit,
  requiresReview,
  stratifiedSample,
} from "./lib/mercury-sampling.mjs";

const API_URL = process.env.MERCURY_API_URL ?? "https://api.inceptionlabs.ai/v1/chat/completions";
const MODEL = process.env.MERCURY_MODEL ?? "mercury-2";
const EFFORT = process.env.MERCURY_REASONING_EFFORT ?? "instant";

function args(argv) {
  const out = {
    graph: "data/source/public-graph.json",
    outDir: "artifacts/mercury-audit",
    stateFile: null,
    limit: 0,
    startAt: 0,
    concurrency: 6,
    resume: false,
    heuristicOnly: false,
    full: false,
    samplePercent: 0,
    sampleSize: 0,
    minPerType: 3,
    seed: "hugin-mercury-v1",
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--graph") out.graph = argv[++i];
    else if (arg === "--out-dir") out.outDir = argv[++i];
    else if (arg === "--state-file") out.stateFile = argv[++i];
    else if (arg === "--limit") out.limit = Number(argv[++i]);
    else if (arg === "--start-at") out.startAt = Number(argv[++i]);
    else if (arg === "--concurrency") out.concurrency = Number(argv[++i]);
    else if (arg === "--sample-percent") out.samplePercent = Number(argv[++i]);
    else if (arg === "--sample-size") out.sampleSize = Number(argv[++i]);
    else if (arg === "--min-per-type") out.minPerType = Number(argv[++i]);
    else if (arg === "--seed") out.seed = String(argv[++i]);
    else if (arg === "--resume") out.resume = true;
    else if (arg === "--full") out.full = true;
    else if (arg === "--heuristic-only") out.heuristicOnly = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }

  for (const [name, value] of [["limit", out.limit], ["start-at", out.startAt], ["sample-size", out.sampleSize], ["min-per-type", out.minPerType]]) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number`);
  }
  if (!Number.isFinite(out.samplePercent) || out.samplePercent < 0 || out.samplePercent > 100) throw new Error("sample-percent must be between 0 and 100");
  if (!Number.isFinite(out.concurrency) || out.concurrency < 1) throw new Error("concurrency must be at least 1");
  if (!out.seed.trim()) throw new Error("seed must not be empty");

  out.limit = Math.floor(out.limit);
  out.startAt = Math.floor(out.startAt);
  out.sampleSize = Math.floor(out.sampleSize);
  out.minPerType = Math.max(1, Math.floor(out.minPerType));
  out.concurrency = Math.min(24, Math.floor(out.concurrency));
  return out;
}

function loadExisting(file) {
  const map = new Map();
  if (!file || !fs.existsSync(file)) return map;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean)) {
    try {
      const item = JSON.parse(line);
      if (item.entity_id) map.set(String(item.entity_id), item);
    } catch {}
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

function fallback(node, heuristic, reason = "heuristic-only") {
  const wrongQa = heuristic.issues.includes("incorrect_qa_classification");
  return normalizeAudit({
    detected_content_type: wrongQa ? "source_code" : heuristic.qaTyped ? "qa" : heuristic.codeLike ? "code_snippet" : "unknown",
    current_type_valid: !wrongQa,
    language: heuristic.language,
    suggested_title: wrongQa ? fallbackTitle(node) : null,
    summary: String(node.summary ?? node.description ?? ""),
    tags: Array.isArray(node.tags) ? node.tags : [],
    mitre_candidates: [],
    entities: [],
    relation_candidates: [],
    quality_issues: heuristic.issues.length ? heuristic.issues : ["none"],
    recommended_renderer: heuristic.codeLike ? "code" : heuristic.qaTyped ? "qa" : "markdown",
    safe_fixes: {
      remove_qa_prefix: wrongQa,
      extract_technical_answer: wrongQa,
      set_content_format: heuristic.codeLike ? "code" : "markdown",
      replace_summary: false,
      reclassify_node: wrongQa,
    },
    confidence: wrongQa ? 0.82 : 0.5,
    needs_review: true,
    rationale: reason,
  }, node, heuristic);
}

async function callMercury(messages, requestId) {
  const key = process.env.INCEPTION_API_KEY;
  if (!key) throw new Error("INCEPTION_API_KEY is required unless --heuristic-only is used");

  const body = {
    model: MODEL,
    reasoning_effort: EFFORT,
    messages,
    response_format: { type: "json_schema", json_schema: auditJsonSchema },
    max_tokens: 1800,
    stream: false,
  };

  let lastError;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
          "X-Request-Id": requestId,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(150000),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`Mercury HTTP ${response.status}: ${text.slice(0, 500)}`);
      const payload = JSON.parse(text);
      const content = payload?.choices?.[0]?.message?.content;
      return typeof content === "string" ? JSON.parse(content) : content;
    } catch (error) {
      lastError = error;
      if (attempt < 5) await new Promise((resolve) => setTimeout(resolve, 750 * 2 ** (attempt - 1)));
    }
  }
  throw lastError;
}

function summarize(results) {
  const byType = {};
  const byIssue = {};
  let review = 0;
  let reclassify = 0;
  let incorrectQa = 0;
  let semanticClaims = 0;

  for (const item of results) {
    byType[item.detected_content_type] = (byType[item.detected_content_type] ?? 0) + 1;
    for (const issue of item.quality_issues ?? []) byIssue[issue] = (byIssue[issue] ?? 0) + 1;
    if (requiresReview(item)) review += 1;
    if (item.safe_fixes?.reclassify_node) reclassify += 1;
    if (item.quality_issues?.includes("incorrect_qa_classification")) incorrectQa += 1;
    if ((item.semantic_claim_flags ?? []).length > 0) semanticClaims += 1;
  }

  return {
    total: results.length,
    needs_review: review,
    reclassification_candidates: reclassify,
    incorrect_qa_candidates: incorrectQa,
    semantic_claim_candidates: semanticClaims,
    by_detected_type: Object.fromEntries(Object.entries(byType).sort((a, b) => b[1] - a[1])),
    by_quality_issue: Object.fromEntries(Object.entries(byIssue).sort((a, b) => b[1] - a[1])),
  };
}

function cleanupPlan(results) {
  const safeFixes = [];
  const semanticClaims = [];
  for (const item of results) {
    const flags = item.semantic_claim_flags ?? [];
    if (flags.length > 0) {
      semanticClaims.push({ entity_id: item.entity_id, flags, summary: item.summary, confidence: item.confidence });
    }

    const actions = Object.entries(item.safe_fixes ?? {})
      .filter(([key, value]) => key === "set_content_format" ? Boolean(value) : value === true)
      .map(([key, value]) => ({ action: key, value }));
    if (actions.length > 0) {
      safeFixes.push({
        entity_id: item.entity_id,
        confidence: item.confidence,
        ready_for_apply: item.confidence >= 0.9 && flags.length === 0 && !requiresReview({ ...item, quality_issues: ["none"], needs_review: false }),
        actions,
        issues: item.quality_issues,
        rationale: item.rationale,
      });
    }
  }

  return {
    generated_at: new Date().toISOString(),
    policy: "proposal-only; no graph mutation",
    safe_fix_candidates: safeFixes,
    semantic_claim_review: semanticClaims,
  };
}

function writeReports(dir, {
  runResults,
  cumulativeResults,
  processedIndex,
  samplePlan,
  meta,
}) {
  const runSummary = summarize(runResults);
  const cumulativeSummary = summarize(cumulativeResults);
  const coveragePercent = meta.graph_total > 0 ? Number((100 * cumulativeResults.length / meta.graph_total).toFixed(2)) : 0;
  const summary = {
    generated_at: new Date().toISOString(),
    ...runSummary,
    graph: meta.graph,
    model: meta.model,
    reasoning_effort: meta.reasoning_effort,
    mode: meta.mode,
    success: meta.success,
    failed: meta.failed,
    skipped_unchanged: meta.skipped_unchanged,
    graph_total: meta.graph_total,
    cumulative_current: cumulativeResults.length,
    cumulative_stale: processedIndex.filter((item) => !item.current).length,
    remaining_current: Math.max(0, meta.graph_total - cumulativeResults.length),
    coverage_percent: coveragePercent,
    cumulative: cumulativeSummary,
  };

  fs.writeFileSync(path.join(dir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "sample-plan.json"), `${JSON.stringify(samplePlan, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "processed-index.json"), `${JSON.stringify(processedIndex, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "run-audit.jsonl"), runResults.length ? `${runResults.map((item) => JSON.stringify(item)).join("\n")}\n` : "");

  const review = runResults.filter(requiresReview).sort((a, b) => b.confidence - a.confidence);
  fs.writeFileSync(path.join(dir, "review-queue.json"), `${JSON.stringify(review, null, 2)}\n`);

  const candidates = {
    generated_at: new Date().toISOString(),
    mitre: runResults.flatMap((item) => (item.mitre_candidates ?? []).map((candidate) => ({ entity_id: item.entity_id, ...candidate }))),
    relations: runResults.flatMap((item) => (item.relation_candidates ?? []).map((candidate) => ({ entity_id: item.entity_id, ...candidate }))),
    reclassifications: runResults
      .filter((item) => item.safe_fixes?.reclassify_node)
      .map((item) => ({ entity_id: item.entity_id, from: item.current_content_type, to: item.detected_content_type, language: item.language, confidence: item.confidence, evidence: item.rationale })),
  };
  fs.writeFileSync(path.join(dir, "candidates.json"), `${JSON.stringify(candidates, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "cleanup-plan.json"), `${JSON.stringify(cleanupPlan(runResults), null, 2)}\n`);

  const strataRows = Object.entries(samplePlan.strata ?? {})
    .map(([type, values]) => `| ${type} | ${values.population} | ${values.selected} |`)
    .join("\n");
  fs.writeFileSync(path.join(dir, "REPORT.md"), `# Mercury graph audit\n\n- Mode: **${summary.mode}**\n- Nodes audited in this run: **${summary.total}**\n- Successful Mercury responses: **${summary.success}**\n- Mercury failures: **${summary.failed}**\n- Current processed coverage: **${summary.cumulative_current}/${summary.graph_total} (${summary.coverage_percent}%)**\n- Remaining current nodes: **${summary.remaining_current}**\n- Needs review in this run: **${summary.needs_review}**\n- Incorrect QA candidates: **${summary.incorrect_qa_candidates}**\n- Reclassification candidates: **${summary.reclassification_candidates}**\n- Semantic claim candidates: **${summary.semantic_claim_candidates}**\n- Model: \`${summary.model}\`\n\n## Stratified selection\n\n| Type | Eligible population | Selected |\n|---|---:|---:|\n${strataRows || "| none | 0 | 0 |"}\n\nThe workflow is proposal-only. Review \`review-queue.json\`, \`cleanup-plan.json\`, and \`candidates.json\` before applying graph changes.\n`);
}

function buildFullPlan(entries, seed, mode) {
  const strata = {};
  for (const entry of entries) {
    const type = nodeStratum(entry.node);
    if (!strata[type]) strata[type] = { population: 0, selected: 0 };
    strata[type].population += 1;
    strata[type].selected += 1;
  }
  return { seed, mode, eligible: entries.length, target: entries.length, strata };
}

async function main() {
  const options = args(process.argv.slice(2));
  const graphPath = path.resolve(options.graph);
  const outDir = path.resolve(options.outDir);
  const outputState = path.join(outDir, "audit.jsonl");
  const inputState = options.stateFile ? path.resolve(options.stateFile) : outputState;
  fs.mkdirSync(outDir, { recursive: true });

  const graph = JSON.parse(fs.readFileSync(graphPath, "utf8"));
  const allEntries = (graph.nodes ?? []).map((node) => prepareNode(graph, node));
  const entryById = new Map(allEntries.map((entry) => [String(entry.node.id), entry]));
  const existing = options.resume ? loadExisting(inputState) : new Map();

  for (const [entityId, item] of existing.entries()) {
    const entry = entryById.get(String(entityId));
    if (entry && entry.sourceHash === item.source_hash) {
      existing.set(String(entityId), reconcileAudit(item, entry.node, entry.content));
    }
  }

  const samplingRequested = options.full || options.samplePercent > 0 || options.sampleSize > 0;
  const legacyPool = samplingRequested
    ? allEntries
    : allEntries.slice(options.startAt, options.limit > 0 ? options.startAt + options.limit : undefined);
  const eligible = legacyPool.filter((entry) => existing.get(String(entry.node.id))?.source_hash !== entry.sourceHash);
  const skippedUnchanged = legacyPool.length - eligible.length;

  let selected;
  let samplePlan;
  let mode;
  if (options.full) {
    selected = eligible;
    mode = "full-resume";
    samplePlan = buildFullPlan(selected, options.seed, mode);
  } else if (options.samplePercent > 0 || options.sampleSize > 0) {
    const sampled = stratifiedSample(eligible, {
      samplePercent: options.samplePercent,
      sampleSize: options.sampleSize,
      minPerType: options.minPerType,
      seed: options.seed,
    });
    selected = sampled.selected;
    mode = "stratified-sample";
    samplePlan = { ...sampled.plan, mode };
  } else {
    selected = eligible;
    mode = "legacy-sequential";
    samplePlan = buildFullPlan(selected, options.seed, mode);
  }

  samplePlan = {
    ...samplePlan,
    graph_total: allEntries.length,
    previously_current: allEntries.filter((entry) => existing.get(String(entry.node.id))?.source_hash === entry.sourceHash).length,
    skipped_unchanged: skippedUnchanged,
    selected_ids: selected.map((entry) => String(entry.node.id)),
  };

  let cursor = 0;
  let success = 0;
  let failed = 0;
  const runResults = [];

  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= selected.length) return;
      const { node, content, heuristic } = selected[index];
      try {
        const raw = options.heuristicOnly
          ? null
          : await callMercury(buildMessages(node, content, heuristic), crypto.randomUUID());
        const normalized = options.heuristicOnly ? fallback(node, heuristic) : normalizeAudit(raw, node, heuristic);
        const audit = reconcileAudit(normalized, node, content);
        existing.set(String(node.id), audit);
        runResults.push(audit);
        success += 1;
      } catch (error) {
        const audit = reconcileAudit(fallback(node, heuristic, `Mercury failed: ${error.message}`), node, content);
        runResults.push(audit);
        failed += 1;
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(options.concurrency, Math.max(1, selected.length)) }, worker));

  const cumulative = [...existing.values()].sort((a, b) => String(a.entity_id).localeCompare(String(b.entity_id)));
  fs.writeFileSync(outputState, cumulative.length ? `${cumulative.map((item) => JSON.stringify(item)).join("\n")}\n` : "");

  const processedIndex = buildProcessedIndex(allEntries, existing);
  const cumulativeCurrent = processedIndex
    .filter((record) => record.current)
    .map((record) => existing.get(record.entity_id))
    .filter(Boolean);

  runResults.sort((a, b) => String(a.entity_id).localeCompare(String(b.entity_id)));
  writeReports(outDir, {
    runResults,
    cumulativeResults: cumulativeCurrent,
    processedIndex,
    samplePlan,
    meta: {
      graph: options.graph,
      graph_total: allEntries.length,
      model: options.heuristicOnly ? "heuristic-only" : MODEL,
      reasoning_effort: options.heuristicOnly ? null : EFFORT,
      mode,
      success,
      failed,
      skipped_unchanged: skippedUnchanged,
    },
  });

  console.log(`Audit complete: ${runResults.length} newly audited; ${cumulativeCurrent.length}/${allEntries.length} current nodes persisted; ${failed} Mercury failures; artifact=${outDir}`);

  if (!options.heuristicOnly && selected.length > 0 && success === 0) {
    throw new Error(`Mercury failed for all ${failed} selected entities; inspect the uploaded artifact for HTTP/API errors`);
  }
}

main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exit(1);
});
