import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { detectLanguage, extractQaSections, inspectHeuristically, looksLikeCode, normalizeAudit } from "../scripts/lib/mercury-audit.mjs";
import { reconcileAudit, requiresReview, sameTypeFamily, stratifiedSample } from "../scripts/lib/mercury-sampling.mjs";

const assembly = `EXTRN g_NtAllocateVirtualMemorySSN:DWORD
.code
NtAllocateVirtualMemory proc
  mov r10, rcx
  mov eax, g_NtAllocateVirtualMemorySSN
  syscall
  ret
NtAllocateVirtualMemory endp`;

assert.equal(looksLikeCode(assembly), true);
assert.equal(detectLanguage({ label: "syscalls.asm" }, assembly), "x86_64_assembly");
assert.equal(detectLanguage({ label: "exploit.poc.py" }, ""), "python");
assert.equal(sameTypeFamily("tradecraft_qa", "qa"), true);
assert.equal(sameTypeFamily("technique", "technical_note"), false);

const wrapped = `## 🎯 Research Context & Scenario\n\nsyscalls.asm\n\n---\n\n## 🔬 Full Technical Analysis\n\n${assembly}\n\n---`;
assert.equal(extractQaSections(wrapped).scenario, "syscalls.asm");

const node = { id: "qa:1", type: "tradecraft_qa", galaxyId: "tradecraft_qa", label: "QA · Exploit Development · syscalls.asm", tags: [] };
const heuristic = inspectHeuristically(node, wrapped);
assert.equal(heuristic.codeLike, true);
assert.equal(heuristic.filenamePrompt, true);
assert.ok(heuristic.issues.includes("incorrect_qa_classification"));

const normalized = normalizeAudit({
  detected_content_type: "source_code", current_type_valid: false, language: "x86_64_assembly",
  suggested_title: "Windows Native API syscall wrappers", summary: "Assembly wrappers around Windows Native API calls.",
  tags: ["Assembly", "windows native api", "assembly"],
  mitre_candidates: [{ id: "T1106", confidence: 0.9, evidence: "Native API calls are explicit." }],
  entities: [{ name: "NtAllocateVirtualMemory", type: "api" }],
  relation_candidates: [{ target_hint: "Windows Native API", relation: "uses", confidence: 0.9, evidence: "Explicit Nt APIs." }],
  quality_issues: ["incorrect_qa_classification"], recommended_renderer: "code",
  safe_fixes: { remove_qa_prefix: true, extract_technical_answer: true, set_content_format: "code", replace_summary: true, reclassify_node: true },
  confidence: 0.94, needs_review: false, rationale: "The scenario is a filename and the answer is assembly.",
}, node, heuristic);
assert.deepEqual(normalized.tags, ["assembly", "windows-native-api"]);
assert.equal(normalized.safe_fixes.reclassify_node, true);

const reconciledQa = reconcileAudit(normalized, node, wrapped);
assert.equal(reconciledQa.safe_fixes.reclassify_node, true);
assert.equal(requiresReview(reconciledQa), true);

const techniqueNode = { id: "T-001", type: "technique", label: "Technique", tags: ["one", "two"] };
const techniqueContent = "## Summary\nA grounded summary already exists.\n\n## Technical Deep Dive\nDetails.";
const techniqueHeuristic = inspectHeuristically(techniqueNode, techniqueContent);
assert.ok(techniqueHeuristic.issues.includes("missing_summary"));
const noOp = reconcileAudit(normalizeAudit({
  detected_content_type: "technique", current_type_valid: true, language: null,
  suggested_title: null, summary: "A grounded summary already exists.", tags: ["one", "two"],
  mitre_candidates: [], entities: [], relation_candidates: [], quality_issues: ["missing_summary"],
  recommended_renderer: "markdown",
  safe_fixes: { remove_qa_prefix: false, extract_technical_answer: false, set_content_format: "markdown", replace_summary: false, reclassify_node: true },
  confidence: 0.91, needs_review: false, rationale: "Type is already valid.",
}, techniqueNode, techniqueHeuristic), techniqueNode, techniqueContent);
assert.deepEqual(noOp.quality_issues, ["none"]);
assert.equal(noOp.safe_fixes.reclassify_node, false);
assert.equal(requiresReview(noOp), false);

const sampleEntries = [
  ...Array.from({ length: 10 }, (_, index) => ({ node: { id: `tech-${index}`, type: "technique" } })),
  ...Array.from({ length: 4 }, (_, index) => ({ node: { id: `qa-${index}`, type: "tradecraft_qa" } })),
  { node: { id: "tool-0", type: "tool" } },
];
const sampleA = stratifiedSample(sampleEntries, { sampleSize: 8, minPerType: 2, seed: "fixed" });
const sampleB = stratifiedSample(sampleEntries, { sampleSize: 8, minPerType: 2, seed: "fixed" });
assert.deepEqual(sampleA.selected.map((entry) => entry.node.id), sampleB.selected.map((entry) => entry.node.id));
assert.equal(sampleA.selected.length, 8);
assert.ok(sampleA.plan.strata.technique.selected >= 2);
assert.ok(sampleA.plan.strata.qa.selected >= 2);
assert.equal(sampleA.plan.strata.tool.selected, 1);

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-mercury-test-"));
try {
  const graphPath = path.join(tempDir, "graph.json");
  const outDir = path.join(tempDir, "audit");
  const graph = {
    nodes: [
      node,
      techniqueNode,
      { id: "qa:2", type: "tradecraft_qa", galaxyId: "tradecraft_qa", label: "QA · Why use Kerberos?", tags: ["kerberos", "authentication"] },
      { id: "tool:1", type: "tool", label: "Tool", tags: ["utility", "windows"] },
    ],
    contents: {
      [node.id]: wrapped,
      [techniqueNode.id]: techniqueContent,
      "qa:2": "## 🎯 Research Context & Scenario\n\nWhy use Kerberos?\n\n---\n\n## 🔬 Full Technical Analysis\n\nKerberos provides ticket-based authentication.\n\n---",
      "tool:1": "## Summary\nA small Windows utility.\n\n## Usage\nRun it locally.",
    },
  };
  fs.writeFileSync(graphPath, JSON.stringify(graph));

  const run = (...extraArgs) => spawnSync(process.execPath, [
    "scripts/mercury-audit-graph.mjs",
    "--graph", graphPath,
    "--out-dir", outDir,
    "--heuristic-only",
    ...extraArgs,
  ], { cwd: process.cwd(), encoding: "utf8" });

  const first = run("--sample-percent", "75", "--min-per-type", "1", "--seed", "integration");
  assert.equal(first.status, 0, first.stderr);
  const firstSummary = JSON.parse(fs.readFileSync(path.join(outDir, "summary.json"), "utf8"));
  const firstPlan = JSON.parse(fs.readFileSync(path.join(outDir, "sample-plan.json"), "utf8"));
  assert.equal(firstSummary.total, 3);
  assert.equal(firstSummary.cumulative_current, 3);
  assert.equal(firstPlan.mode, "stratified-sample");
  assert.equal(Object.values(firstPlan.strata).filter((value) => value.selected > 0).length, 3);

  const unchanged = run("--resume", "--state-file", path.join(outDir, "audit.jsonl"), "--full");
  assert.equal(unchanged.status, 0, unchanged.stderr);
  const unchangedSummary = JSON.parse(fs.readFileSync(path.join(outDir, "summary.json"), "utf8"));
  assert.equal(unchangedSummary.total, 1);
  assert.equal(unchangedSummary.skipped_unchanged, 3);
  assert.equal(unchangedSummary.cumulative_current, 4);

  graph.contents[node.id] = wrapped.replace("mov eax, g_NtAllocateVirtualMemorySSN", "mov eax, 18h");
  fs.writeFileSync(graphPath, JSON.stringify(graph));
  const changed = run("--resume", "--state-file", path.join(outDir, "audit.jsonl"), "--full");
  assert.equal(changed.status, 0, changed.stderr);
  const changedSummary = JSON.parse(fs.readFileSync(path.join(outDir, "summary.json"), "utf8"));
  assert.equal(changedSummary.total, 1);
  assert.equal(changedSummary.cumulative_current, 4);
  const changedLines = fs.readFileSync(path.join(outDir, "audit.jsonl"), "utf8").trim().split(/\r?\n/);
  assert.equal(changedLines.length, 4);
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log("Mercury audit helper tests passed.");
