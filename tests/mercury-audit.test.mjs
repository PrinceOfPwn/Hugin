import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { detectLanguage, extractQaSections, inspectHeuristically, looksLikeCode, normalizeAudit } from "../scripts/lib/mercury-audit.mjs";

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

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-mercury-test-"));
try {
  const graphPath = path.join(tempDir, "graph.json");
  const outDir = path.join(tempDir, "audit");
  const graph = { nodes: [node], contents: { [node.id]: wrapped } };
  fs.writeFileSync(graphPath, JSON.stringify(graph));

  const run = (...extraArgs) => spawnSync(process.execPath, [
    "scripts/mercury-audit-graph.mjs",
    "--graph", graphPath,
    "--out-dir", outDir,
    "--heuristic-only",
    ...extraArgs,
  ], { cwd: process.cwd(), encoding: "utf8" });

  const first = run();
  assert.equal(first.status, 0, first.stderr);
  const firstAudit = JSON.parse(fs.readFileSync(path.join(outDir, "audit.jsonl"), "utf8").trim());
  assert.equal(firstAudit.detected_content_type, "source_code");
  assert.equal(firstAudit.suggested_title, "syscalls.asm");

  const unchanged = run("--resume");
  assert.equal(unchanged.status, 0, unchanged.stderr);
  const unchangedSummary = JSON.parse(fs.readFileSync(path.join(outDir, "summary.json"), "utf8"));
  assert.equal(unchangedSummary.skipped_unchanged, 1);

  graph.contents[node.id] = wrapped.replace("mov eax, g_NtAllocateVirtualMemorySSN", "mov eax, 18h");
  fs.writeFileSync(graphPath, JSON.stringify(graph));
  const changed = run("--resume");
  assert.equal(changed.status, 0, changed.stderr);
  const changedLines = fs.readFileSync(path.join(outDir, "audit.jsonl"), "utf8").trim().split(/\r?\n/);
  assert.equal(changedLines.length, 1);
  const changedAudit = JSON.parse(changedLines[0]);
  assert.notEqual(changedAudit.source_hash, firstAudit.source_hash);
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log("Mercury audit helper tests passed.");
