import assert from "node:assert/strict";
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
console.log("Mercury audit helper tests passed.");
