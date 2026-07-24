#!/usr/bin/env node
/**
 * ingest.mjs — Universal JSONL ingestor for HUGIN
 *
 * Accepts ANY .jsonl file regardless of schema. Uses Qwen3.5-2B-ONNX via
 * @huggingface/transformers to:
 *   1. Map raw records to the canonical {prompt, answer, task, tags, mitre} schema
 *   2. Generate a 2-sentence technical summary
 *   3. Extract MITRE ATT&CK technique IDs from the content
 *
 * Then injects the results into data/source/public-graph.json as tradecraft_qa nodes.
 *
 * Usage:
 *   node scripts/ingest.mjs <input.jsonl> [--dry-run] [--limit=N] [--no-model]
 *
 * Flags:
 *   --dry-run     Print what would be written, don't modify the graph
 *   --limit=N     Process only the first N records (useful for testing)
 *   --no-model    Skip LLM enrichment, use heuristic extraction only (fast)
 *
 * Environment:
 *   HUGIN_MODEL_CACHE   Path to HuggingFace model cache (default: .hf-cache)
 *   HUGIN_INGEST_MODEL  HF model ID override (default: onnx-community/Qwen3.5-2B-ONNX-OPT)
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ── CLI args ──────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const positional = argv.filter((a) => !a.startsWith("--"));
const flags = new Set(argv.filter((a) => a.startsWith("--")));

const DRY_RUN  = flags.has("--dry-run");
const NO_MODEL = flags.has("--no-model");
const LIMIT    = (() => {
  const f = argv.find((a) => a.startsWith("--limit="));
  return f ? Number.parseInt(f.split("=")[1], 10) : Infinity;
})();

const INPUT_PATH = path.resolve(positional[0] ?? "hugin/samples_normalized.jsonl");
if (!fs.existsSync(INPUT_PATH)) {
  console.error(`Input not found: ${INPUT_PATH}`);
  process.exit(1);
}

const GRAPH_PATH  = path.resolve("data/source/public-graph.json");
const GALAXY_ID   = "tradecraft_qa";
const MODEL_ID    = process.env.HUGIN_INGEST_MODEL ?? "onnx-community/Qwen3.5-2B-ONNX-OPT";
const MODEL_CACHE = process.env.HUGIN_MODEL_CACHE  ?? ".hf-cache";
const MODEL_DTYPE = "q4"; // fits in ~2.5GB RAM, fast on CPU

// ── Helpers ───────────────────────────────────────────────────────────────────
const sha256    = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
const shortHash = (v, n = 16) => sha256(v).slice(0, n);

function truncate(value, len = 300) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (text.length <= len) return text;
  return `${text.slice(0, len).replace(/\s+\S*$/, "")}…`;
}

// ── Sanitization (inline, no dep on sanitize.mjs for portability) ─────────────
const SANITIZE_RULES = [
  [/https?:\/\/\S*(?:offsec\.com|offensive-security\.com|maldevacademy\.com|sans\.org)\S*/gi, "[private-url]"],
  [/\bAKI[A-Z0-9]{16,}\b/g, "[aws-key-id]"],
  [/\b(?:OSED|OSEP|OSCP|OSWA|OSWP|PEN-200|PEN200|EXP-312|WEB-200|WEB200)\b/gi, "Source A"],
  [/\bSANS[- ]?SEC\d{3}\b/gi, "Source B"],
  [/\bCRTO\d?\b|\bCRTE\b/gi, "Source B"],
  [/maldev[a-z0-9_-]*/gi, "Source B"],
  [/\bOffensive\s+Security\b/gi, "Source C"],
  [/(?:fake)?offensive-security\.(?:com|net|org)/gi, "[private-domain]"],
  [/offsec[a-z0-9_-]*/gi, "Source C"],
  [/\b(?:emiperalta|tamarisk)\b/gi, "operator"],
  [/\bOWN_NOTES\b/gi, "curated-notes"],
];
function sanitize(value) {
  if (typeof value !== "string") return value;
  let s = value;
  for (const [p, r] of SANITIZE_RULES) s = s.replace(p, r);
  return s.replace(/[ \t]{2,}/g, " ").trim();
}

// ── MITRE heuristic extractor (always runs, model augments it) ────────────────
function extractMitreHeuristic(text) {
  const matches = String(text).match(/\bT\d{4}(?:\.\d{3})?\b/g);
  return [...new Set(matches ?? [])].slice(0, 10);
}

// ── Task classifier (heuristic) ───────────────────────────────────────────────
const TASK_KEYWORDS = {
  exploit_dev:      /exploit|rop|shellcode|overflow|heap|seh|dep|aslr|gadget|payload/i,
  evasion:          /evas|bypass|amsi|etw|hook|obfuscat|sandbox|av|edr|antivirus/i,
  web_exploit:      /xss|sqli|csrf|ssrf|idor|lfi|rfi|web|http|cors|jwt|token/i,
  lateral_movement: /lateral|pivot|dcsync|kerberos|pass.?the|ad|ldap|smb|wmi|rdp/i,
  post_exploitation:/mimikatz|lsass|credential|dump|hashdump|meterpreter|beacon/i,
  persistence:      /persist|registry|autorun|cron|scheduled.task|startup|backdoor/i,
  reversing:        /revers|disassembl|ida|ghidra|radare|binary|decompil/i,
  malware_analysis: /malware|sample|dyndns|c2|command.control|dropper|loader/i,
};
function classifyTask(text) {
  for (const [task, re] of Object.entries(TASK_KEYWORDS)) {
    if (re.test(text)) return task;
  }
  return "research";
}

// ── Schema detector: figure out what fields the record has ───────────────────
function detectSchema(record) {
  // Format A: {messages[], meta{}} — RFT benchmark traces
  if (record.messages && Array.isArray(record.messages) && record.meta) return "rft";
  // Format B: {prompt, answer} — SFT / gateway verifier
  if (record.prompt && record.answer && !record.input && !record.scenario) return "sft";
  // Format C: {input/scenario, answer, task_type} — v5 / augmented / legacy
  if ((record.input || record.scenario) && record.answer) return "v5";
  // Format D: {messages[]} without meta — chat format
  if (record.messages && Array.isArray(record.messages)) return "chat";
  // Format E: completely unknown — hand to model
  return "unknown";
}

// ── Heuristic extraction (no model) ──────────────────────────────────────────
function extractHeuristic(record) {
  const schema = detectSchema(record);
  let prompt = "", answer = "", conversation = null;

  if (schema === "rft") {
    const msgs = record.messages ?? [];
    prompt = msgs.find((m) => m.role === "user")?.content ?? "";
    answer = msgs.find((m) => m.role === "assistant")?.content ?? "";
  } else if (schema === "sft") {
    // Try to parse JSON answer (verifier format)
    let parsedAnswer = record.answer;
    try {
      const j = JSON.parse(record.answer);
      parsedAnswer = [j.reasoning, j.near_miss_avoided].filter(Boolean).join("\n\n") || record.answer;
    } catch { /* not JSON */ }
    prompt = record.prompt;
    answer = parsedAnswer;
  } else if (schema === "v5") {
    prompt = record.input ?? record.scenario ?? "";
    answer = record.answer ?? "";
    const raw = record.conversation ?? record.turns ?? null;
    if (Array.isArray(raw) && raw.length > 0) {
      conversation = raw.map((t) => ({
        role: t.role === "operator" ? "user" : (t.role ?? "user"),
        content: sanitize(t.content ?? ""),
      }));
    }
  } else if (schema === "chat") {
    const msgs = record.messages ?? [];
    const userMsgs = msgs.filter((m) => m.role === "user");
    const asstMsgs = msgs.filter((m) => m.role === "assistant");
    prompt  = userMsgs.map((m) => m.content).join("\n\n");
    answer  = asstMsgs.map((m) => m.content).join("\n\n");
  } else {
    // Unknown: grab anything that looks like content
    const contentFields = ["content", "text", "body", "response", "completion", "output"];
    const questionFields = ["question", "query", "input", "instruction", "scenario", "context"];
    prompt = String(record[questionFields.find((k) => record[k])] ?? record.prompt ?? "");
    answer = String(record[contentFields.find((k) => record[k])] ?? record.answer ?? "");
  }

  const rawText = `${prompt} ${answer}`;
  const existingTags = [
    ...(record.tags ?? []),
    ...(record._primary_topic ? [record._primary_topic] : []),
    ...(record.task_type ? [record.task_type] : []),
  ].map(sanitize).filter(Boolean);

  return {
    schema,
    prompt:  sanitize(prompt),
    answer:  sanitize(answer),
    conversation,
    task:    record.task_type ?? record._adapter_target ?? classifyTask(rawText),
    tags:    existingTags,
    mitre:   extractMitreHeuristic(rawText),
    summary: truncate(sanitize(answer), 240),
    near_miss: (record.near_miss ?? []).map((nm) => {
      if (typeof nm === "string") return sanitize(nm);
      return sanitize((nm.rejected_answer ?? nm.value ?? "") + (nm.failure_mode ? ` — ${nm.failure_mode}` : ""));
    }).filter(Boolean),
    cert_origin: record.cert_origin ?? null,
    difficulty:  record.difficulty ?? null,
  };
}

// ── Model enrichment ─────────────────────────────────────────────────────────
let generator = null;
async function loadModel() {
  if (generator) return;
  console.log(`\nLoading generation model: ${MODEL_ID} (dtype=${MODEL_DTYPE})`);
  console.log("This downloads ~1.5GB on first run, then caches in", MODEL_CACHE);
  const { pipeline, env } = await import("@huggingface/transformers");
  env.cacheDir = MODEL_CACHE;
  generator = await pipeline("text-generation", MODEL_ID, {
    dtype: MODEL_DTYPE,
    device: "cpu",
  });
  console.log("Model loaded.\n");
}

async function enrichWithModel(extracted) {
  const { prompt, answer, task } = extracted;
  const rawText = `${prompt}\n\n${answer}`.slice(0, 2000); // cap to avoid OOM

  const systemPrompt = `You are a cybersecurity knowledge base assistant. Given a technical Q&A record, output a JSON object with:
- "summary": 2-sentence technical summary (plain text, no markdown, max 200 chars)
- "mitre": array of MITRE ATT&CK technique IDs found in the text (e.g. ["T1055", "T1134.001"]), empty array if none
- "tags": array of 3-6 lowercase technical keyword tags (e.g. ["shellcode", "dep-bypass", "rop"])
- "task": one of: exploit_dev | evasion | web_exploit | lateral_movement | post_exploitation | persistence | reversing | malware_analysis | research

Output ONLY the JSON object, no explanation, no markdown fences.`;

  const userMessage = `Technical Q&A:\n\nSCENARIO: ${prompt.slice(0, 600)}\n\nANSWER: ${answer.slice(0, 800)}`;

  const messages = [
    { role: "system", content: systemPrompt },
    { role: "user",   content: userMessage },
  ];

  try {
    const result = await generator(messages, {
      max_new_tokens: 200,
      temperature: 0.1,
      do_sample: false,
    });
    const raw = result[0]?.generated_text;
    // The model returns the full messages array; extract the last assistant reply
    const lastMsg = Array.isArray(raw)
      ? raw.find((m) => m.role === "assistant")?.content ?? ""
      : String(raw ?? "");

    // Extract JSON from the response
    const jsonMatch = lastMsg.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON in model output");
    const parsed = JSON.parse(jsonMatch[0]);

    return {
      ...extracted,
      summary: sanitize(truncate(parsed.summary ?? extracted.summary, 240)),
      mitre:   [...new Set([...extracted.mitre, ...(parsed.mitre ?? []).filter((t) => /^T\d{4}/.test(t))])].slice(0, 12),
      tags:    [...new Set([...extracted.tags, ...(parsed.tags ?? []).map(sanitize)])].slice(0, 16),
      task:    parsed.task ?? extracted.task,
    };
  } catch (err) {
    // Model failed → keep heuristic extraction silently
    return extracted;
  }
}

// ── Markdown body builder ─────────────────────────────────────────────────────
function buildBody(rec) {
  const conv = rec.conversation;
  const convSection = conv && conv.length > 0
    ? `\n\n## 💬 Multi-Turn Dialogue\n\n${conv.map((t) =>
        `**${t.role === "user" ? "Operator" : "Assistant"}:** ${t.content}`
      ).join("\n\n")}`
    : "";

  const nearMissSection = rec.near_miss?.length > 0
    ? `\n\n## ⚠️ Failure Modes & Alternatives\n\n${rec.near_miss.map((nm) => `- ${nm}`).join("\n")}`
    : "";

  const mitreSection = rec.mitre?.length > 0
    ? `\n\n## 📑 MITRE ATT&CK Coverage\n\n${rec.mitre.map((t) => `- \`${t}\``).join("\n")}`
    : "";

  const metaParts = [
    rec.task    && `**Task domain:** \`${rec.task}\``,
    rec.cert_origin && `**Source category:** ${rec.cert_origin}`,
    rec.difficulty != null && `**Difficulty:** ${rec.difficulty}`,
  ].filter(Boolean).join("  ·  ");

  return `## 🎯 Research Context & Scenario

${rec.prompt}

---

## 🔬 Full Technical Analysis

${rec.answer}${convSection}${nearMissSection}${mitreSection}

---

*${metaParts}*`.trim();
}

// ── Node builder ──────────────────────────────────────────────────────────────
function subgalaxyFor(task) {
  const map = {
    exploit_dev:      "Exploit Development",
    evasion:          "Evasion & Defense Bypass",
    web_exploit:      "Web Exploitation",
    lateral_movement: "Lateral Movement",
    post_exploitation:"Post-Exploitation",
    persistence:      "Persistence Mechanisms",
    reversing:        "Reverse Engineering",
    malware_analysis: "Malware Analysis",
  };
  return map[task] ?? "Tradecraft Research";
}

function buildNode(rec, rawId) {
  const publicId  = `tradecraft_qa:${shortHash(rawId, 20)}`;
  const evidenceId = `QA-${shortHash(rawId, 10).toUpperCase()}`;
  const promptSnip = truncate(rec.prompt, 90);
  const title = `QA · ${subgalaxyFor(rec.task)} · ${promptSnip}`;
  const tags  = [...new Set([rec.task, ...rec.tags])].map(sanitize).slice(0, 16);

  return {
    node: {
      id: publicId,
      type: "tradecraft_qa",
      publishState: "core",
      evidenceId,
      sourceClass: "operator-tradecraft-note",
      sourceHash:  shortHash(rawId, 16),
      label:       title,
      name:        title,
      summary:     rec.summary,
      description: rec.summary,
      category:    subgalaxyFor(rec.task),
      topic:       rec.task,
      tags,
      mitre:       rec.mitre,
      galaxyId:    GALAXY_ID,
      qa_task:     rec.task,
      qa_record_id: sanitize(rawId),
    },
    body: buildBody(rec),
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`\nHUGIN Universal Ingestor`);
  console.log(`  Input : ${INPUT_PATH}`);
  console.log(`  Model : ${NO_MODEL ? "disabled (--no-model)" : MODEL_ID}`);
  console.log(`  Limit : ${LIMIT === Infinity ? "none" : LIMIT}`);
  console.log(`  Mode  : ${DRY_RUN ? "DRY RUN" : "WRITE"}\n`);

  // Load graph
  if (!fs.existsSync(GRAPH_PATH)) {
    console.error(`Graph not found: ${GRAPH_PATH}`);
    process.exit(1);
  }
  const graph = JSON.parse(fs.readFileSync(GRAPH_PATH, "utf8"));
  const existingIds = new Set((graph.nodes ?? []).map((n) => String(n.id)));

  // Parse JSONL
  const lines = fs.readFileSync(INPUT_PATH, "utf8").split("\n").filter(Boolean);
  console.log(`Parsing ${lines.length} lines…`);

  const records = lines.slice(0, LIMIT).flatMap((line, i) => {
    try { return [JSON.parse(line)]; }
    catch { console.warn(`  Line ${i + 1}: parse error, skipping`); return []; }
  });
  console.log(`Valid records: ${records.length}`);

  // Load model if needed
  if (!NO_MODEL) await loadModel();

  // Process
  const newNodes    = [];
  const newContents = {};
  let   skipped     = 0;
  let   enriched    = 0;

  console.log(`\nProcessing…`);
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const rawId  = record.id ?? sha256(`${i}:${JSON.stringify(record)}`).slice(0, 40);
    const publicId = `tradecraft_qa:${shortHash(rawId, 20)}`;

    if (existingIds.has(publicId)) { skipped++; continue; }

    // 1. Heuristic extraction (always)
    let extracted = extractHeuristic(record);

    // Skip records with no meaningful content
    if (!extracted.prompt && !extracted.answer) { skipped++; continue; }

    // 2. Model enrichment (optional)
    if (!NO_MODEL && generator) {
      extracted = await enrichWithModel(extracted);
      enriched++;
    }

    // 3. Build graph node
    const { node, body } = buildNode(extracted, rawId);
    newNodes.push(node);
    newContents[node.id] = body;
    existingIds.add(node.id);

    // Progress every 100
    if ((i + 1) % 100 === 0 || i === records.length - 1) {
      process.stdout.write(`\r  ${i + 1}/${records.length} processed — ${newNodes.length} new, ${skipped} skipped   `);
    }
  }

  console.log(`\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(` Input records : ${records.length}`);
  console.log(` New nodes     : ${newNodes.length}`);
  console.log(` Skipped       : ${skipped}`);
  console.log(` Model enriched: ${enriched}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  if (DRY_RUN) {
    console.log("DRY RUN — sample node:");
    console.log(JSON.stringify(newNodes[0], null, 2));
    return;
  }

  if (newNodes.length === 0) {
    console.log("Nothing new to import.");
    return;
  }

  // Merge into graph
  graph.nodes    = [...(graph.nodes ?? []), ...newNodes];
  graph.contents = { ...(graph.contents ?? {}), ...newContents };

  const coreCount        = graph.nodes.filter((n) => n.publishState === "core").length;
  const supportCount     = graph.nodes.filter((n) => n.publishState === "support").length;
  const evidenceCount    = graph.nodes.filter((n) => n.publishState === "evidence").length;
  const quarantinedCount = graph.nodes.filter((n) => n.publishState === "quarantined").length;

  graph.quality = {
    ...(graph.quality || {}),
    states: {
      core: coreCount,
      support: supportCount,
      evidence: evidenceCount,
      quarantined: quarantinedCount,
    },
  };

  graph.rawCounts = {
    nodes:     graph.nodes.length,
    relations: (graph.edges ?? []).length,
  };

  fs.writeFileSync(GRAPH_PATH, `${JSON.stringify(graph)}\n`);
  console.log(`✅ ${newNodes.length} nodes written to ${GRAPH_PATH}`);
  console.log(`   Total nodes: ${graph.nodes.length}`);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
