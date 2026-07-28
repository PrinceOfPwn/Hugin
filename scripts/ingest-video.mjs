#!/usr/bin/env node
// Uploads MP4/MOV/etc. from data/incoming/ to Gemini, extracts structured notes,
// and emits a `video_notes`-shaped JSONL that the existing pipeline picks up
// via the schema-router. Source video is moved to data/incoming/.wrapped/
// after successful extraction (or deleted with --purge-source).
//
// Requires: GEMINI_API_KEY. Silently exits 0 if the key is absent so this
// step can be safely wired into ingest-v2.yml regardless of secret setup.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const argv = process.argv.slice(2);
const dryRun = argv.includes("--dry-run");
const purge = argv.includes("--purge-source");

const MODEL = process.env.HUGIN_GEMINI_VIDEO_MODEL ?? "gemini-3.6-flash";
const API_KEY = process.env.GEMINI_API_KEY;

const INCOMING = path.resolve("data/incoming");
const WRAPPED = path.join(INCOMING, ".wrapped");
const CACHE_DIR = path.resolve(".cache");
const VIDEO_EXT = new Set([".mp4", ".mov", ".mkv", ".webm", ".m4v"]);
const SKIP_DIRS = new Set([".wrapped", "quarantine"]);

if (!fs.existsSync(INCOMING)) {
  console.log("No data/incoming directory — nothing to process.");
  process.exit(0);
}
fs.mkdirSync(WRAPPED, { recursive: true });
fs.mkdirSync(CACHE_DIR, { recursive: true });

function listVideos() {
  return fs.readdirSync(INCOMING, { withFileTypes: true })
    .filter((e) => e.isFile() && !e.name.startsWith("."))
    .filter((e) => VIDEO_EXT.has(path.extname(e.name).toLowerCase()))
    .map((e) => path.join(INCOMING, e.name));
}

const videos = listVideos();
if (videos.length === 0) {
  console.log("No video files under data/incoming — skipping video ingest.");
  process.exit(0);
}

if (!API_KEY) {
  console.warn(`Found ${videos.length} video file(s) but GEMINI_API_KEY is not set — skipping.`);
  process.exit(0);
}

const EXTRACTION_PROMPT = `You are extracting structured research notes from a technical video. Analyze the full audio + visual track and emit ONE JSON object matching exactly this schema (no prose outside the JSON):

{
  "title": "concise title (<= 80 chars)",
  "language": "en" | "es" | "pt" | "other",
  "duration_sec": <integer>,
  "summary": "2-3 sentence executive summary of the whole video",
  "segments": [
    {
      "start_sec": <integer>,
      "end_sec": <integer>,
      "topic": "short label",
      "notes": "detailed technical notes for this segment as markdown",
      "techniques_mentioned": ["name1", "name2"],
      "code_or_commands": ["exact snippets/commands referenced verbatim, if any"],
      "references": ["URLs, tools, papers cited in this segment"]
    }
  ],
  "overall_techniques": ["deduplicated list across all segments"],
  "overall_references": ["deduplicated list across all segments"]
}

Rules:
- Base every claim on the actual audio/video content. Do not invent techniques not mentioned.
- Segments should be substantial (typically 60-300 sec each). Do not over-segment.
- Notes must be technical and specific — no filler like "the speaker discusses X" without saying what about X.
- Return ONLY the JSON object.`;

async function loadGenAI() {
  try {
    const mod = await import("@google/genai");
    return mod;
  } catch (err) {
    console.error("Missing dep @google/genai. Add it to package.json and run `npm install`.");
    console.error(err.message);
    process.exit(1);
  }
}

function fileFingerprint(filePath) {
  const stat = fs.statSync(filePath);
  const head = fs.readFileSync(filePath, { flag: "r" }).subarray(0, 1024 * 1024);
  return crypto.createHash("sha256").update(head).update(String(stat.size)).digest("hex").slice(0, 24);
}

function cachePath(fingerprint) {
  return path.join(CACHE_DIR, `video-notes-${fingerprint}.json`);
}

function outJsonlPath(sourcePath) {
  const base = path.basename(sourcePath, path.extname(sourcePath));
  return path.join(INCOMING, `${base}-video-notes.jsonl`);
}

async function uploadAndWait(genai, videoPath) {
  const uploaded = await genai.files.upload({
    file: videoPath,
    config: { mimeType: mimeFor(videoPath), displayName: path.basename(videoPath) },
  });
  let file = uploaded;
  const deadline = Date.now() + 10 * 60 * 1000;
  while (file.state !== "ACTIVE") {
    if (file.state === "FAILED") throw new Error(`Gemini file processing failed: ${file.name}`);
    if (Date.now() > deadline) throw new Error(`Timed out waiting for file to become ACTIVE: ${file.name}`);
    await new Promise((r) => setTimeout(r, 5000));
    file = await genai.files.get({ name: file.name });
  }
  return file;
}

function mimeFor(videoPath) {
  const ext = path.extname(videoPath).toLowerCase();
  if (ext === ".mp4" || ext === ".m4v") return "video/mp4";
  if (ext === ".mov") return "video/quicktime";
  if (ext === ".webm") return "video/webm";
  if (ext === ".mkv") return "video/x-matroska";
  return "application/octet-stream";
}

function parseJsonStrict(text) {
  const trimmed = text.trim().replace(/^```json\s*/i, "").replace(/```$/, "").trim();
  return JSON.parse(trimmed);
}

async function extractOne(genai, videoPath) {
  const fingerprint = fileFingerprint(videoPath);
  const cache = cachePath(fingerprint);
  if (fs.existsSync(cache)) {
    return { ...JSON.parse(fs.readFileSync(cache, "utf8")), cached: true, fingerprint };
  }
  console.log(`[gemini] uploading ${path.basename(videoPath)} (${(fs.statSync(videoPath).size / 1024 / 1024).toFixed(1)} MB)...`);
  const file = await uploadAndWait(genai, videoPath);
  console.log(`[gemini] extracting notes with ${MODEL}...`);
  const response = await genai.models.generateContent({
    model: MODEL,
    contents: [
      { role: "user", parts: [
        { fileData: { fileUri: file.uri, mimeType: file.mimeType } },
        { text: EXTRACTION_PROMPT },
      ] },
    ],
    config: { responseMimeType: "application/json", temperature: 0.2 },
  });
  const text = response.text ?? response.response?.text?.() ?? "";
  const notes = parseJsonStrict(text);
  fs.writeFileSync(cache, JSON.stringify({ notes, model: MODEL, extracted_at: new Date().toISOString() }, null, 2));
  return { notes, model: MODEL, extracted_at: new Date().toISOString(), cached: false, fingerprint };
}

function buildJsonlRecord(sourcePath, extraction) {
  const { notes, model, extracted_at, fingerprint } = extraction;
  const body = [
    `# ${notes.title}`,
    "",
    notes.summary ?? "",
    "",
    ...(notes.segments ?? []).map((s) => [
      `## ${formatTimestamp(s.start_sec)}–${formatTimestamp(s.end_sec)} · ${s.topic ?? ""}`.trim(),
      "",
      s.notes ?? "",
      "",
      s.techniques_mentioned?.length ? `**Techniques:** ${s.techniques_mentioned.join(", ")}` : "",
      s.code_or_commands?.length ? "\n```\n" + s.code_or_commands.join("\n") + "\n```\n" : "",
      s.references?.length ? `**Refs:** ${s.references.join(", ")}` : "",
    ].filter(Boolean).join("\n")),
  ].join("\n");
  return {
    title: notes.title,
    body,
    language: notes.language ?? "en",
    wrapped_from: "gemini_video",
    wrapped_at: new Date().toISOString(),
    video_notes: {
      source_file: path.relative(process.cwd(), sourcePath),
      fingerprint,
      duration_sec: notes.duration_sec ?? null,
      model,
      extracted_at,
      segments: notes.segments ?? [],
      overall_techniques: notes.overall_techniques ?? [],
      overall_references: notes.overall_references ?? [],
    },
  };
}

function formatTimestamp(sec) {
  if (sec == null || !Number.isFinite(sec)) return "?";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${m}:${String(s).padStart(2, "0")}`;
}

function moveOrDelete(src, destParent) {
  if (dryRun) return;
  if (purge) { fs.rmSync(src, { force: true }); return; }
  fs.mkdirSync(destParent, { recursive: true });
  fs.renameSync(src, path.join(destParent, path.basename(src)));
}

const genaiMod = await loadGenAI();
const genai = new genaiMod.GoogleGenAI({ apiKey: API_KEY });

let ok = 0;
let skipped = 0;
let failed = 0;
for (const videoPath of videos) {
  const outPath = outJsonlPath(videoPath);
  if (fs.existsSync(outPath)) {
    console.log(`[skip] ${path.basename(videoPath)} → ${path.basename(outPath)} already exists`);
    skipped++;
    continue;
  }
  try {
    const extraction = await extractOne(genai, videoPath);
    const record = buildJsonlRecord(videoPath, extraction);
    if (!dryRun) fs.writeFileSync(outPath, JSON.stringify(record) + "\n");
    console.log(`[${dryRun ? "DRY-RUN" : "OK"}] ${path.basename(videoPath)} → ${path.basename(outPath)}${extraction.cached ? " (from cache)" : ""}`);
    moveOrDelete(videoPath, WRAPPED);
    ok++;
  } catch (err) {
    console.error(`[FAIL] ${path.basename(videoPath)}: ${err.message}`);
    failed++;
  }
}

console.log(`ingest-video: ${ok} extracted, ${skipped} skipped, ${failed} failed of ${videos.length} total`);
process.exit(failed > 0 ? 1 : 0);
