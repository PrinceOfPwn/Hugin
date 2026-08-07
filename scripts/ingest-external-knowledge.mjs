#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  DEFAULT_CHUNK_CHARS,
  chunkPdfText,
  chunkPlainText,
  htmlToText,
  sha256,
  slugify,
} from "./lib/external-knowledge.mjs";

const MAX_DOCUMENTS_HARD = 50;
const MAX_PAGES_HARD = 1500;
const MAX_CHUNK_CHARS_HARD = 90000;
const argv = process.argv.slice(2);
const configArg = argv.find((arg) => !arg.startsWith("--"));
if (!configArg) {
  console.error("Usage: node scripts/ingest-external-knowledge.mjs <collection.json> [--source=URL] [--out=FILE] [--max-documents=N] [--max-pages=N] [--require-complete]");
  process.exit(2);
}

const configPath = path.resolve(configArg);
if (!fs.existsSync(configPath)) throw new Error(`Collection config not found: ${configPath}`);
const collection = JSON.parse(fs.readFileSync(configPath, "utf8"));
const sourceOverride = argValue("--source=");
if (sourceOverride) collection.source = sourceOverride;
if (!collection.id || !collection.title || !collection.source) throw new Error("Collection requires id, title, and source");
if (!/^https?:\/\//i.test(collection.source)) throw new Error("Publishable external knowledge requires a public http(s) source URL");

const maxDocuments = intArg("--max-documents=", collection.max_documents ?? 25, MAX_DOCUMENTS_HARD);
const maxPages = intArg("--max-pages=", collection.max_pages_per_document ?? MAX_PAGES_HARD, MAX_PAGES_HARD);
const chunkChars = intArg("--chunk-chars=", collection.chunk_chars ?? DEFAULT_CHUNK_CHARS, MAX_CHUNK_CHARS_HARD);
const overlapPages = intArg("--overlap-pages=", collection.chunk_overlap_pages ?? 1, 20);
const requireComplete = argv.includes("--require-complete");
const output = path.resolve(argValue("--out=") ?? `.cache/hugin-external/${slugify(collection.id)}.chunks.jsonl`);
const inventoryPath = path.resolve(argValue("--inventory=") ?? `${output.replace(/\.jsonl$/i, "")}.inventory.json`);

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-external-"));
const records = [];
const inventory = {
  collection: { id: collection.id, title: collection.title, source: collection.source },
  staged_at: new Date().toISOString(),
  limits: { max_documents: maxDocuments, max_pages_per_document: maxPages, max_document_bytes: maxDocumentBytes() },
  resolved_sources: 0,
  selected_sources: 0,
  complete: false,
  documents: [],
  skipped: [],
};

try {
  const resolvedSources = await resolveSources(collection.source);
  inventory.resolved_sources = resolvedSources.length;
  if (!resolvedSources.length) throw new Error(`No supported documents resolved from ${collection.source}`);
  if (requireComplete && resolvedSources.length > maxDocuments) {
    inventory.selected_sources = maxDocuments;
    writeInventory();
    throw new Error(`Complete publication requires all ${resolvedSources.length} documents, but max_documents=${maxDocuments}`);
  }

  const sources = resolvedSources.slice(0, maxDocuments);
  inventory.selected_sources = sources.length;
  for (const [docIndex, source] of sources.entries()) {
    process.stdout.write(`[external] ${docIndex + 1}/${sources.length} ${source.title} ... `);
    try {
      const result = await stageSource(source);
      inventory.documents.push(result.inventory);
      records.push(...result.records);
      console.log(`${result.records.length} chunks`);
    } catch (error) {
      inventory.skipped.push({ title: source.title, url: source.url, reason: String(error?.message ?? error).slice(0, 700) });
      console.log(`SKIP (${String(error?.message ?? error).slice(0, 160)})`);
    }
  }

  inventory.complete = inventory.selected_sources === inventory.resolved_sources
    && inventory.documents.length === inventory.selected_sources
    && inventory.skipped.length === 0
    && inventory.documents.every((document) => !document.pages_truncated);
  writeInventory();

  if (requireComplete && !inventory.complete) {
    throw new Error(`Complete publication gate failed: resolved=${inventory.resolved_sources}, staged=${inventory.documents.length}, skipped=${inventory.skipped.length}`);
  }
  if (!records.length) throw new Error("External staging produced zero chunks");

  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
  console.log(`[external] staged ${records.length} chunks from ${inventory.documents.length} document(s) -> ${output}`);
  console.log(`[external] inventory -> ${inventoryPath}`);
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function writeInventory() {
  fs.mkdirSync(path.dirname(inventoryPath), { recursive: true });
  fs.writeFileSync(inventoryPath, `${JSON.stringify({ ...inventory, chunks: records.length }, null, 2)}\n`);
}

function argValue(prefix) {
  return argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length) ?? null;
}

function intArg(prefix, fallback, max = Infinity) {
  const raw = argValue(prefix);
  const value = raw == null || raw === "" ? Number(fallback) : Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${prefix} expects a positive integer`);
  if (value > max) throw new Error(`${prefix} must be <= ${max}`);
  return value;
}

function maxDocumentBytes() {
  const value = Number(collection.max_document_bytes ?? 100 * 1024 * 1024);
  if (!Number.isFinite(value) || value <= 0 || value > 150 * 1024 * 1024) throw new Error("max_document_bytes must be between 1 and 157286400");
  return value;
}

function ensurePdftotext() {
  const result = spawnSync("pdftotext", ["-v"], { encoding: "utf8" });
  if (result.error?.code === "ENOENT") throw new Error("pdftotext is required for PDF ingestion. Install poppler-utils on Linux.");
  if (result.status !== 0 && result.status != null) throw new Error(`pdftotext is unavailable: ${(result.stderr || result.stdout || "unknown error").slice(0, 300)}`);
}

function githubHeaders() {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Hugin-external-knowledge",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

async function githubJson(url, label) {
  const response = await fetch(url, { headers: githubHeaders(), signal: AbortSignal.timeout(60000) });
  const text = await response.text();
  if (!response.ok) throw new Error(`${label} failed: ${response.status} ${text.slice(0, 240)}`);
  try { return JSON.parse(text); } catch { throw new Error(`${label} returned invalid JSON`); }
}

async function githubRefExists(owner, repo, kind, ref) {
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/ref/${kind}/${encodeURIComponent(ref)}`;
  const response = await fetch(url, { headers: githubHeaders(), signal: AbortSignal.timeout(30000) });
  if (response.status === 404) return false;
  if (!response.ok) throw new Error(`GitHub ref lookup failed: ${response.status} ${(await response.text()).slice(0, 200)}`);
  return true;
}

async function resolveGithubRef(owner, repo, tailSegments) {
  if (!tailSegments?.length) {
    const metadata = await githubJson(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, "GitHub repository metadata");
    if (!metadata.default_branch) throw new Error("GitHub repository did not report a default branch");
    return { ref: metadata.default_branch, remainder: [] };
  }
  for (let length = tailSegments.length; length >= 1; length--) {
    const candidate = tailSegments.slice(0, length).map(decodeURIComponent).join("/");
    if (await githubRefExists(owner, repo, "heads", candidate) || await githubRefExists(owner, repo, "tags", candidate)) {
      return { ref: candidate, remainder: tailSegments.slice(length).map(decodeURIComponent) };
    }
  }
  throw new Error(`Unable to resolve GitHub branch/tag from ${tailSegments.join("/")}`);
}

async function resolveSources(sourceValue) {
  if (/^https?:\/\/github\.com\//i.test(sourceValue)) {
    const parsed = parseGithubUrl(sourceValue);
    if (!parsed) throw new Error(`Unsupported GitHub URL: ${sourceValue}`);
    const { owner, repo, mode, tail } = parsed;
    const resolved = await resolveGithubRef(owner, repo, mode ? tail : []);
    if (mode === "blob") {
      const filePath = resolved.remainder.join("/");
      if (!filePath || !/\.pdf$/i.test(filePath)) throw new Error("GitHub blob sources must point to a PDF");
      const metadata = await githubJson(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(resolved.ref)}`,
        "GitHub file metadata",
      );
      if (metadata.type !== "file" || !metadata.sha) throw new Error("GitHub blob URL did not resolve to a file");
      return [{
        title: path.basename(filePath),
        url: sourceValue,
        kind: "pdf",
        repo: `${owner}/${repo}`,
        ref: resolved.ref,
        repoPath: filePath,
        githubOwner: owner,
        githubRepo: repo,
        githubBlobSha: metadata.sha,
        size: metadata.size ?? null,
      }];
    }
    const prefix = mode === "tree" ? resolved.remainder.join("/") : "";
    return resolveGithubPdfRepo({ owner, repo, ref: resolved.ref, prefix });
  }
  if (/^https?:\/\//i.test(sourceValue)) {
    return [{ title: titleFromUrl(sourceValue), url: sourceValue, fetchUrl: sourceValue, kind: /\.pdf(?:$|[?#])/i.test(sourceValue) ? "pdf" : "web" }];
  }
  throw new Error("Only public http(s) sources are supported by the publishable external ingestion path");
}

function parseGithubUrl(value) {
  try {
    const url = new URL(value);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const owner = decodeURIComponent(parts[0]);
    const repo = decodeURIComponent(parts[1].replace(/\.git$/, ""));
    const mode = parts[2] === "tree" || parts[2] === "blob" ? parts[2] : null;
    const tail = mode ? parts.slice(3) : [];
    return { owner, repo, mode, tail };
  } catch {
    return null;
  }
}

async function resolveGithubPdfRepo({ owner, repo, ref, prefix }) {
  const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const payload = await githubJson(api, "GitHub tree request");
  if (payload.truncated) throw new Error("GitHub tree response was truncated; narrow the repository path");
  const normalizedPrefix = prefix ? `${prefix.replace(/\/$/, "")}/` : "";
  return (payload.tree ?? [])
    .filter((entry) => entry.type === "blob" && entry.path.startsWith(normalizedPrefix) && /\.pdf$/i.test(entry.path))
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((entry) => ({
      title: path.basename(entry.path),
      url: `https://github.com/${owner}/${repo}/blob/${ref.split("/").map(encodeURIComponent).join("/")}/${entry.path.split("/").map(encodeURIComponent).join("/")}`,
      kind: "pdf",
      repo: `${owner}/${repo}`,
      ref,
      repoPath: entry.path,
      githubOwner: owner,
      githubRepo: repo,
      githubBlobSha: entry.sha,
      size: entry.size ?? null,
    }));
}

async function fetchGithubBlob(source, maxBytes) {
  if (source.size != null && Number(source.size) > maxBytes) throw new Error(`document exceeds max_document_bytes (${source.size} > ${maxBytes})`);
  const payload = await githubJson(
    `https://api.github.com/repos/${encodeURIComponent(source.githubOwner)}/${encodeURIComponent(source.githubRepo)}/git/blobs/${encodeURIComponent(source.githubBlobSha)}`,
    "GitHub blob fetch",
  );
  if (payload.encoding !== "base64" || typeof payload.content !== "string") throw new Error("GitHub blob response did not contain base64 content");
  const bytes = Buffer.from(payload.content.replace(/\s+/g, ""), "base64");
  if (bytes.length > maxBytes) throw new Error(`document exceeds max_document_bytes (${bytes.length} > ${maxBytes})`);
  return bytes;
}

async function readResponseWithLimit(response, maxBytes) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared && declared > maxBytes) throw new Error(`document exceeds max_document_bytes (${declared} > ${maxBytes})`);
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("document size limit exceeded");
        throw new Error(`document exceeds max_document_bytes (${total} > ${maxBytes})`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

async function stageSource(source) {
  const maxBytes = maxDocumentBytes();
  let bytes;
  let contentType = "";
  if (source.githubBlobSha) {
    bytes = await fetchGithubBlob(source, maxBytes);
    contentType = "application/pdf";
  } else {
    const response = await fetch(source.fetchUrl, {
      headers: { "User-Agent": "Hugin-external-knowledge/1.0" },
      redirect: "follow",
      signal: AbortSignal.timeout(120000),
    });
    if (!response.ok) throw new Error(`fetch failed: ${response.status}`);
    contentType = response.headers.get("content-type") ?? "";
    bytes = await readResponseWithLimit(response, maxBytes);
  }

  const digest = sha256(bytes);
  const sourceId = `external-source:${sha256(`${collection.id}:${source.url}:${digest}`).slice(0, 24)}`;
  const isPdf = source.kind === "pdf" || /application\/pdf/i.test(contentType) || bytes.subarray(0, 5).toString("ascii") === "%PDF-";
  let chunks;
  let sourceTitle = source.title;
  let totalPages = null;
  let pagesTruncated = false;

  if (isPdf) {
    ensurePdftotext();
    const pdfPath = path.join(tempRoot, `${slugify(source.title)}-${digest.slice(0, 8)}.pdf`);
    fs.writeFileSync(pdfPath, bytes);
    const result = spawnSync("pdftotext", ["-layout", "-enc", "UTF-8", pdfPath, "-"], {
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
    });
    if (result.status !== 0) throw new Error(`pdftotext failed: ${(result.stderr || result.stdout || "unknown error").slice(0, 500)}`);
    totalPages = result.stdout.split("\f").filter((page) => page.trim()).length;
    pagesTruncated = totalPages > maxPages;
    if (requireComplete && pagesTruncated) throw new Error(`PDF has ${totalPages} text pages but max_pages=${maxPages}; complete publication refuses truncation`);
    chunks = chunkPdfText(result.stdout, { chunkChars, overlapPages, maxPages });
  } else {
    const decoded = bytes.toString("utf8");
    const parsed = /text\/html/i.test(contentType) || /<html|<body|<article/i.test(decoded.slice(0, 5000))
      ? htmlToText(decoded)
      : { title: "", text: decoded };
    if (parsed.title) sourceTitle = parsed.title;
    chunks = chunkPlainText(parsed.text, { chunkChars, overlapChars: collection.chunk_overlap_chars ?? 1600 });
  }

  if (!chunks.length) throw new Error("document produced zero non-empty chunks");
  const out = chunks.map((chunk, index) => {
    const chunkId = `external-chunk:${sha256(`${sourceId}:${index}:${chunk.text}`).slice(0, 28)}`;
    return {
      id: chunkId,
      title: `${sourceTitle}${chunk.page_start ? ` · pp. ${chunk.page_start}${chunk.page_end !== chunk.page_start ? `–${chunk.page_end}` : ""}` : ` · segment ${index + 1}`}`,
      body: chunk.text,
      source_document: {
        collection_id: collection.id,
        collection_title: collection.title,
        knowledge_profile: collection.knowledge_profile ?? "offensive-web",
        source_id: sourceId,
        source_title: sourceTitle,
        source_url: source.url,
        source_kind: isPdf ? "pdf" : "web",
        source_sha256: digest,
        repo: source.repo ?? null,
        ref: source.ref ?? null,
        repo_path: source.repoPath ?? null,
        chunk_index: index,
        page_start: chunk.page_start ?? null,
        page_end: chunk.page_end ?? null,
        char_start: chunk.char_start ?? null,
        char_end: chunk.char_end ?? null,
        publication_policy: "derived-knowledge-only",
      },
    };
  });

  return {
    records: out,
    inventory: {
      source_id: sourceId,
      title: sourceTitle,
      url: source.url,
      kind: isPdf ? "pdf" : "web",
      sha256: digest,
      bytes: bytes.length,
      chunks: out.length,
      total_pages: totalPages,
      pages: out.length && out.at(-1).source_document.page_end ? out.at(-1).source_document.page_end : null,
      pages_truncated: pagesTruncated,
    },
  };
}

function titleFromUrl(value) {
  try {
    const url = new URL(value);
    return decodeURIComponent(path.basename(url.pathname)) || url.hostname;
  } catch {
    return value;
  }
}
