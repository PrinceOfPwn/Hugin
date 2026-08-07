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

const argv = process.argv.slice(2);
const configArg = argv.find((arg) => !arg.startsWith("--"));
if (!configArg) {
  console.error("Usage: node scripts/ingest-external-knowledge.mjs <collection.json> [--source=URL] [--out=FILE] [--max-documents=N] [--max-pages=N]");
  process.exit(2);
}

const configPath = path.resolve(configArg);
if (!fs.existsSync(configPath)) throw new Error(`Collection config not found: ${configPath}`);
const collection = JSON.parse(fs.readFileSync(configPath, "utf8"));
const sourceOverride = argValue("--source=");
if (sourceOverride) collection.source = sourceOverride;
if (!collection.id || !collection.title || !collection.source) throw new Error("Collection requires id, title, and source");

const maxDocuments = intArg("--max-documents=", collection.max_documents ?? 25);
const maxPages = intArg("--max-pages=", collection.max_pages_per_document ?? Infinity);
const chunkChars = intArg("--chunk-chars=", collection.chunk_chars ?? DEFAULT_CHUNK_CHARS);
const overlapPages = intArg("--overlap-pages=", collection.chunk_overlap_pages ?? 1);
const output = path.resolve(argValue("--out=") ?? `.cache/hugin-external/${slugify(collection.id)}.chunks.jsonl`);
const inventoryPath = path.resolve(argValue("--inventory=") ?? `${output.replace(/\.jsonl$/i, "")}.inventory.json`);

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-external-"));
const records = [];
const inventory = {
  collection: { id: collection.id, title: collection.title, source: collection.source },
  staged_at: new Date().toISOString(),
  documents: [],
  skipped: [],
};

try {
  ensurePdftotext();
  const sources = (await resolveSources(collection.source)).slice(0, maxDocuments);
  if (!sources.length) throw new Error(`No supported documents resolved from ${collection.source}`);

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

  if (!records.length) throw new Error("External staging produced zero chunks");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
  fs.mkdirSync(path.dirname(inventoryPath), { recursive: true });
  fs.writeFileSync(inventoryPath, `${JSON.stringify({ ...inventory, chunks: records.length }, null, 2)}\n`);
  console.log(`[external] staged ${records.length} chunks from ${inventory.documents.length} document(s) -> ${output}`);
  console.log(`[external] inventory -> ${inventoryPath}`);
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function argValue(prefix) {
  return argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length) ?? null;
}

function intArg(prefix, fallback) {
  const raw = argValue(prefix);
  if (raw == null || raw === "") return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${prefix} expects a positive integer`);
  return value;
}

function ensurePdftotext() {
  const result = spawnSync("pdftotext", ["-v"], { encoding: "utf8" });
  if (result.error?.code === "ENOENT") {
    throw new Error("pdftotext is required for PDF ingestion. Install poppler-utils on Linux.");
  }
}

async function resolveSources(sourceValue) {
  if (/^https?:\/\/github\.com\//i.test(sourceValue)) {
    const repo = parseGithubRepoUrl(sourceValue);
    if (repo && !/\.pdf(?:$|[?#])/i.test(sourceValue) && !/\/blob\//i.test(sourceValue)) return resolveGithubPdfRepo(repo);
    const blob = parseGithubBlobUrl(sourceValue);
    if (blob) return [{
      title: path.basename(blob.filePath),
      url: sourceValue,
      fetchUrl: `https://raw.githubusercontent.com/${blob.owner}/${blob.repo}/${encodeURIComponent(blob.ref)}/${blob.filePath.split("/").map(encodeURIComponent).join("/")}`,
      kind: "pdf",
    }];
  }
  if (/^https?:\/\//i.test(sourceValue)) {
    return [{ title: titleFromUrl(sourceValue), url: sourceValue, fetchUrl: sourceValue, kind: /\.pdf(?:$|[?#])/i.test(sourceValue) ? "pdf" : "web" }];
  }
  const local = path.resolve(sourceValue);
  if (!fs.existsSync(local)) throw new Error(`Source not found: ${sourceValue}`);
  return [{ title: path.basename(local), url: `file://${local}`, localPath: local, kind: /\.pdf$/i.test(local) ? "pdf" : "web" }];
}

function parseGithubRepoUrl(value) {
  try {
    const url = new URL(value);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/, "");
    let ref = "main";
    let prefix = "";
    if (parts[2] === "tree" && parts[3]) {
      ref = decodeURIComponent(parts[3]);
      prefix = parts.slice(4).map(decodeURIComponent).join("/");
    }
    return { owner, repo, ref, prefix };
  } catch {
    return null;
  }
}

function parseGithubBlobUrl(value) {
  const repo = parseGithubRepoUrl(value);
  if (!repo) return null;
  const parts = new URL(value).pathname.split("/").filter(Boolean);
  const blobIndex = parts.indexOf("blob");
  if (blobIndex < 0 || !parts[blobIndex + 1]) return null;
  return {
    owner: parts[0], repo: parts[1], ref: decodeURIComponent(parts[blobIndex + 1]),
    filePath: parts.slice(blobIndex + 2).map(decodeURIComponent).join("/"),
  };
}

async function resolveGithubPdfRepo({ owner, repo, ref, prefix }) {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Hugin-external-knowledge",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const response = await fetch(api, { headers, signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error(`GitHub tree request failed: ${response.status} ${await response.text().then((t) => t.slice(0, 240))}`);
  const payload = await response.json();
  if (payload.truncated) throw new Error("GitHub tree response was truncated; narrow the repository path");
  const normalizedPrefix = prefix ? `${prefix.replace(/\/$/, "")}/` : "";
  return (payload.tree ?? [])
    .filter((entry) => entry.type === "blob" && entry.path.startsWith(normalizedPrefix) && /\.pdf$/i.test(entry.path))
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((entry) => ({
      title: path.basename(entry.path),
      url: `https://github.com/${owner}/${repo}/blob/${encodeURIComponent(ref)}/${entry.path.split("/").map(encodeURIComponent).join("/")}`,
      fetchUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(ref)}/${entry.path.split("/").map(encodeURIComponent).join("/")}`,
      kind: "pdf",
      repo: `${owner}/${repo}`,
      ref,
      repoPath: entry.path,
    }));
}

async function stageSource(source) {
  let bytes;
  let contentType = "";
  if (source.localPath) {
    bytes = fs.readFileSync(source.localPath);
    contentType = source.kind === "pdf" ? "application/pdf" : "text/html";
  } else {
    const response = await fetch(source.fetchUrl, {
      headers: { "User-Agent": "Hugin-external-knowledge/1.0" },
      redirect: "follow",
      signal: AbortSignal.timeout(120000),
    });
    if (!response.ok) throw new Error(`fetch failed: ${response.status}`);
    const length = Number(response.headers.get("content-length") || 0);
    const maxBytes = Number(collection.max_document_bytes ?? 100 * 1024 * 1024);
    if (length && length > maxBytes) throw new Error(`document exceeds max_document_bytes (${length} > ${maxBytes})`);
    bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maxBytes) throw new Error(`document exceeds max_document_bytes (${bytes.length} > ${maxBytes})`);
    contentType = response.headers.get("content-type") ?? "";
  }

  const digest = sha256(bytes);
  const sourceId = `external-source:${sha256(`${collection.id}:${source.url}:${digest}`).slice(0, 24)}`;
  const isPdf = source.kind === "pdf" || /application\/pdf/i.test(contentType) || bytes.subarray(0, 5).toString("ascii") === "%PDF-";
  let chunks;
  let sourceTitle = source.title;

  if (isPdf) {
    const pdfPath = path.join(tempRoot, `${slugify(source.title)}-${digest.slice(0, 8)}.pdf`);
    fs.writeFileSync(pdfPath, bytes);
    const result = spawnSync("pdftotext", ["-layout", "-enc", "UTF-8", pdfPath, "-"], {
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
    });
    if (result.status !== 0) throw new Error(`pdftotext failed: ${(result.stderr || result.stdout || "unknown error").slice(0, 500)}`);
    chunks = chunkPdfText(result.stdout, { chunkChars, overlapPages, maxPages });
  } else {
    const decoded = bytes.toString("utf8");
    const parsed = /text\/html/i.test(contentType) || /<html|<body|<article/i.test(decoded.slice(0, 5000))
      ? htmlToText(decoded)
      : { title: "", text: decoded };
    if (parsed.title) sourceTitle = parsed.title;
    chunks = chunkPlainText(parsed.text, { chunkChars, overlapChars: collection.chunk_overlap_chars ?? 1600 });
  }

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
      pages: out.length && out.at(-1).source_document.page_end ? out.at(-1).source_document.page_end : null,
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
