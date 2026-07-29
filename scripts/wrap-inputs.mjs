#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const dryRun = argv.includes("--dry-run");
const purge = argv.includes("--purge-source");

const INCOMING = path.resolve("data/incoming");
const WRAPPED = path.join(INCOMING, ".wrapped");
const SKIP_DIRS = new Set([".wrapped", "quarantine"]);
// Curated evidence + auto-generated batches — never wrap-in-place; they are
// authoritative source material or already-emitted JSONL surroundings.
const SKIP_DIR_PATTERNS = [/^bundle-\d+$/, /^expand-/, /^tech-/, /^src-/];

const CODE_EXT = new Set([
  ".rs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".java", ".kt", ".kts", ".swift", ".rb", ".php", ".cs", ".scala",
  ".sh", ".bash", ".zsh", ".fish", ".pl",
]);
const DOC_EXT = new Set([".md", ".markdown", ".txt", ".rst", ".adoc"]);
const SKIP_SUFFIX = [".jsonl", ".mapping.json", ".report.json"];

if (!fs.existsSync(INCOMING)) {
  console.log(`No data/incoming directory at ${INCOMING} — nothing to wrap.`);
  process.exit(0);
}
fs.mkdirSync(WRAPPED, { recursive: true });

const now = new Date().toISOString();
const stats = { rawFiles: 0, projects: 0, jsonlLines: 0, dryRun };

function isHidden(name) {
  return name.startsWith(".");
}

function shouldSkipFile(name) {
  if (isHidden(name)) return true;
  for (const suf of SKIP_SUFFIX) if (name.endsWith(suf)) return true;
  return false;
}

function extOf(name) {
  return path.extname(name).toLowerCase();
}

function kindOf(name) {
  const ext = extOf(name);
  if (CODE_EXT.has(ext)) return "source_code";
  if (DOC_EXT.has(ext)) return "documentation";
  return null;
}

function isSkippedDir(name) {
  if (SKIP_DIRS.has(name)) return true;
  for (const pat of SKIP_DIR_PATTERNS) if (pat.test(name)) return true;
  return false;
}

// Latest curated bundle by lexical sort (bundle-<YYYYMMDD> pattern → newest wins).
function findLatestBundle() {
  try {
    const bundles = fs.readdirSync(INCOMING, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^bundle-\d+$/.test(e.name))
      .map((e) => e.name)
      .sort();
    return bundles.length ? path.join(INCOMING, bundles[bundles.length - 1]) : null;
  } catch { return null; }
}

function humanize(basename) {
  return basename
    .replace(/[-_]+/g, " ")
    .replace(/\.[^.]+$/, "")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

function firstH1(text) {
  const m = text.match(/^\s*#\s+(.+?)\s*$/m);
  return m ? m[1].trim() : null;
}

function walkRecursive(dir, base, acc) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (isHidden(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkRecursive(full, base, acc);
    } else if (entry.isFile() && !shouldSkipFile(entry.name)) {
      const rel = path.relative(base, full);
      acc.push({ full, rel });
    }
  }
  return acc;
}

function walkProject(dir) {
  return walkRecursive(dir, dir, []);
}

function buildCodeLine({ fileName, relativePath, ext, content, projectManifest }) {
  const rec = {
    file_name: fileName,
    relative_path: relativePath,
    file_type: ext.replace(/^\./, ""),
    content,
    wrapped_from: "raw_file",
    wrapped_at: now,
  };
  if (projectManifest) rec.project_manifest = projectManifest;
  return rec;
}

function buildDocLine({ title, body, projectManifest }) {
  const rec = {
    title,
    body,
    language: "en",
    wrapped_from: "raw_file",
    wrapped_at: now,
  };
  if (projectManifest) rec.project_manifest = projectManifest;
  return rec;
}

function jsonlStringify(records) {
  return records.map((r) => JSON.stringify(r)).join("\n") + "\n";
}

function moveOrDelete(src, destParent) {
  if (dryRun) return;
  if (purge) {
    fs.rmSync(src, { recursive: true, force: true });
    return;
  }
  fs.mkdirSync(destParent, { recursive: true });
  const dest = path.join(destParent, path.basename(src));
  fs.renameSync(src, dest);
}

function wrapSingleFile(entry) {
  const kind = kindOf(entry.name);
  if (!kind) return null;
  const abs = path.join(INCOMING, entry.name);
  const content = fs.readFileSync(abs, "utf8");
  const baseNoExt = entry.name.replace(/\.[^.]+$/, "");
  const outPath = path.join(INCOMING, `${baseNoExt}.jsonl`);
  if (fs.existsSync(outPath)) {
    return { action: "skip-existing-jsonl", src: entry.name, out: path.basename(outPath) };
  }
  let record;
  if (kind === "source_code") {
    record = buildCodeLine({
      fileName: entry.name,
      relativePath: entry.name,
      ext: extOf(entry.name),
      content,
    });
  } else {
    record = buildDocLine({
      title: firstH1(content) ?? humanize(entry.name),
      body: content,
    });
  }
  if (!dryRun) fs.writeFileSync(outPath, jsonlStringify([record]));
  // Route raw source_code to the latest curated bundle's source-extracts/ so
  // it becomes authoritative evidence (preserved through the Ronda-J purge),
  // instead of being buried under .wrapped/. Docs still go to .wrapped/ since
  // they are more transient (spec drafts, notes).
  let destParent = WRAPPED;
  if (kind === "source_code") {
    const bundle = findLatestBundle();
    if (bundle) destParent = path.join(bundle, "source-extracts");
  }
  moveOrDelete(abs, destParent);
  stats.rawFiles++;
  stats.jsonlLines++;
  const dest = path.relative(INCOMING, destParent);
  return { action: "wrap-file", kind, src: entry.name, out: path.basename(outPath), dest, lines: 1 };
}

function wrapProject(dirEntry) {
  const projectName = dirEntry.name;
  const abs = path.join(INCOMING, projectName);
  const files = walkProject(abs).filter((f) => kindOf(f.rel) !== null);
  if (files.length === 0) {
    return { action: "skip-empty-project", dir: projectName };
  }
  const outPath = path.join(INCOMING, `${projectName}.jsonl`);
  if (fs.existsSync(outPath)) {
    return { action: "skip-existing-jsonl", dir: projectName, out: path.basename(outPath) };
  }
  const records = [];
  for (const f of files) {
    const kind = kindOf(f.rel);
    const content = fs.readFileSync(f.full, "utf8");
    const role = detectRole(f.rel, kind);
    const projectManifest = { project: projectName, relative_path: f.rel, role };
    if (kind === "source_code") {
      records.push(buildCodeLine({
        fileName: path.basename(f.rel),
        relativePath: f.rel,
        ext: extOf(f.rel),
        content,
        projectManifest,
      }));
    } else {
      records.push(buildDocLine({
        title: firstH1(content) ?? humanize(path.basename(f.rel)),
        body: content,
        projectManifest,
      }));
    }
  }
  if (!dryRun) fs.writeFileSync(outPath, jsonlStringify(records));
  moveOrDelete(abs, WRAPPED);
  stats.projects++;
  stats.jsonlLines += records.length;
  return { action: "wrap-project", dir: projectName, out: path.basename(outPath), lines: records.length };
}

function detectRole(relPath, kind) {
  const lower = path.basename(relPath).toLowerCase();
  if (lower === "readme.md" || lower === "readme.markdown" || lower === "readme.txt") return "readme";
  if (/^walk[-]?through\.md$/.test(lower) || lower === "walkthrough.md") return "walkthrough";
  if (kind === "documentation") return "documentation";
  return "source_code";
}

const topEntries = fs.readdirSync(INCOMING, { withFileTypes: true });
const actions = [];
for (const entry of topEntries) {
  if (isHidden(entry.name)) continue;
  if (entry.isDirectory() && isSkippedDir(entry.name)) continue;
  if (entry.isFile()) {
    if (shouldSkipFile(entry.name)) continue;
    const result = wrapSingleFile(entry);
    if (result) actions.push(result);
  } else if (entry.isDirectory()) {
    const result = wrapProject(entry);
    if (result) actions.push(result);
  }
}

const label = dryRun ? "DRY-RUN" : "WRAP";
if (actions.length === 0) {
  console.log(`[${label}] no raw files to wrap under ${path.relative(process.cwd(), INCOMING)}`);
} else {
  for (const a of actions) {
    const detail = a.dir ? `project=${a.dir}` : `src=${a.src}`;
    const out = a.out ? ` out=${a.out}` : "";
    const lines = a.lines != null ? ` lines=${a.lines}` : "";
    console.log(`[${label}] ${a.action} ${detail}${out}${lines}`);
  }
}
console.log(`[${label}] summary: ${stats.rawFiles} raw files, ${stats.projects} project bundles, ${stats.jsonlLines} JSONL lines total`);
