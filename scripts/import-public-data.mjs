import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const input = path.resolve(process.argv[2] ?? "hugin/vault-export/graph.json");
const output = path.resolve(process.argv[3] ?? "data/source/public-graph.json");

if (!fs.existsSync(input)) {
  throw new Error(`Owner import not found: ${input}`);
}

const rawText = fs.readFileSync(input, "utf8");
const graph = JSON.parse(rawText);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

const absoluteUnix = /\/(?:Users|home)\/[^\s/]+\/[^\s)\]}>"']+/gi;
const absoluteWindows = /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^\s)\]}>"']+/gi;
const localUser = /\b(?:emiperalta|tamarisk)\b/gi;

function sanitizeString(value) {
  return value
    .replace(absoluteUnix, (match) => `[local-source:${sha256(match).slice(0, 12)}]`)
    .replace(absoluteWindows, (match) => `[local-source:${sha256(match).slice(0, 12)}]`)
    .replace(localUser, "source-owner");
}

function sanitize(value) {
  if (typeof value === "string") return sanitizeString(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !["source_path", "file_path", "absolute_path"].includes(key))
        .map(([key, child]) => [key, sanitize(child)])
    );
  }
  return value;
}

const quarantined = [];
const edges = graph.edges.filter((edge, index) => {
  if (edge.source === edge.target) {
    quarantined.push({ index, ...sanitize(edge), reason: "self-relation" });
    return false;
  }
  return true;
});

const nodes = graph.nodes.map((node) => {
  const clean = sanitize(node);
  const sourceKey = clean.source_key || clean.category || clean.type || "hugin";
  return {
    ...clean,
    sourceKey,
    sourceLabel: String(sourceKey)
      .replace(/[-_]+/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase()),
    sourceHash: sha256(JSON.stringify(node)).slice(0, 16)
  };
});

const contents = Object.fromEntries(
  Object.entries(graph.contents).map(([id, body]) => [id, sanitizeString(body)])
);

const projection = {
  schemaVersion: "2.0.0",
  importedAt: new Date().toISOString(),
  ownerAuthorization: "All included content and Raven assets are provided and authorized by the repository owner.",
  sourceHash: sha256(rawText),
  nodes,
  edges: edges.map(sanitize),
  contents,
  quarantined
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(projection)}\n`);

console.log(JSON.stringify({
  output: path.relative(ROOT, output),
  nodes: nodes.length,
  curatedRelations: edges.length,
  contents: Object.keys(contents).length,
  quarantined: quarantined.length,
  sourceHash: projection.sourceHash
}, null, 2));
