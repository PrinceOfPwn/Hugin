import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const input = path.resolve(process.argv[2] ?? "hugin/vault-export/graph.json");
const output = path.resolve(process.argv[3] ?? "data/source/public-graph.json");

const CORE_TYPES = new Set([
  "technique",
  "playbook",
  "concept",
  "detection",
  "lgtm_note",
  "chain",
  "architecture",
  "pattern"
]);
const SUPPORT_TYPES = new Set(["source", "documentation", "source-extract", "reference"]);

const LOW_VALUE_RULES = [
  {
    reason: "title-or-cover",
    pattern: /\b(?:title|cover|opening)\s+(?:page|slide)\b|\bcourse\s+title\b/i
  },
  {
    reason: "navigation-only",
    pattern: /\btable\s+of\s+contents\b|\bagenda\s+(?:page|slide)\b|\bbibliography\s+(?:page|slide)\b|\breferences\s+(?:page|slide)\b/i
  },
  {
    reason: "objectives-or-overview",
    pattern: /\blearning\s+objectives?\b|\bcourse\s+overview\b|\bmodule\s+overview\b/i
  },
  {
    reason: "legal-or-promotional",
    pattern: /\bcopyright\s+notice\b|\bdisclaimer\s+(?:page|slide)\b|\bpromotional\s+link\b/i
  }
];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const shortHash = (value, length = 16) => sha256(String(value)).slice(0, length);

if (!fs.existsSync(input)) {
  throw new Error(`Owner import not found: ${input}`);
}

const rawText = fs.readFileSync(input, "utf8");
const graph = JSON.parse(rawText);
const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];
const rawContents = graph.contents && typeof graph.contents === "object" ? graph.contents : {};

const absoluteUnix = /\/(?:Users|home)\/[^\s/]+\/[^\s)\]}>"']+/gi;
const absoluteWindows = /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^\s)\]}>"']+/gi;
const localUser = /\b(?:emiperalta|tamarisk)\b/gi;
const anonymousSourceUrl = /https?:\/\/(?:www\.)?(?:linktr\.ee\/offsecexam|sans\.org|offsec\.com|maldevacademy\.com)[^\s)\]}>"']*/gi;

function anonymizeSourceNames(value) {
  return value
    .replace(/https?:\/\/[^\s)\]}>"']*offsec[^\s)\]}>"']*/gi, "[private-source]")
    .replace(/\bSANS\s+SEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSANS(?:\s+Institute)?\b/gi, "Source A")
    .replace(/\bCertified\s+Red\s+Team\s+Operator\b|\bCRTO\b/gi, "Source B")
    .replace(/\bMalDev(?:[_ -]*Academy)?\b/gi, "Source B")
    .replace(/\bOffensive\s+Security\b|\bOffSec(?:[_ -]*[A-Za-z]+)?\b/gi, "Source B")
    .replace(/OffSec/gi, "research")
    .replace(/\b(Source [AB])(?:\s+\1)+\b/gi, "$1");
}

function sanitizeString(value) {
  return anonymizeSourceNames(String(value))
    .replace(absoluteUnix, "[private-source]")
    .replace(absoluteWindows, "[private-source]")
    .replace(localUser, "source-owner")
    .replace(anonymousSourceUrl, "[private-source]")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/ +([,.;:])/g, "$1")
    .trim();
}

function sanitize(value) {
  if (typeof value === "string") return sanitizeString(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => ![
          "source_path",
          "source_key",
          "sourceLabel",
          "file_path",
          "absolute_path",
          "local_path"
        ].includes(key))
        .map(([key, child]) => [key, sanitize(child)])
    );
  }
  return value;
}

function publicIdFor(node) {
  const rawId = String(node.id);
  if (node.type === "atlas_reference") return `evidence:${shortHash(rawId, 20)}`;
  if (/\b(?:SANS|SEC\d{3}|CRTO|MalDev|OffSec)\b/i.test(rawId) || /(?:\/Users\/|[A-Za-z]:\\Users\\)/i.test(rawId)) {
    return `${node.type || "entity"}:${shortHash(rawId, 20)}`;
  }
  return sanitizeString(rawId);
}

function classificationFor(node, body) {
  if (node.type === "atlas_reference") {
    const text = [node.label, node.title, node.summary, node.description, body].filter(Boolean).join(" ");
    const match = LOW_VALUE_RULES.find((rule) => rule.pattern.test(text));
    if (match) return { publishState: "quarantined", quarantineReason: match.reason };
    return { publishState: "evidence", quarantineReason: null };
  }
  if (CORE_TYPES.has(node.type)) return { publishState: "core", quarantineReason: null };
  if (SUPPORT_TYPES.has(node.type)) return { publishState: "support", quarantineReason: null };
  return { publishState: "support", quarantineReason: null };
}

function neutralCategory(node) {
  if (node.type === "atlas_reference") return "evidence";
  const category = sanitizeString(node.category || node.type || "uncategorized")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  return category || "uncategorized";
}

const publicIdByRawId = new Map(rawNodes.map((node) => [String(node.id), publicIdFor(node)]));
const quarantinedNodes = [];
const stateCounts = { core: 0, support: 0, evidence: 0, quarantined: 0 };

const nodes = [];
const contents = {};
for (const rawNode of rawNodes) {
  const rawId = String(rawNode.id);
  const publicId = publicIdByRawId.get(rawId);
  const rawBody = rawContents[rawId] || rawNode.description || rawNode.summary || "";
  const { publishState, quarantineReason } = classificationFor(rawNode, rawBody);
  stateCounts[publishState] += 1;

  if (publishState === "quarantined") {
    quarantinedNodes.push({
      id: `Q-${shortHash(rawId, 12).toUpperCase()}`,
      type: rawNode.type,
      reason: quarantineReason
    });
    continue;
  }

  const clean = sanitize(rawNode);
  const evidenceId = `EV-${shortHash(rawId, 10).toUpperCase()}`;
  nodes.push({
    ...clean,
    id: publicId,
    category: neutralCategory(rawNode),
    publishState,
    evidenceId,
    sourceClass: publishState === "evidence" ? "training-reference" : "owner-authorized-research",
    sourceHash: sha256(JSON.stringify(rawNode)).slice(0, 16)
  });
  contents[publicId] = sanitizeString(rawBody);
}

const publishedIds = new Set(nodes.map((node) => node.id));
const quarantinedRelations = [];
const edges = [];

for (const [index, rawEdge] of rawEdges.entries()) {
  const source = publicIdByRawId.get(String(rawEdge.source));
  const target = publicIdByRawId.get(String(rawEdge.target));
  const publicEdge = sanitize({ ...rawEdge, source, target });

  if (source === target) {
    quarantinedRelations.push({
      id: `RQ-${shortHash(`${index}:${source}:${target}`, 12).toUpperCase()}`,
      reason: "self-relation"
    });
    continue;
  }
  if (!publishedIds.has(source) || !publishedIds.has(target)) {
    quarantinedRelations.push({
      id: `RQ-${shortHash(`${index}:${source}:${target}`, 12).toUpperCase()}`,
      reason: "quarantined-evidence-endpoint"
    });
    continue;
  }
  edges.push(publicEdge);
}

const projection = {
  schemaVersion: "2.1.0",
  ownerAuthorization: "All included material and brand assets are provided and authorized by the repository owner.",
  sourceHash: sha256(rawText),
  rawCounts: {
    nodes: rawNodes.length,
    relations: rawEdges.length
  },
  quality: {
    states: stateCounts,
    quarantinedNodes,
    quarantinedRelations,
    rules: LOW_VALUE_RULES.map(({ reason }) => reason)
  },
  nodes,
  edges,
  contents
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(projection)}\n`);

console.log(JSON.stringify({
  output: path.relative(ROOT, output),
  rawCounts: projection.rawCounts,
  publicNodes: nodes.length,
  publicRelations: edges.length,
  states: stateCounts,
  quarantinedRelations: quarantinedRelations.length,
  sourceHash: projection.sourceHash
}, null, 2));
