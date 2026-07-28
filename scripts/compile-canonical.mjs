#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sanitize } from "./lib/sanitize.mjs";
import { normalizeWhitespace, readJsonl, sha256 } from "./lib/ingest-contract.mjs";

const inputArg = process.argv[2];
if (!inputArg) {
  console.error("Usage: node scripts/compile-canonical.mjs <enriched.jsonl>");
  process.exit(1);
}

const input = path.resolve(inputArg);
const graphPath = path.resolve("data/source/public-graph.json");
const manifestPath = path.resolve("data/source/ingest-manifest.json");
if (!fs.existsSync(graphPath)) throw new Error(`Graph not found: ${graphPath}`);

const graph = JSON.parse(fs.readFileSync(graphPath, "utf8"));
graph.nodes ??= [];
graph.edges ??= [];
graph.contents ??= {};
const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, "utf8")) : { version: 2, sources: {}, node_owners: {}, edge_owners: {} };
manifest.version = 2;
manifest.sources ??= {};
manifest.node_owners ??= {};
manifest.edge_owners ??= {};
const { records } = readJsonl(input);
const canonical = records.map(({ value }) => value);
const baseName = path.basename(input, ".jsonl");
const normalizedReportPath = path.resolve("data/normalized", `${baseName}.report.json`);
let reportedSource = null;
if (fs.existsSync(normalizedReportPath)) {
  try { reportedSource = JSON.parse(fs.readFileSync(normalizedReportPath, "utf8"))?.input ?? null; } catch {}
}
const sourceKey = canonical[0]?.source?.input_file ?? reportedSource ?? path.relative(process.cwd(), input);
const previous = manifest.sources[sourceKey] ?? { node_ids: [], edge_ids: [] };

const previousNodeIds = new Set(previous.node_ids ?? []);
const previousEdgeIds = new Set(previous.edge_ids ?? []);
const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
const edges = new Map(graph.edges.map((edge) => [edge.id ?? edgeKey(edge), edge]));

for (const id of previousNodeIds) {
  const owners = new Set(manifest.node_owners[id] ?? []);
  owners.delete(sourceKey);
  if (owners.size === 0) {
    nodes.delete(id);
    delete graph.contents[id];
    delete manifest.node_owners[id];
  } else {
    manifest.node_owners[id] = [...owners];
  }
}
for (const id of previousEdgeIds) {
  const owners = new Set(manifest.edge_owners[id] ?? []);
  owners.delete(sourceKey);
  if (owners.size === 0) {
    edges.delete(id);
    delete manifest.edge_owners[id];
  } else {
    manifest.edge_owners[id] = [...owners];
  }
}
const emittedNodeIds = new Set();
const emittedEdgeIds = new Set();

for (const record of canonical) {
  const recordNode = buildRecordNode(record);
  upsertNode(recordNode.node, recordNode.body);

  const namedNodes = new Map();
  for (const concept of record.enrichment?.concepts ?? []) {
    const node = buildDerivedNode("concept", concept.name, concept.description, record, concept.confidence);
    upsertNode(node.node, node.body);
    namedNodes.set(normalizeName(concept.name), node.node.id);
    connect(recordNode.node.id, node.node.id, relationForRecord(record.kind), concept.description);
  }
  for (const technique of record.enrichment?.techniques ?? []) {
    const node = buildDerivedNode("technique", technique.name, technique.description, record, technique.confidence, technique.phase);
    upsertNode(node.node, node.body);
    namedNodes.set(normalizeName(technique.name), node.node.id);
    connect(recordNode.node.id, node.node.id, relationForRecord(record.kind), technique.description);
  }

  for (const relation of record.enrichment?.relations ?? []) {
    const sourceId = namedNodes.get(normalizeName(relation.source));
    const targetId = namedNodes.get(normalizeName(relation.target));
    if (sourceId && targetId && sourceId !== targetId) connect(sourceId, targetId, relation.type, relation.description);
  }
}

graph.nodes = [...nodes.values()];
graph.edges = [...edges.values()];
graph.rawCounts = { nodes: graph.nodes.length, relations: graph.edges.length };
const core = graph.nodes.filter((node) => node.publishState === "core").length;
const support = graph.nodes.filter((node) => node.publishState === "support").length;
const evidence = graph.nodes.filter((node) => node.publishState === "evidence").length;
graph.quality = {
  ...(graph.quality ?? {}),
  states: {
    ...(graph.quality?.states ?? {}),
    core,
    support,
    evidence,
    quarantined: graph.quality?.states?.quarantined ?? 0,
  },
};

for (const id of emittedNodeIds) {
  const owners = new Set(manifest.node_owners[id] ?? []);
  owners.add(sourceKey);
  manifest.node_owners[id] = [...owners];
}
for (const id of emittedEdgeIds) {
  const owners = new Set(manifest.edge_owners[id] ?? []);
  owners.add(sourceKey);
  manifest.edge_owners[id] = [...owners];
}
manifest.sources[sourceKey] = {
  input: path.relative(process.cwd(), input),
  input_sha256: sha256(fs.readFileSync(input)),
  node_ids: [...emittedNodeIds],
  edge_ids: [...emittedEdgeIds],
  compiled_at: new Date().toISOString(),
};

fs.writeFileSync(graphPath, `${JSON.stringify(sanitize(graph), null, 2)}\n`);
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Compiled ${canonical.length} canonical records into ${emittedNodeIds.size} nodes and ${emittedEdgeIds.size} edges`);

function upsertNode(node, body) {
  const existing = nodes.get(node.id);
  nodes.set(node.id, existing ? { ...existing, ...node } : node);
  graph.contents[node.id] = body;
  emittedNodeIds.add(node.id);
}

function connect(source, target, type, rationale) {
  const id = `ingest-edge:${sha256(`${source}:${target}:${type}`).slice(0, 22)}`;
  const edge = { id, source, target, type: type || "related_to", origin: "universal-ingest", rationale: rationale || "Derived from evidence-grounded semantic enrichment." };
  edges.set(id, edge);
  emittedEdgeIds.add(id);
}

function buildRecordNode(record) {
  const type = nodeTypeFor(record.kind);
  const id = `${type}:${sha256(record.id).slice(0, 22)}`;
  const summary = record.enrichment?.summary || normalizeWhitespace(record.content).slice(0, 420);
  const node = sanitize({
    id,
    type,
    publishState: record.publish_state ?? "core",
    evidenceId: `ING-${sha256(record.id).slice(0, 12).toUpperCase()}`,
    sourceClass: "universal-ingest",
    sourceHash: record.source?.record_sha256 ?? sha256(record.content).slice(0, 16),
    label: record.title,
    name: record.title,
    summary,
    description: summary,
    category: record.category,
    topic: record.kind,
    tags: [...new Set([record.kind, record.category, record.language, ...(record.tags ?? []), ...(record.enrichment?.tags ?? [])])].filter(Boolean).slice(0, 24),
    mitre: verifiedMitreIds(record.enrichment?.mitre_candidates ?? []),
    mitre_candidates: record.enrichment?.mitre_candidates ?? [],
    confidence: record.routing?.router_confidence,
    galaxyId: galaxyFor(record.kind),
    code_artifact: record.kind === "source_code" ? {
      file_name: record.facets?.code_file_name ?? record.title,
      language: record.language,
      relative_path: record.facets?.code_relative_path ?? null,
      raw_code: record.content,
    } : null,
    enrichment_status: record.enrichment?.status ?? "degraded",
    enrichment_model: record.enrichment?.model ?? null,
  });
  return { node, body: buildBody(record) };
}

function buildDerivedNode(type, name, description, record, confidence, topic = null) {
  const canonicalName = normalizeName(name);
  const id = `${type}:${sha256(canonicalName).slice(0, 22)}`;
  const evidenceId = `SYN-${sha256(`${type}:${canonicalName}`).slice(0, 12).toUpperCase()}`;
  const node = sanitize({
    id,
    type,
    publishState: "support",
    evidenceId,
    sourceClass: "model-inferred-grounded",
    sourceHash: sha256(`${record.id}:${canonicalName}`).slice(0, 16),
    label: name,
    name,
    summary: description,
    description,
    category: topic || record.category,
    topic: topic || type,
    tags: [type, record.category].filter(Boolean),
    confidence,
  });
  const body = `## ${name}\n\n${description}\n\n---\n\nDerived automatically from evidence-grounded enrichment of **${record.title}**.`;
  return { node, body };
}

function buildBody(record) {
  const lines = [`## ${record.title}`, "", record.enrichment?.abstract || record.enrichment?.summary || "", "", "---", "", record.content];
  const concepts = record.enrichment?.concepts ?? [];
  const techniques = record.enrichment?.techniques ?? [];
  const entities = record.enrichment?.entities ?? [];
  if (concepts.length) lines.push("", "## Concepts", "", ...concepts.map((item) => `- **${item.name}:** ${item.description}`));
  if (techniques.length) lines.push("", "## Techniques", "", ...techniques.map((item) => `- **${item.name}:** ${item.description}`));
  if (entities.length) lines.push("", "## Explicit entities", "", ...entities.map((item) => `- ${item.name} (${item.type})`));
  lines.push("", "---", "", `*Automatic ingestion status: ${record.enrichment?.status ?? "degraded"}*`);
  return sanitize(lines.join("\n"));
}

function normalizeName(value) {
  return String(value ?? "")
    .normalize("NFKD")
    .toLowerCase()
    .split("").map((char) => {
      const code = char.codePointAt(0);
      const alphaNumeric = (code >= 48 && code <= 57) || (code >= 97 && code <= 122);
      return alphaNumeric ? char : " ";
    }).join("")
    .split(" ").filter(Boolean).join(" ");
}

function nodeTypeFor(kind) {
  return ({
    source_code: "source",
    documentation: "documentation",
    training_qa: "tradecraft_qa",
    writeup: "playbook",
    playbook: "playbook",
    note: "concept",
    conversation: "tradecraft_qa",
    dataset_record: "source",
    unknown: "source",
  })[kind] ?? "source";
}

function galaxyFor(kind) {
  return ({
    source_code: "sources",
    documentation: "sources",
    training_qa: "tradecraft_qa",
    writeup: "techniques",
    playbook: "techniques",
    note: "evidence",
    conversation: "tradecraft_qa",
    dataset_record: "sources",
    unknown: "sources",
  })[kind] ?? "sources";
}

function relationForRecord(kind) {
  if (kind === "source_code") return "implements";
  if (kind === "documentation" || kind === "writeup" || kind === "playbook") return "documents";
  return "related_to";
}

function verifiedMitreIds(candidates) {
  const catalogPath = path.resolve("data/reference/mitre-techniques.json");
  if (!fs.existsSync(catalogPath)) return [];
  try {
    const catalog = JSON.parse(fs.readFileSync(catalogPath, "utf8"));
    const known = new Set(Array.isArray(catalog) ? catalog.map(String) : Object.keys(catalog));
    return candidates.map((item) => String(item.id)).filter((id) => known.has(id));
  } catch {
    return [];
  }
}

function edgeKey(edge) {
  return `${edge.source}:${edge.target}:${edge.type ?? "related_to"}`;
}
