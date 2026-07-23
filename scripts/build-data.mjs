import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SOURCE = path.resolve("data/source/public-graph.json");
const PUBLIC = path.resolve("public/data");
const GENERATED = path.resolve("src/generated");
// This Transformers.js repository publishes the q8 `model_quantized.onnx`
// artifact. The newer onnx-community mirror currently exposes fp32/fp16/q4,
// but not q8, so it cannot satisfy HUGIN's pinned q8 build contract.
const MODEL = "Xenova/all-MiniLM-L6-v2";
const REVISION = "751bff37182d3f1213fa05d7196b954e230abad9";
const NEIGHBORS = 8;
const SHARDS = 64;

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

const GALAXY_DEFS = [
  ["techniques", "Techniques & Playbooks", "Operator techniques and field-ready playbooks.", "#d84a57"],
  ["internals", "Windows Internals & Concepts", "Structures, primitives, APIs, and system behavior.", "#8f73c9"],
  ["defenses", "Detections & Defenses", "Telemetry, detections, defensive controls, and countermeasures.", "#6b94b8"],
  ["chains", "Operational Chains", "Sequential workflows and capability dependencies.", "#bc8153"],
  ["evidence", "Evidence & Research Notes", "Curated synthesis, LGTM notes, and supporting observations.", "#b95f6b"],
  ["sources", "Source & Documentation", "Anonymous implementation sources and documentation.", "#6f7898"],
  ["gaps", "Research Gaps", "Open questions, proposals, and coverage gaps.", "#b89b5d"],
  ["architecture", "Architecture & Patterns", "System architecture, reusable patterns, and maps.", "#9b6ca8"]
];

const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const shortHash = (value, length = 10) => sha256(value).slice(0, length);
const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`);

function cleanText(value = "") {
  return String(value)
    .replace(/^---[\s\S]*?---/m, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/[`#>*_|\[\]()]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function sentence(value, length = 240) {
  const text = cleanText(value);
  if (text.length <= length) return text;
  return `${text.slice(0, length).replace(/\s+\S*$/, "")}…`;
}

function slugify(value) {
  return String(value)
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 72);
}

function humanize(value) {
  return String(value || "")
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .trim();
}

function galaxyFor(node) {
  if (["technique", "playbook"].includes(node.type)) return "techniques";
  if (node.type === "concept") return "internals";
  if (node.type === "detection") return "defenses";
  if (node.type === "chain") return "chains";
  if (node.type === "lgtm_note") {
    if (/gap|proposed|emerging/i.test(`${node.kind || ""} ${node.category || ""}`)) return "gaps";
    return "evidence";
  }
  if (["source", "source-extract", "documentation", "reference"].includes(node.type)) return "sources";
  return "architecture";
}

function routeFor(kind, slug) {
  const roots = {
    technique: "techniques",
    playbook: "techniques",
    concept: "concepts",
    detection: "detections",
    chain: "chains"
  };
  return `/${roots[kind] ?? "entities"}/${slug}/`;
}

function evidenceDomain(node) {
  const topic = humanize(node.topic || "");
  if (/process|thread|windows|exploit|loader|injection|syscall/i.test(topic)) return "Windows Internals";
  if (/detect|defen|telemetry|sysmon|etw/i.test(topic)) return "Detection";
  if (/persist/i.test(topic)) return "Persistence";
  if (/network|c2|command/i.test(topic)) return "Network Operations";
  return topic || "Technical Research";
}

function evidenceTitle(node) {
  const generic = /training|research|source|corpus|course|windows tool development/i;
  const cue = (node.key_cues || [])
    .map((value) => sentence(value, 42))
    .find((value) => value && !generic.test(value));
  const domain = evidenceDomain(node);
  if (!cue || cue.toLowerCase() === domain.toLowerCase()) return `Evidence · ${domain}`;
  return `Evidence · ${domain} · ${cue}`;
}

function evidenceScore(node, summary) {
  const text = `${summary} ${(node.key_cues || []).join(" ")}`;
  let score = Math.min(4, Math.floor(summary.length / 90));
  score += Math.min(3, (node.key_cues || []).length);
  if (/\b(?:API|ETW|Sysmon|event|structure|memory|registry|thread|process|token|loader|callback|telemetry)\b/i.test(text)) score += 3;
  if (/\b(?:requires|enables|detects|because|trade-off|limitation|signal)\b/i.test(text)) score += 2;
  return score;
}

if (!fs.existsSync(SOURCE)) {
  throw new Error(`Missing ${SOURCE}. Run npm run data:import first.`);
}

const source = JSON.parse(fs.readFileSync(SOURCE, "utf8"));
if (source.rawCounts?.nodes !== 5608) {
  throw new Error(`Expected a 5,608-record owner import, found ${source.rawCounts?.nodes ?? "unknown"}.`);
}

for (const target of [PUBLIC, GENERATED]) {
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
}

const sourceNodeById = new Map(source.nodes.map((node) => [node.id, node]));
const entitySourceNodes = source.nodes.filter((node) => ["core", "support"].includes(node.publishState));
const evidenceSourceNodes = source.nodes.filter((node) => node.publishState === "evidence");
const entityIds = new Set(entitySourceNodes.map((node) => node.id));
const evidenceIds = new Set(evidenceSourceNodes.map((node) => node.id));

const graphSourceEdges = source.edges.filter((edge) => entityIds.has(edge.source) && entityIds.has(edge.target));
const evidenceSourceEdges = source.edges.filter((edge) =>
  (evidenceIds.has(edge.source) && entityIds.has(edge.target)) ||
  (entityIds.has(edge.source) && evidenceIds.has(edge.target))
);

const edgeDegree = new Map();
for (const edge of graphSourceEdges) {
  edgeDegree.set(edge.source, (edgeDegree.get(edge.source) || 0) + 1);
  edgeDegree.set(edge.target, (edgeDegree.get(edge.target) || 0) + 1);
}

const seenSlugs = new Set();
const bodies = {};
const entities = entitySourceNodes.map((node) => {
  const body = source.contents[node.id] || node.description || node.summary || "";
  const title = sentence(node.label || node.name || node.summary || node.id, 116);
  let slug = `${slugify(title) || "entity"}-${shortHash(node.id, 7)}`;
  while (seenSlugs.has(slug)) slug = `${slug}-${shortHash(slug, 3)}`;
  seenSlugs.add(slug);

  const bodyRef = sha256(body);
  bodies[bodyRef] ??= body;
  const galaxyId = galaxyFor(node);
  const tags = [...new Set(
    [...(node.tags || []), ...(node.key_cues || []), ...(node.techniques || [])]
      .map((value) => sentence(value, 48))
      .filter(Boolean)
  )].slice(0, 24);
  const mitre = Array.isArray(node.mitre) ? node.mitre.map(String) : node.mitre ? [String(node.mitre)] : [];

  return {
    id: node.id,
    slug,
    route: routeFor(node.type, slug),
    title,
    kind: node.type,
    category: node.category || "uncategorized",
    galaxyId,
    subgalaxy: node.topic || node.category || node.type,
    summary: sentence(node.summary || node.description || body, 300) || `Research entity ${node.evidenceId}.`,
    tags,
    tier: node.tier,
    confidence: node.confidence,
    mitre,
    bodyRef,
    bodyShard: Number.parseInt(bodyRef.slice(0, 2), 16) % SHARDS,
    degree: edgeDegree.get(node.id) || 0,
    publishState: node.publishState,
    evidenceId: node.evidenceId,
    provenance: [{
      evidenceId: node.evidenceId,
      sourceClass: node.sourceClass,
      sourceHash: node.sourceHash
    }]
  };
});

const entityById = new Map(entities.map((entity) => [entity.id, entity]));

const evidenceLinkMap = new Map();
for (const edge of evidenceSourceEdges) {
  const evidenceId = evidenceIds.has(edge.source) ? edge.source : edge.target;
  const entityId = entityIds.has(edge.source) ? edge.source : edge.target;
  if (!evidenceLinkMap.has(evidenceId)) evidenceLinkMap.set(evidenceId, []);
  evidenceLinkMap.get(evidenceId).push(entityId);
}

const evidence = evidenceSourceNodes.map((node) => {
  const body = source.contents[node.id] || node.description || node.summary || "";
  const bodyRef = sha256(body);
  bodies[bodyRef] ??= body;
  const summary = sentence(node.summary || node.description || body, 320);
  return {
    id: node.id,
    evidenceId: node.evidenceId,
    title: evidenceTitle(node),
    topic: humanize(node.topic || "technical-research"),
    summary,
    keyCues: (node.key_cues || []).map((value) => sentence(value, 48)).filter(Boolean).slice(0, 8),
    relatedEntityIds: [...new Set(evidenceLinkMap.get(node.id) || [])],
    bodyRef,
    bodyShard: Number.parseInt(bodyRef.slice(0, 2), 16) % SHARDS,
    qualityScore: evidenceScore(node, summary)
  };
}).sort((a, b) => b.qualityScore - a.qualityScore || a.id.localeCompare(b.id));

const curated = graphSourceEdges.map((edge, index) => ({
  id: `curated:${index}:${shortHash(`${edge.source}:${edge.target}:${edge.type}`)}`,
  source: edge.source,
  target: edge.target,
  type: edge.type || "related_to",
  origin: "curated",
  rationale: edge.rationale || "Preserved from the owner-authorized knowledge graph."
}));

const membership = entities.map((entity) => ({
  id: `membership:${entity.id}`,
  source: entity.id,
  target: `galaxy:${entity.galaxyId}`,
  type: "member_of",
  origin: "membership",
  rationale: `Structural placement in ${GALAXY_DEFS.find(([id]) => id === entity.galaxyId)[1]}.`
}));

const embeddingEntities = entities.filter((entity) => entity.publishState === "core");
const embeddingText = (entity) => [
  entity.title,
  entity.summary,
  entity.tags.slice(0, 16).join(" "),
  entity.category,
  entity.subgalaxy,
  entity.mitre.join(" ")
].filter(Boolean).join(". ").slice(0, 1400);

function lexicalVector(text) {
  const vector = new Float32Array(256);
  for (const token of text.toLowerCase().match(/[a-z0-9_-]{2,}/g) || []) {
    vector[Number.parseInt(shortHash(token, 8), 16) % vector.length] += 1;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0)) || 1;
  return Array.from(vector, (value) => value / norm);
}

async function createEmbeddings(texts) {
  const engine = process.env.HUGIN_SIMILARITY_ENGINE || "transformers";
  if (engine === "lexical") {
    return { vectors: texts.map(lexicalVector), engine: "lexical-local" };
  }

  const { env, pipeline } = await import("@huggingface/transformers");
  env.cacheDir = path.resolve(process.env.HUGIN_MODEL_CACHE || ".hf-cache");
  env.useFSCache = true;
  env.allowRemoteModels = true;
  const extractor = await pipeline("feature-extraction", MODEL, {
    revision: REVISION,
    dtype: "q8"
  });
  const vectors = [];
  try {
    for (let start = 0; start < texts.length; start += 64) {
      const result = await extractor(texts.slice(start, start + 64), {
        pooling: "mean",
        normalize: true
      });
      vectors.push(...result.tolist());
      console.log(`Embedded ${Math.min(start + 64, texts.length)}/${texts.length}`);
    }
  } finally {
    await extractor.dispose();
  }
  return { vectors, engine: MODEL };
}

const texts = embeddingEntities.map(embeddingText);
const corpusHash = sha256(texts.join("\n"));
const embeddingCache = path.resolve(".cache", `embeddings-${corpusHash}-${shortHash(REVISION)}-q8.json`);
let embeddings;
if (fs.existsSync(embeddingCache)) {
  embeddings = JSON.parse(fs.readFileSync(embeddingCache, "utf8"));
} else {
  embeddings = await createEmbeddings(texts);
  fs.mkdirSync(path.dirname(embeddingCache), { recursive: true });
  writeJson(embeddingCache, embeddings);
}

const buckets = new Map();
for (const entity of embeddingEntities) {
  for (const key of [
    `g:${entity.galaxyId}`,
    `s:${entity.subgalaxy}`,
    ...entity.tags.slice(0, 10).map((tag) => `t:${tag.toLowerCase()}`)
  ]) {
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(entity.id);
  }
}

const dot = (a, b) => {
  let value = 0;
  for (let index = 0; index < a.length; index += 1) value += a[index] * b[index];
  return value;
};
const indexById = new Map(embeddingEntities.map((entity, index) => [entity.id, index]));
const similarity = [];

for (let index = 0; index < embeddingEntities.length; index += 1) {
  const entity = embeddingEntities[index];
  const candidateIds = new Set();
  const keys = [
    `s:${entity.subgalaxy}`,
    ...entity.tags.slice(0, 10).map((tag) => `t:${tag.toLowerCase()}`),
    `g:${entity.galaxyId}`
  ];
  for (const key of keys) {
    for (const id of buckets.get(key) || []) {
      if (id !== entity.id) candidateIds.add(id);
      if (candidateIds.size >= 512) break;
    }
    if (candidateIds.size >= 512) break;
  }
  for (let offset = 1; candidateIds.size < NEIGHBORS; offset += 1) {
    candidateIds.add(embeddingEntities[(index + offset) % embeddingEntities.length].id);
  }

  const ranked = [...candidateIds]
    .map((id) => ({
      id,
      score: dot(embeddings.vectors[index], embeddings.vectors[indexById.get(id)])
    }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, NEIGHBORS);

  ranked.forEach((neighbor, rank) => similarity.push({
    id: `similarity:${entity.id}:${neighbor.id}`,
    source: entity.id,
    target: neighbor.id,
    type: "similar_to",
    origin: "similarity",
    rationale: "Build-generated semantic similarity; exploratory, not curated.",
    score: Number(neighbor.score.toFixed(6)),
    rank: rank + 1,
    modelRevision: REVISION,
    corpusHash
  }));
}

const galaxyIndex = new Map(GALAXY_DEFS.map((definition, index) => [definition[0], index]));
const galaxies = GALAXY_DEFS.map(([id, name, description, color]) => ({
  id,
  name,
  description,
  color,
  count: entities.filter((entity) => entity.galaxyId === id && entity.publishState === "core").length,
  supportCount: entities.filter((entity) => entity.galaxyId === id && entity.publishState === "support").length
}));

const entityGraphNodes = entities.map((entity) => {
  const galaxy = galaxyIndex.get(entity.galaxyId);
  const baseAngle = (Math.PI * 2 * galaxy) / GALAXY_DEFS.length;
  const localAngle = ((Number.parseInt(shortHash(entity.id, 8), 16) % 100000) / 100000) * Math.PI * 2;
  const radius = 52 + (Number.parseInt(shortHash(`${entity.id}:r`, 6), 16) % 176);
  const centerRadius = 455;
  return {
    id: entity.id,
    label: entity.title,
    kind: entity.kind,
    galaxyId: entity.galaxyId,
    category: entity.category,
    route: entity.route,
    summary: entity.summary,
    scope: entity.publishState,
    degree: entity.degree,
    x: Number((Math.cos(baseAngle) * centerRadius + Math.cos(localAngle) * radius).toFixed(3)),
    y: Number((Math.sin(baseAngle) * centerRadius + Math.sin(localAngle) * radius).toFixed(3)),
    size: Math.min(11, 2.1 + Math.log2(entity.degree + 1)),
    color: GALAXY_DEFS[galaxy][3]
  };
});

const galaxyNodes = galaxies.map((galaxy, index) => {
  const angle = (Math.PI * 2 * index) / galaxies.length;
  return {
    id: `galaxy:${galaxy.id}`,
    label: galaxy.name,
    kind: "galaxy",
    galaxyId: galaxy.id,
    category: "structure",
    route: `/explore/?galaxy=${galaxy.id}`,
    summary: galaxy.description,
    scope: "structure",
    degree: galaxy.count,
    x: Number((Math.cos(angle) * 455).toFixed(3)),
    y: Number((Math.sin(angle) * 455).toFixed(3)),
    size: 17,
    color: galaxy.color,
    isGalaxy: true
  };
});

const graphNodes = [...entityGraphNodes, ...galaxyNodes];
const bodyShards = Array.from({ length: SHARDS }, () => ({}));
for (const [bodyRef, body] of Object.entries(bodies)) {
  bodyShards[Number.parseInt(bodyRef.slice(0, 2), 16) % SHARDS][bodyRef] = body;
}

const evidenceByEntity = {};
for (const item of evidence) {
  for (const entityId of item.relatedEntityIds) {
    evidenceByEntity[entityId] ??= [];
    evidenceByEntity[entityId].push(item.id);
  }
}

const assetPayloads = {
  catalog: entities,
  graph: { nodes: graphNodes, edges: curated },
  similarity,
  membership,
  evidence: {
    items: evidence.map(({ bodyRef, bodyShard, ...item }) => item),
    byEntity: evidenceByEntity
  },
  quality: {
    rawCounts: source.rawCounts,
    states: source.quality.states,
    quarantinedNodes: source.quality.quarantinedNodes,
    quarantinedRelations: source.quality.quarantinedRelations
  }
};

const assets = {};
for (const [name, payload] of Object.entries(assetPayloads)) {
  const json = JSON.stringify(payload);
  const file = `${name}.${shortHash(json)}.json`;
  fs.writeFileSync(path.join(PUBLIC, file), json);
  assets[name] = `/data/${file}`;
}

for (let index = 0; index < SHARDS; index += 1) {
  const json = JSON.stringify(bodyShards[index]);
  const file = `content-${String(index).padStart(2, "0")}.${shortHash(json)}.json`;
  fs.writeFileSync(path.join(PUBLIC, file), json);
  assets[`content-${index}`] = `/data/${file}`;
}

const manifest = {
  schemaVersion: "2.1.0",
  datasetVersion: `2.1.0+${source.sourceHash.slice(0, 12)}`,
  sourceHash: source.sourceHash,
  generatedAt: new Date().toISOString(),
  commit: process.env.GITHUB_SHA || "local",
  counts: {
    rawRecords: source.rawCounts.nodes,
    rawRelations: source.rawCounts.relations,
    coreEntities: embeddingEntities.length,
    supportEntities: entities.length - embeddingEntities.length,
    graphEntities: entities.length,
    evidenceRecords: evidence.length,
    quarantinedEvidence: source.quality.states.quarantined,
    curatedRelations: curated.length,
    evidenceLinks: evidenceSourceEdges.length,
    membershipRelations: membership.length,
    similarityRelations: similarity.length,
    quarantinedRelations: source.quality.quarantinedRelations.length,
    uniqueBodies: Object.keys(bodies).length,
    galaxies: galaxies.length
  },
  assets,
  similarityModel: `${embeddings.engine}:q8`,
  similarityRevision: REVISION,
  corpusHash
};

writeJson(path.join(PUBLIC, "manifest.json"), manifest);
writeJson(path.join(GENERATED, "manifest.json"), manifest);
writeJson(path.join(GENERATED, "entities.json"), entities);
writeJson(path.join(GENERATED, "galaxies.json"), galaxies);
writeJson(path.join(GENERATED, "curated-relations.json"), curated);
writeJson(path.join(GENERATED, "bodies.json"), bodies);
writeJson(path.join(GENERATED, "evidence.json"), evidence);
writeJson(path.join(GENERATED, "evidence-by-entity.json"), evidenceByEntity);
writeJson(path.join(GENERATED, "quality.json"), assetPayloads.quality);

console.log(JSON.stringify(manifest, null, 2));
