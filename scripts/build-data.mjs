import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const SOURCE = path.resolve("data/source/public-graph.json");
const PUBLIC = path.resolve("public/data");
const GENERATED = path.resolve("src/generated");
const MODEL = "onnx-community/all-MiniLM-L6-v2-ONNX";
const REVISION = "aff7a1dc4e8a1ea593e6ea21e95c22ef0a25966f";
const NEIGHBORS = 8;
const SHARDS = 64;

const GALAXY_DEFS = [
  ["techniques", "Techniques & Playbooks", "Operator techniques and field-ready playbooks.", "#ff355d"],
  ["internals", "Windows Internals & Concepts", "Structures, primitives, APIs, and system behavior.", "#9d7bff"],
  ["defenses", "Detections & Defenses", "Telemetry, detections, defensive controls, and countermeasures.", "#38d6ff"],
  ["chains", "Operational Chains", "Sequential workflows and capability dependencies.", "#ff9f43"],
  ["atlas", "Atlas Evidence", "Research evidence and source-grounded observations.", "#ff6b4a"],
  ["sources", "Source & Documentation", "Documentation, source maps, and supporting references.", "#7da6ff"],
  ["gaps", "Research Gaps", "Open questions, proposals, and disconnected evidence.", "#ffd166"],
  ["architecture", "Architecture & Patterns", "System architecture, reusable patterns, and maps.", "#d98cff"]
];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const shortHash = (value, length = 10) => sha256(value).slice(0, length);
const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
const cleanText = (value = "") => String(value).replace(/---[\s\S]*?---/, " ").replace(/[`#>*_|\[\]()]/g, " ").replace(/\s+/g, " ").trim();
const sentence = (value, length = 240) => cleanText(value).slice(0, length).replace(/\s+\S*$/, "");
const slugify = (value) => String(value).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 72);

function galaxyFor(node) {
  const type = node.type;
  if (["technique", "playbook"].includes(type)) return "techniques";
  if (type === "concept") return "internals";
  if (type === "detection") return "defenses";
  if (type === "chain") return "chains";
  if (type === "atlas_reference") return "atlas";
  if (["source", "source-extract", "documentation", "reference"].includes(type)) return "sources";
  if (type === "lgtm_note") return "gaps";
  return "architecture";
}

function routeFor(kind, slug) {
  const roots = {
    technique: "techniques",
    playbook: "techniques",
    concept: "concepts",
    detection: "detections",
    chain: "chains",
    atlas_reference: "atlas"
  };
  return `/${roots[kind] ?? "entities"}/${slug}/`;
}

function atlasTitle(node, body) {
  const heading = body.match(/^#{1,3}\s+(.+)$/m)?.[1];
  const concept = heading || node.summary || node.key_cues?.slice(0, 2).join(" · ") || node.topic || "Evidence";
  const topic = String(node.topic || node.category || "research").replace(/[-_]/g, " ");
  return `${sentence(concept, 78)} · ${topic} · ${node.sourceLabel} · ${shortHash(node.id, 6)}`;
}

if (!fs.existsSync(SOURCE)) throw new Error(`Missing ${SOURCE}. Run npm run data:import first.`);
const source = JSON.parse(fs.readFileSync(SOURCE, "utf8"));
if (source.nodes.length !== 5608) throw new Error(`Expected 5608 nodes, found ${source.nodes.length}`);

fs.mkdirSync(PUBLIC, { recursive: true });
fs.mkdirSync(GENERATED, { recursive: true });

const edgeDegree = new Map();
for (const edge of source.edges) {
  edgeDegree.set(edge.source, (edgeDegree.get(edge.source) || 0) + 1);
  edgeDegree.set(edge.target, (edgeDegree.get(edge.target) || 0) + 1);
}

const seenSlugs = new Set();
const bodies = {};
const entities = source.nodes.map((node) => {
  const body = source.contents[node.id] || node.description || node.summary || "";
  const title = node.type === "atlas_reference" ? atlasTitle(node, body) : String(node.label || node.name || node.id);
  let slug = `${slugify(title) || "entity"}-${shortHash(node.id, 7)}`;
  while (seenSlugs.has(slug)) slug = `${slug}-${shortHash(slug, 3)}`;
  seenSlugs.add(slug);
  const bodyRef = sha256(body);
  bodies[bodyRef] ??= body;
  const galaxyId = galaxyFor(node);
  const tags = [...new Set([...(node.tags || []), ...(node.key_cues || []), ...(node.techniques || [])].map(String))];
  const mitre = Array.isArray(node.mitre) ? node.mitre : node.mitre ? [String(node.mitre)] : [];
  return {
    id: node.id,
    slug,
    route: routeFor(node.type, slug),
    title,
    kind: node.type,
    category: node.category || "uncategorized",
    galaxyId,
    subgalaxy: node.topic || node.category || node.type,
    summary: sentence(node.summary || node.description || body, 280) || `Research entity ${node.id}.`,
    tags,
    tier: node.tier,
    confidence: node.confidence,
    mitre,
    bodyRef,
    bodyShard: Number.parseInt(bodyRef.slice(0, 2), 16) % SHARDS,
    degree: edgeDegree.get(node.id) || 0,
    provenance: [{ sourceKey: node.sourceKey, sourceLabel: node.sourceLabel, sourceHash: node.sourceHash }]
  };
});

const entityById = new Map(entities.map((entity) => [entity.id, entity]));
const curated = source.edges.map((edge, index) => ({
  id: `curated:${index}:${shortHash(`${edge.source}:${edge.target}:${edge.type}`)}`,
  source: edge.source,
  target: edge.target,
  type: edge.type || "related_to",
  origin: "curated",
  rationale: edge.rationale || "Preserved from the owner-authorized source graph."
}));

const membership = entities.map((entity) => ({
  id: `membership:${entity.id}`,
  source: entity.id,
  target: `galaxy:${entity.galaxyId}`,
  type: "member_of",
  origin: "membership",
  rationale: `Structural placement in ${GALAXY_DEFS.find(([id]) => id === entity.galaxyId)[1]}.`
}));

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
  if (engine === "lexical") return { vectors: texts.map(lexicalVector), engine: "lexical-dev" };
  const { env, pipeline } = await import("@huggingface/transformers");
  env.cacheDir = path.resolve(process.env.HUGIN_MODEL_CACHE || ".hf-cache");
  env.useFSCache = true;
  env.allowRemoteModels = true;
  const extractor = await pipeline("feature-extraction", MODEL, { revision: REVISION, dtype: "q4" });
  const vectors = [];
  try {
    for (let start = 0; start < texts.length; start += 64) {
      const result = await extractor(texts.slice(start, start + 64), { pooling: "mean", normalize: true });
      vectors.push(...result.tolist());
      console.log(`Embedded ${Math.min(start + 64, texts.length)}/${texts.length}`);
    }
  } finally {
    await extractor.dispose();
  }
  return { vectors, engine: MODEL };
}

const texts = entities.map(embeddingText);
const corpusHash = sha256(texts.join("\n"));
const embeddingCache = path.resolve(".cache", `embeddings-${corpusHash}-${shortHash(REVISION)}.json`);
let embeddings;
if (fs.existsSync(embeddingCache)) {
  embeddings = JSON.parse(fs.readFileSync(embeddingCache, "utf8"));
} else {
  embeddings = await createEmbeddings(texts);
  fs.mkdirSync(path.dirname(embeddingCache), { recursive: true });
  writeJson(embeddingCache, embeddings);
}

const buckets = new Map();
for (const entity of entities) {
  for (const key of [`g:${entity.galaxyId}`, `s:${entity.subgalaxy}`, ...entity.tags.slice(0, 10).map((tag) => `t:${tag.toLowerCase()}`)]) {
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(entity.id);
  }
}

const dot = (a, b) => {
  let value = 0;
  for (let index = 0; index < a.length; index += 1) value += a[index] * b[index];
  return value;
};
const indexById = new Map(entities.map((entity, index) => [entity.id, index]));
const similarity = [];
for (let index = 0; index < entities.length; index += 1) {
  const entity = entities[index];
  const candidateIds = new Set();
  const keys = [`s:${entity.subgalaxy}`, ...entity.tags.slice(0, 10).map((tag) => `t:${tag.toLowerCase()}`), `g:${entity.galaxyId}`];
  for (const key of keys) {
    for (const id of buckets.get(key) || []) {
      if (id !== entity.id) candidateIds.add(id);
      if (candidateIds.size >= 512) break;
    }
    if (candidateIds.size >= 512) break;
  }
  if (candidateIds.size < NEIGHBORS) {
    for (let offset = 1; candidateIds.size < NEIGHBORS; offset += 1) candidateIds.add(entities[(index + offset) % entities.length].id);
  }
  const ranked = [...candidateIds]
    .map((id) => ({ id, score: dot(embeddings.vectors[index], embeddings.vectors[indexById.get(id)]) }))
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
const entityGraphNodes = entities.map((entity, index) => {
  const galaxy = galaxyIndex.get(entity.galaxyId);
  const baseAngle = (Math.PI * 2 * galaxy) / GALAXY_DEFS.length;
  const localAngle = ((Number.parseInt(shortHash(entity.id, 8), 16) % 100000) / 100000) * Math.PI * 2;
  const radius = 55 + (Number.parseInt(shortHash(`${entity.id}:r`, 6), 16) % 180);
  const centerRadius = 430;
  return {
    id: entity.id,
    label: entity.title,
    kind: entity.kind,
    galaxyId: entity.galaxyId,
    category: entity.category,
    route: entity.route,
    x: Number((Math.cos(baseAngle) * centerRadius + Math.cos(localAngle) * radius).toFixed(3)),
    y: Number((Math.sin(baseAngle) * centerRadius + Math.sin(localAngle) * radius).toFixed(3)),
    size: Math.min(12, 2.2 + Math.log2(entity.degree + 1)),
    color: GALAXY_DEFS[galaxy][3]
  };
});

const galaxies = GALAXY_DEFS.map(([id, name, description, color]) => ({
  id,
  name,
  description,
  color,
  count: entities.filter((entity) => entity.galaxyId === id).length
}));
const galaxyNodes = galaxies.map((galaxy, index) => {
  const angle = (Math.PI * 2 * index) / galaxies.length;
  return {
    id: `galaxy:${galaxy.id}`,
    label: galaxy.name,
    kind: "galaxy",
    galaxyId: galaxy.id,
    category: "structure",
    route: `/explore/?galaxy=${galaxy.id}`,
    x: Number((Math.cos(angle) * 430).toFixed(3)),
    y: Number((Math.sin(angle) * 430).toFixed(3)),
    size: 18,
    color: galaxy.color,
    isGalaxy: true
  };
});
const graphNodes = [...entityGraphNodes, ...galaxyNodes];

const bodyShards = Array.from({ length: SHARDS }, () => ({}));
for (const [bodyRef, body] of Object.entries(bodies)) bodyShards[Number.parseInt(bodyRef.slice(0, 2), 16) % SHARDS][bodyRef] = body;

const assetPayloads = {
  catalog: entities,
  graph: { nodes: graphNodes, edges: curated },
  similarity,
  membership
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
  schemaVersion: "2.0.0",
  datasetVersion: `2.0.0+${source.sourceHash.slice(0, 12)}`,
  sourceHash: source.sourceHash,
  generatedAt: new Date().toISOString(),
  commit: process.env.GITHUB_SHA || "local",
  counts: {
    nodes: entities.length,
    curatedRelations: curated.length,
    membershipRelations: membership.length,
    similarityRelations: similarity.length,
    quarantinedRelations: source.quarantined.length,
    uniqueBodies: Object.keys(bodies).length,
    galaxies: galaxies.length
  },
  assets,
  similarityModel: `${embeddings.engine}:q4`,
  similarityRevision: REVISION,
  corpusHash
};
const manifestJson = JSON.stringify(manifest);
const manifestFile = `manifest.${shortHash(manifestJson)}.json`;
writeJson(path.join(PUBLIC, manifestFile), manifest);
writeJson(path.join(PUBLIC, "manifest.json"), manifest);

writeJson(path.join(GENERATED, "manifest.json"), manifest);
writeJson(path.join(GENERATED, "entities.json"), entities);
writeJson(path.join(GENERATED, "galaxies.json"), galaxies);
writeJson(path.join(GENERATED, "curated-relations.json"), curated);
writeJson(path.join(GENERATED, "bodies.json"), bodies);

console.log(JSON.stringify(manifest, null, 2));
