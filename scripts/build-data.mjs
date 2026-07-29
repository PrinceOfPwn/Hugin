import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  forceSimulation,
  forceManyBody,
  forceLink
} from "d3-force-3d";

const SOURCE = path.resolve("data/source/public-graph.json");
const MANIFEST_PATH = path.resolve("data/source/ingest-manifest.json");
const PUBLIC = path.resolve("public/data");
const GENERATED = path.resolve("src/generated");
// This Transformers.js repository publishes the q8 `model_quantized.onnx`
// artifact. The newer onnx-community mirror currently exposes fp32/fp16/q4,
// but not q8, so it cannot satisfy HUGIN's pinned q8 build contract.
const MODEL = "Xenova/all-MiniLM-L6-v2";
const REVISION = "751bff37182d3f1213fa05d7196b954e230abad9";
const NEIGHBORS = 8;
const SHARDS = 64;

const GALAXY_DEFS = [
  ["techniques", "Techniques & Playbooks", "Operator techniques and field-ready playbooks.", "#d84a57"],
  ["internals", "Windows Internals & Concepts", "Structures, primitives, APIs, and system behavior.", "#8f73c9"],
  ["defenses", "Detections & Defenses", "Telemetry, detections, defensive controls, and countermeasures.", "#6b94b8"],
  ["chains", "Operational Chains", "Sequential workflows and capability dependencies.", "#bc8153"],
  ["evidence", "Evidence & Research Notes", "Curated synthesis, LGTM notes, and supporting observations.", "#b95f6b"],
  ["sources", "Source & Documentation", "Anonymous implementation sources and documentation.", "#6f7898"],
  ["gaps", "Research Gaps", "Open questions, proposals, and coverage gaps.", "#b89b5d"],
  ["architecture", "Architecture & Patterns", "System architecture, reusable patterns, and maps.", "#9b6ca8"],
  ["tradecraft_qa", "Tradecraft Q&A", "Operator-curated technical research notes: scenarios, full analysis, and MITRE coverage.", "#00e5bf"]
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
  if (node.type === "tradecraft_qa" || node.galaxyId === "tradecraft_qa") return "tradecraft_qa";
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
    chain: "chains",
    tradecraft_qa: "tradecraft"
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
// Per-entity ingestion timestamps — populated by compile-canonical.mjs.
const ingestManifest = fs.existsSync(MANIFEST_PATH)
  ? JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"))
  : { node_history: {} };
const nodeHistory = ingestManifest.node_history ?? {};
if (!source.rawCounts?.nodes || source.rawCounts.nodes < 5000) {
  throw new Error(`Expected at least 5,000-record owner import, found ${source.rawCounts?.nodes ?? "unknown"}.`);
}

for (const target of [PUBLIC, GENERATED]) {
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
}

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
    code_artifact: node.code_artifact || null,
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

// Char-based node mass — derived from raw content length, capped at 20.
for (const entity of entities) {
  const rawContent = source.contents[entity.id];
  const contentLen = typeof rawContent === "string" ? rawContent.length : 0;
  const charCount = (entity.title?.length ?? 0)
    + (entity.summary?.length ?? 0)
    + contentLen
    + ((entity.tags ?? []).join(" ").length);
  entity.charCount = charCount;
  entity.mass = Math.min(20, 1 + Math.log2(charCount + 1));
  // Ingestion timestamps sourced from ingest-manifest.node_history.
  const hist = nodeHistory[entity.id];
  entity.firstSeenAt = hist?.firstSeenAt ?? null;
  entity.lastUpdatedAt = hist?.lastUpdatedAt ?? null;
}

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

const engine = process.env.HUGIN_SIMILARITY_ENGINE || "transformers";
const engineTag = engine === "lexical" ? "lexical" : "minilm-q8";

async function createEmbeddings(entitiesList) {
  const cacheFile = path.resolve(".cache", `vector-store-${engineTag}-${shortHash(REVISION)}.json`);
  fs.mkdirSync(path.dirname(cacheFile), { recursive: true });

  let vectorStore = {};
  if (fs.existsSync(cacheFile)) {
    try {
      vectorStore = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    } catch {
      vectorStore = {};
    }
  }

  const items = entitiesList.map((entity) => {
    const text = embeddingText(entity);
    const key = sha256(`${entity.id}:${text}`);
    return { entity, text, key };
  });

  const missing = items.filter((item) => !vectorStore[item.key]);

  if (missing.length > 0) {
    console.log(`Embedding ${missing.length} new/updated entities (${items.length - missing.length} cached)...`);

    if (engine === "lexical") {
      for (const item of missing) {
        vectorStore[item.key] = lexicalVector(item.text);
      }
    } else {
      const { env, pipeline } = await import("@huggingface/transformers");
      env.cacheDir = path.resolve(process.env.HUGIN_MODEL_CACHE || ".hf-cache");
      env.useFSCache = true;
      env.allowRemoteModels = true;
      const extractor = await pipeline("feature-extraction", MODEL, {
        revision: REVISION,
        dtype: "q8"
      });
      try {
        const batchSize = 64;
        for (let start = 0; start < missing.length; start += batchSize) {
          const batch = missing.slice(start, start + batchSize);
          const result = await extractor(batch.map((b) => b.text), {
            pooling: "mean",
            normalize: true
          });
          const list = result.tolist();
          batch.forEach((item, i) => {
            vectorStore[item.key] = list[i];
          });
          console.log(`Embedded ${Math.min(start + batchSize, missing.length)}/${missing.length} new items`);
        }
      } finally {
        await extractor.dispose();
      }
    }

    writeJson(cacheFile, vectorStore);
  } else {
    console.log(`All ${items.length} entity embeddings loaded from incremental cache.`);
  }

  const vectors = items.map((item) => vectorStore[item.key]);
  return { vectors, engine: engine === "lexical" ? "lexical-local" : MODEL };
}

const texts = embeddingEntities.map(embeddingText);
const corpusHash = sha256(texts.join("\n"));
const embeddings = await createEmbeddings(embeddingEntities);

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

// Per-entity similarity cache — keyed by entity id, tracks top-8 kNN plus the
// contentHash of the inputs that produced it. Independent from the embedding
// cache (which is keyed by embedding-text hash).
const similarityCacheFile = path.resolve(
  ".cache",
  `entity-similarity-${engineTag}-${shortHash(REVISION)}.json`
);
fs.mkdirSync(path.dirname(similarityCacheFile), { recursive: true });

// Outgoing curated edges per entity at similarity time. `curated` here still
// only contains graphSourceEdges — AI-inferred edges are merged later.
const outgoingByEntity = new Map();
for (const edge of curated) {
  if (!outgoingByEntity.has(edge.source)) outgoingByEntity.set(edge.source, []);
  outgoingByEntity.get(edge.source).push(`${edge.type}:${edge.target}`);
}

const contentHashInputFor = (entity) => {
  const tagsSorted = [...(entity.tags || [])].sort();
  const outgoingSorted = [...(outgoingByEntity.get(entity.id) || [])].sort();
  const label = entity.label ?? entity.title ?? "";
  const summary = entity.summary ?? "";
  return `${entity.id}|${label}|${summary}|${tagsSorted.join(",")}|${outgoingSorted.join(",")}`;
};

const currentContentHashes = new Map(
  embeddingEntities.map((e) => [e.id, sha256(contentHashInputFor(e))])
);
const corpusSignature = sha256([...currentContentHashes.keys()].sort().join(","));

let priorCache = null;
if (fs.existsSync(similarityCacheFile)) {
  try {
    const raw = JSON.parse(fs.readFileSync(similarityCacheFile, "utf8"));
    if (raw && raw.modelRevision === REVISION) priorCache = raw;
  } catch {
    priorCache = null;
  }
}

const priorById = priorCache?.byId ?? {};
const priorIds = new Set(Object.keys(priorById));
const currentIds = new Set(currentContentHashes.keys());

// Safety valve: if >10% of ids added or removed vs prior corpus, full recompute.
let fullRecompute = !priorCache;
if (priorCache) {
  let added = 0;
  let removed = 0;
  for (const id of currentIds) if (!priorIds.has(id)) added += 1;
  for (const id of priorIds) if (!currentIds.has(id)) removed += 1;
  const denom = Math.max(1, priorIds.size);
  if ((added + removed) / denom > 0.10) fullRecompute = true;
}

const changedIds = new Set();
if (priorCache) {
  for (const [id, hash] of currentContentHashes) {
    if (priorById[id]?.contentHash !== hash) changedIds.add(id);
  }
}
const removedIds = new Set();
if (priorCache) {
  for (const id of priorIds) if (!currentIds.has(id)) removedIds.add(id);
}

const invalidatedIds = new Set();
if (fullRecompute) {
  for (const id of currentIds) invalidatedIds.add(id);
} else {
  for (const id of changedIds) invalidatedIds.add(id);
  // Dependency inversion: any entity whose cached neighborhood contained a
  // changed or removed id must be recomputed even if its own content is stable.
  for (const [id, entry] of Object.entries(priorById)) {
    if (!currentIds.has(id) || invalidatedIds.has(id)) continue;
    if ((entry.top || []).some((n) => changedIds.has(n.id) || removedIds.has(n.id))) {
      invalidatedIds.add(id);
    }
  }
}

const newByIdCache = {};
let reusedCount = 0;

for (let index = 0; index < embeddingEntities.length; index += 1) {
  const entity = embeddingEntities[index];
  const contentHash = currentContentHashes.get(entity.id);
  let top;

  if (!invalidatedIds.has(entity.id) && priorById[entity.id]) {
    top = priorById[entity.id].top;
    reusedCount += 1;
  } else {
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

    top = ranked.map((neighbor, rank) => ({
      id: neighbor.id,
      score: Number(neighbor.score.toFixed(6)),
      rank: rank + 1
    }));
  }

  newByIdCache[entity.id] = { contentHash, top };

  top.forEach((neighbor, rank) => similarity.push({
    id: `similarity:${entity.id}:${neighbor.id}`,
    source: entity.id,
    target: neighbor.id,
    type: "similar_to",
    origin: "similarity",
    rationale: "Build-generated semantic similarity; exploratory, not curated.",
    score: neighbor.score,
    rank: neighbor.rank ?? (rank + 1),
    modelRevision: REVISION,
    corpusHash
  }));
}

writeJson(similarityCacheFile, {
  modelRevision: REVISION,
  engineTag,
  corpusSignature,
  byId: newByIdCache
});

console.log(
  `similarity: ${changedIds.size} changed, ${invalidatedIds.size} invalidated, ${reusedCount} reused of ${embeddingEntities.length} total`
);

// ─── AI enrichment merge + bridge_score ──────────────────────────────────────
const ENRICHED_DIR   = path.resolve("data/enriched/entities");
const TYPED_REL_FILE = path.resolve("data/enriched/relations/typed.jsonl");

// 1a. Merge per-entity AI enrichment (namespaced under _ai to never overwrite)
let aiEnrichedCount = 0;
if (fs.existsSync(ENRICHED_DIR)) {
  for (const entity of entities) {
    const p = path.join(ENRICHED_DIR, `${entity.id}.json`);
    if (!fs.existsSync(p)) continue;
    try {
      const ai = JSON.parse(fs.readFileSync(p, "utf8"));
      entity._ai = {
        summary:         ai.summary,
        mitre:           ai.mitre,
        apis:            ai.apis,
        iocs:            ai.iocs,
        tags:            ai.tags,
        chains_with:     ai.chains_with,
        alternatives:    ai.alternatives,
        counters:        ai.counters,
        stealth:         ai.stealth,
        complexity:      ai.complexity,
        os_requirements: ai.os_requirements,
        confidence:      ai.confidence,
        model:           ai._model,
        enrichedAt:      ai._at,
      };
      aiEnrichedCount++;
    } catch (err) {
      console.warn(`enrich merge: skip ${entity.id} — ${err.message}`);
    }
  }
  console.log(`AI enrichment merged into ${aiEnrichedCount}/${entities.length} entities`);
}

// 1b. Promote high-confidence typed relations to curated-like edges.
let inferredEdgesAdded = 0;
if (fs.existsSync(TYPED_REL_FILE)) {
  const entityIds = new Set(entities.map((e) => e.id));
  const existingEdge = new Set(curated.map((r) => `${r.source}|${r.target}|${r.type}`));

  const lines = fs.readFileSync(TYPED_REL_FILE, "utf8").split("\n").filter(Boolean);
  for (const line of lines) {
    let t;
    try { t = JSON.parse(line); } catch { continue; }
    if (!t || t.type === "none" || t.type === "related") continue;
    if (!Number.isInteger(t.confidence) || t.confidence < 4) continue;
    if (!entityIds.has(t.src) || !entityIds.has(t.tgt))      continue;

    const src = t.reverse ? t.tgt : t.src;
    const tgt = t.reverse ? t.src : t.tgt;
    const key = `${src}|${tgt}|${t.type}`;
    if (existingEdge.has(key)) continue;
    existingEdge.add(key);

    curated.push({
      id: `inferred:${src}:${tgt}:${t.type}`,
      source: src,
      target: tgt,
      type: t.type,
      origin: "inferred",
      rationale: t.rationale,
      confidence: t.confidence,
      modelRevision: t._model,
      similarityAtInference: t.similarity,
    });
    inferredEdgesAdded++;
  }
  console.log(`Inferred edges promoted to curated: ${inferredEdgesAdded}`);
}

// 1c. Recompute degree to include inferred edges.
{
  const deg = new Map();
  for (const r of curated) {
    deg.set(r.source, (deg.get(r.source) || 0) + 1);
    deg.set(r.target, (deg.get(r.target) || 0) + 1);
  }
  for (const entity of entities) entity.degree = deg.get(entity.id) ?? 0;
}

// 1d. Bridge score — emergent multi-domain concepts.
const entityGalaxyMap = new Map(entities.map((e) => [e.id, e.galaxyId]));
const nGalaxies = GALAXY_DEFS.length || 1;
const denomForeign = Math.max(1, nGalaxies - 1);

const bridgeNeighborBag = new Map();
const bumpBridge = (id, gid) => {
  if (!bridgeNeighborBag.has(id)) bridgeNeighborBag.set(id, {});
  const bag = bridgeNeighborBag.get(id);
  bag[gid] = (bag[gid] || 0) + 1;
};
for (const r of curated) {
  const sg = entityGalaxyMap.get(r.source);
  const tg = entityGalaxyMap.get(r.target);
  if (sg && tg) { bumpBridge(r.source, tg); bumpBridge(r.target, sg); }
}

const bridgeRanking = [];
for (const entity of entities) {
  const bag = bridgeNeighborBag.get(entity.id) || {};
  const total = Object.values(bag).reduce((a, b) => a + b, 0);
  if (total === 0) { entity.bridge_score = 0; continue; }

  const own = bag[entity.galaxyId] || 0;
  const foreign = total - own;
  const distinctForeign = Object.keys(bag).filter((g) => g !== entity.galaxyId).length;

  const score = (foreign / total) * (distinctForeign / denomForeign);
  entity.bridge_score = Number(score.toFixed(4));
  entity._bridge = {
    total_neighbors: total,
    own_galaxy: own,
    foreign_galaxies: Object.fromEntries(
      Object.entries(bag).filter(([g]) => g !== entity.galaxyId)
    ),
  };
  if (foreign >= 2 && distinctForeign >= 2) {
    bridgeRanking.push({ id: entity.id, score: entity.bridge_score, distinctForeign });
  }
}
bridgeRanking.sort((a, b) =>
  b.score - a.score || b.distinctForeign - a.distinctForeign || a.id.localeCompare(b.id)
);
const topBridges = bridgeRanking.slice(0, 20).map((x) => x.id);
console.log(`Bridge concepts: ${bridgeRanking.length} qualifying nodes (≥2 foreign galaxies, ≥2 foreign edges), top-20 exported`);
// ─────────────────────────────────────────────────────────────────────────────

// ─── Universe physics precompute ─────────────────────────────────────────────
// Deterministic Fibonacci-sphere placement of galaxy centroids (mass-weighted
// radial scaling), orbital binding for low-mass satellites, and an N-body
// equilibrium pass via d3-force-3d. Positions are frozen at build time so the
// browser only reads them; no per-frame layout compute lives client-side.

const ORBIT_EDGE_TYPES = new Set([
  "enables", "derives_from", "extract_of", "member_of", "describes", "example_of"
]);

function fibonacciSphere(nPoints) {
  const points = [];
  const phi = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < nPoints; i++) {
    const yy = 1 - (i / (nPoints - 1 || 1)) * 2;
    const rr = Math.sqrt(1 - yy * yy);
    const theta = phi * i;
    points.push([Math.cos(theta) * rr, yy, Math.sin(theta) * rr]);
  }
  return points;
}

function unitVecFromHash(seed) {
  const h1 = Number.parseInt(shortHash(`${seed}:u`, 8), 16);
  const h2 = Number.parseInt(shortHash(`${seed}:v`, 8), 16);
  const theta = (h1 / 0xffffffff) * Math.PI * 2;
  const phi = Math.acos(1 - 2 * (h2 / 0xffffffff));
  return {
    x: Math.sin(phi) * Math.cos(theta),
    y: Math.sin(phi) * Math.sin(theta),
    z: Math.cos(phi),
  };
}

const galaxyMassTotals = new Map();
for (const entity of entities) {
  galaxyMassTotals.set(
    entity.galaxyId,
    (galaxyMassTotals.get(entity.galaxyId) || 0) + (entity.mass || 0)
  );
}
const universeTotalMass = Math.max(1e-6,
  [...galaxyMassTotals.values()].reduce((a, b) => a + b, 0)
);

// Universe-scale radius: 2500 units so galaxies are visibly separated in the
// cinematic renderer. Small mass-weighted bump (up to +1000) so heavier
// galaxies sit slightly further out — subtle depth cue.
const UNIVERSE_RADIUS = 2500;
const galaxyCentroids = {};
const galaxySpinAxes = {};
const spherePoints = fibonacciSphere(GALAXY_DEFS.length);
GALAXY_DEFS.forEach(([gid], i) => {
  const [ux, uy, uz] = spherePoints[i];
  const gMass = galaxyMassTotals.get(gid) || 0;
  const radius = UNIVERSE_RADIUS + (gMass / universeTotalMass) * 1000;
  galaxyCentroids[gid] = {
    x: Number((ux * radius).toFixed(3)),
    y: Number((uy * radius).toFixed(3)),
    z: Number((uz * radius).toFixed(3)),
  };
  // Deterministic spin axis derived from galaxyId — defines the orbital
  // plane for satellites in this galaxy.
  const axis = unitVecFromHash(`spin:${gid}`);
  galaxySpinAxes[gid] = {
    x: Number(axis.x.toFixed(6)),
    y: Number(axis.y.toFixed(6)),
    z: Number(axis.z.toFixed(6)),
  };
});

// Orbital binding — walk curated edges of an "orbit-worthy" type, restricted
// to same-galaxy neighbors with strictly greater mass. Heavier satellites sit
// slightly further out so mass ordering is legible visually.
const entityById = new Map(entities.map((e) => [e.id, e]));
const neighborsByEntity = new Map();
for (const edge of curated) {
  if (!ORBIT_EDGE_TYPES.has(edge.type)) continue;
  if (!entityById.has(edge.source) || !entityById.has(edge.target)) continue;
  if (!neighborsByEntity.has(edge.source)) neighborsByEntity.set(edge.source, new Set());
  if (!neighborsByEntity.has(edge.target)) neighborsByEntity.set(edge.target, new Set());
  neighborsByEntity.get(edge.source).add(edge.target);
  neighborsByEntity.get(edge.target).add(edge.source);
}

function hash01(seed) {
  return Number.parseInt(shortHash(seed, 8), 16) / 0xffffffff;
}

let orbitCount = 0;
for (const entity of entities) {
  const neighbors = neighborsByEntity.get(entity.id);
  let bestParent = null;
  if (neighbors) {
    for (const nid of neighbors) {
      const n = entityById.get(nid);
      if (!n || n.galaxyId !== entity.galaxyId) continue;
      if ((n.mass || 0) <= (entity.mass || 0)) continue;
      if (!bestParent || (n.mass || 0) > (bestParent.mass || 0)) bestParent = n;
    }
  }
  if (bestParent) {
    entity.orbitOf = bestParent.id;
    // Scaled for the 2500-unit universe: satellites sit ~40–70 units from
    // their attractor with heavier satellites further out.
    entity.orbitDistance = Number(
      (40 + 30 * ((entity.mass || 0) / (bestParent.mass || 1))).toFixed(3)
    );
    // Kepler orbital elements — stable per entity id.
    const a = entity.orbitDistance;
    const e = Number((0.15 * hash01(`${entity.id}:e`)).toFixed(4));
    const omega = Number((hash01(`${entity.id}:w`) * Math.PI * 2).toFixed(4));
    const Omega = Number((hash01(`${entity.id}:O`) * Math.PI * 2).toFixed(4));
    // Inclination biased small so most satellites orbit near the galaxy
    // spin plane; a few tilt more dramatically.
    const incl = Number((hash01(`${entity.id}:i`) * Math.PI * 0.55).toFixed(4));
    const M0 = Number((hash01(`${entity.id}:M`) * Math.PI * 2).toFixed(4));
    // Faster orbits around heavier parents (crude Kepler-ish: n ∝ √M/a³).
    const n = Number(
      (0.05 + 0.15 * ((bestParent.mass || 1) / ((entity.mass || 0) + 1))).toFixed(5)
    );
    entity.orbit = { a, e, omega, Omega, incl, M0, n };
    orbitCount += 1;
  } else {
    entity.orbitOf = null;
    entity.orbitDistance = null;
    entity.orbit = null;
  }
}

// Attractors — top-3 mass nodes per galaxy get isAttractor=true. Non-orbiter
// preferred so hubs stay static; if fewer than 3 non-orbiters, fall back to
// heaviest nodes regardless.
const byGalaxy = new Map();
for (const entity of entities) {
  if (!byGalaxy.has(entity.galaxyId)) byGalaxy.set(entity.galaxyId, []);
  byGalaxy.get(entity.galaxyId).push(entity);
}
for (const [, list] of byGalaxy) {
  const nonOrbiters = list
    .filter((e) => !e.orbitOf)
    .sort((a, b) => (b.mass || 0) - (a.mass || 0));
  const picks = nonOrbiters.slice(0, 3);
  if (picks.length < 3) {
    const rest = list
      .filter((e) => !picks.includes(e))
      .sort((a, b) => (b.mass || 0) - (a.mass || 0));
    for (const e of rest) {
      if (picks.length >= 3) break;
      picks.push(e);
    }
  }
  for (const e of picks) e.isAttractor = true;
}

// N-body pass — orbiters are held out; only "free" nodes feel the sim.
const isOrbiter = (id) => !!entityById.get(id)?.orbitOf;
const freeEntities = entities.filter((e) => !e.orbitOf);
const simNodes = freeEntities.map((e) => {
  const c = galaxyCentroids[e.galaxyId] || { x: 0, y: 0, z: 0 };
  const jitter = unitVecFromHash(`${e.id}:jitter`);
  // Larger initial spread inside a galaxy so the sim relaxes into a wider
  // blob (scales with the 2500-unit universe).
  return {
    id: e.id,
    mass: e.mass || 1,
    galaxyId: e.galaxyId,
    x: c.x + jitter.x * 60,
    y: c.y + jitter.y * 60,
    z: c.z + jitter.z * 60,
  };
});
const simIndex = new Map(simNodes.map((n, i) => [n.id, i]));

const freeEdges = curated
  .filter((e) => simIndex.has(e.source) && simIndex.has(e.target))
  .map((e) => ({ source: e.source, target: e.target }));

// Applied on each tick; alpha-scaled so it goes quiet as sim cools.
function galaxyPull(alpha) {
  for (const node of simNodes) {
    const c = galaxyCentroids[node.galaxyId];
    if (!c) continue;
    node.vx = (node.vx || 0) + (c.x - node.x) * 0.05 * alpha;
    node.vy = (node.vy || 0) + (c.y - node.y) * 0.05 * alpha;
    node.vz = (node.vz || 0) + (c.z - node.z) * 0.05 * alpha;
  }
}

const N_ITER = 300;
const sim = forceSimulation(simNodes, 3)
  .force("charge", forceManyBody().strength((d) => -100 * (d.mass || 1)))
  .force("link", forceLink(freeEdges).id((d) => d.id).distance(150).strength(0.4))
  .force("galaxy", galaxyPull)
  .alpha(1.0)
  .alphaMin(0.02)
  .alphaDecay(1 - Math.pow(0.02, 1 / N_ITER))
  .velocityDecay(0.4)
  .stop();

for (let i = 0; i < N_ITER; i++) sim.tick();

for (const node of simNodes) {
  const e = entityById.get(node.id);
  if (!e) continue;
  e.position = {
    x: Number((node.x ?? 0).toFixed(3)),
    y: Number((node.y ?? 0).toFixed(3)),
    z: Number((node.z ?? 0).toFixed(3)),
  };
}

// Place orbital satellites deterministically at their Kepler position for t=0
// (i.e. mean anomaly = M0). This is the exact same closed-form path that the
// client renderer will evaluate every frame, so t=0 is a seamless handoff. We
// build the same spin-axis rotation matrix here, in JS, that kepler.ts builds
// at runtime — keep the two math paths in sync.
function buildSpinRotationJs(axis) {
  const vx = axis.x, vy = axis.y, vz = axis.z;
  // cross([0,0,1], axis)
  const cx = -vy, cy = vx, cz = 0;
  const s = Math.sqrt(cx * cx + cy * cy + cz * cz);
  const c = vz;
  if (s < 1e-8) {
    return c > 0
      ? [1, 0, 0, 0, 1, 0, 0, 0, 1]
      : [1, 0, 0, 0, -1, 0, 0, 0, -1];
  }
  const invS = 1 / s;
  const kx = cx * invS, ky = cy * invS, kz = cz * invS;
  const t = 1 - c;
  return [
    c + kx * kx * t,       kx * ky * t - kz * s, kx * kz * t + ky * s,
    ky * kx * t + kz * s,  c + ky * ky * t,      ky * kz * t - kx * s,
    kz * kx * t - ky * s,  kz * ky * t + kx * s, c + kz * kz * t,
  ];
}

function keplerT0(o, R) {
  const M = o.M0;
  let E = M;
  for (let i = 0; i < 3; i++) E = E - (E - o.e * Math.sin(E) - M) / (1 - o.e * Math.cos(E));
  const cosE = Math.cos(E);
  const sinE = Math.sin(E);
  const xO = o.a * (cosE - o.e);
  const yO = o.a * Math.sqrt(1 - o.e * o.e) * sinE;
  const cw = Math.cos(o.omega), sw = Math.sin(o.omega);
  const x1 = xO * cw - yO * sw;
  const y1 = xO * sw + yO * cw;
  const ci = Math.cos(o.incl), si = Math.sin(o.incl);
  const y2 = y1 * ci;
  const z2 = y1 * si;
  const cO = Math.cos(o.Omega), sO = Math.sin(o.Omega);
  const x3 = x1 * cO - y2 * sO;
  const y3 = x1 * sO + y2 * cO;
  const z3 = z2;
  return {
    x: R[0] * x3 + R[1] * y3 + R[2] * z3,
    y: R[3] * x3 + R[4] * y3 + R[5] * z3,
    z: R[6] * x3 + R[7] * y3 + R[8] * z3,
  };
}

const spinRotByGalaxy = {};
for (const [gid, axis] of Object.entries(galaxySpinAxes)) {
  spinRotByGalaxy[gid] = buildSpinRotationJs(axis);
}

// Sort by mass desc so a heavier satellite is resolved before any lighter
// satellite that might (rarely) orbit it in a multi-level chain.
const orbiterList = entities.filter((e) => e.orbitOf)
  .sort((a, b) => (b.mass || 0) - (a.mass || 0));
for (const sat of orbiterList) {
  const parent = entityById.get(sat.orbitOf);
  const base = parent?.position || galaxyCentroids[sat.galaxyId] || { x: 0, y: 0, z: 0 };
  const R = spinRotByGalaxy[sat.galaxyId] || [1, 0, 0, 0, 1, 0, 0, 0, 1];
  const rel = keplerT0(sat.orbit, R);
  sat.position = {
    x: Number((base.x + rel.x).toFixed(3)),
    y: Number((base.y + rel.y).toFixed(3)),
    z: Number((base.z + rel.z).toFixed(3)),
  };
}

console.log(`Universe physics: ${simNodes.length} free nodes, ${orbitCount} orbiters, ${freeEdges.length} sim edges, ${N_ITER} iters`);
// ─────────────────────────────────────────────────────────────────────────────

const galaxyIndex = new Map(GALAXY_DEFS.map((definition, index) => [definition[0], index]));
const galaxies = GALAXY_DEFS.map(([id, name, description, color]) => ({
  id,
  name,
  description,
  color,
  count: entities.filter((entity) => entity.galaxyId === id && entity.publishState === "core").length,
  supportCount: entities.filter((entity) => entity.galaxyId === id && entity.publishState === "support").length,
  totalMass: Number(
    entities
      .filter((entity) => entity.galaxyId === id)
      .reduce((sum, entity) => sum + (entity.mass || 0), 0)
      .toFixed(4)
  ),
  centroid: galaxyCentroids[id],
  spinAxis: galaxySpinAxes[id],
}));

const entityGraphNodes = entities.map((entity) => {
  const galaxy = galaxyIndex.get(entity.galaxyId);
  const pos = entity.position || { x: 0, y: 0, z: 0 };
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
    x: pos.x,
    y: pos.y,
    z: pos.z,
    size: Math.min(11, 2.0 + (entity.mass ?? 2) * 0.4),
    color: GALAXY_DEFS[galaxy][3],
    mass: entity.mass ?? 0,
    orbitOf: entity.orbitOf ?? null,
    orbit: entity.orbit ?? null,
    isAttractor: entity.isAttractor ?? false,
  };
});

const galaxyNodes = galaxies.map((galaxy) => {
  const c = galaxy.centroid || { x: 0, y: 0, z: 0 };
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
    x: c.x,
    y: c.y,
    z: c.z,
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
    galaxies: galaxies.length,
    aiEnrichedEntities: aiEnrichedCount,
    inferredRelations:  inferredEdgesAdded,
    bridgeConcepts:     bridgeRanking.length,
  },
  assets,
  similarityModel: `${embeddings.engine}:q8`,
  similarityRevision: REVISION,
  corpusHash,
  aiModel:    "onnx-community/Qwen3-4B-Instruct-2507-ONNX",
  topBridges,
  layout_version: "universe.v2-kepler",
};

writeJson(path.join(PUBLIC, "manifest.json"), manifest);
writeJson(path.join(GENERATED, "manifest.json"), manifest);
writeJson(path.join(GENERATED, "entities.json"), entities);
writeJson(path.join(GENERATED, "galaxies.json"), galaxies);
writeJson(path.join(GENERATED, "curated-relations.json"), curated);
writeJson(path.join(GENERATED, "similarity.json"), similarity);
writeJson(path.join(GENERATED, "bodies.json"), bodies);
writeJson(path.join(GENERATED, "evidence.json"), evidence);
writeJson(path.join(GENERATED, "evidence-by-entity.json"), evidenceByEntity);
writeJson(path.join(GENERATED, "quality.json"), assetPayloads.quality);
// Slim position map: id → {x,y,z} — consumed by the 3D graph page. Sourced
// from the physics precompute so the browser doesn't have to run a layout.
const graphPositions = Object.fromEntries(
  entities.filter((e) => e.position).map((e) => [e.id, e.position])
);
writeJson(path.join(GENERATED, "graph-positions.json"), graphPositions);

console.log(JSON.stringify(manifest, null, 2));
