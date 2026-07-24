// ═════════════════════════════════════════════════════════════════════════════
//  PATCH: Merge AI-enriched metadata + inferred typed relations into build.
//
//  Two independent edits to scripts/build-data.mjs:
//
//   [1]  MERGE BLOCK — insert immediately AFTER the loop that fills
//        `similarity` and BEFORE `entityGraphNodes` is built (~line 400).
//
//   [2]  WRITE similarity.json — add to the block of writeJson(...) calls
//        at the very end so the enrich scripts can consume it. This is
//        REQUIRED — without it, enrich-entities.mjs cannot find neighbors.
//
//  Also add two counters to manifest.counts and one top-level field.
// ═════════════════════════════════════════════════════════════════════════════

// ─── [1] MERGE BLOCK ─────────────────────────────────────────────────────────
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
//     Only accept confidence >= 4 and specific types (not "related"/"none").
//     Respects `reverse` boolean if the model signalled inverted direction.
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

    // Respect direction — if the model flagged reverse, swap endpoints
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

// 1c. Recompute degree so hub-ranking and graph layout account for inferred edges.
{
  const deg = new Map();
  for (const r of curated) {
    deg.set(r.source, (deg.get(r.source) || 0) + 1);
    deg.set(r.target, (deg.get(r.target) || 0) + 1);
  }
  for (const entity of entities) entity.degree = deg.get(entity.id) ?? 0;
}

// 1d. Bridge score — emergent multi-domain concepts.
//
//     For each entity E in galaxy G:
//       neighbors        = all cards E connects to via curated ∪ inferred
//       foreign          = neighbors whose galaxyId != G
//       distinct_foreign = number of *distinct* foreign galaxies touched
//
//       bridge_score = (foreign / total) * (distinct_foreign / (N_GALAXIES - 1))
//
//     Range: 0 (all neighbors in same galaxy) → 1 (all neighbors foreign AND
//     spread across every other galaxy). Emits `_bridge` with per-galaxy
//     counts for the sidebar UI, plus `topBridges` (top-20 IDs) for the
//     home page section.
const entityGalaxyMap = new Map(entities.map((e) => [e.id, e.galaxyId]));
const nGalaxies = galaxies.length || 1;
const denomForeign = Math.max(1, nGalaxies - 1);

const bridgeNeighborBag = new Map();  // id → { <galaxyId>: count }
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
  b.score - a.score ||
  b.distinctForeign - a.distinctForeign ||
  a.id.localeCompare(b.id)
);
const topBridges = bridgeRanking.slice(0, 20).map((x) => x.id);
console.log(`Bridge concepts: ${bridgeRanking.length} qualifying nodes (≥2 foreign galaxies, ≥2 foreign edges), top-20 exported`);


// ─── [2] EXTRA WRITE — REQUIRED for enrich scripts ───────────────────────────
// Add this line inside the block of writeJson calls at the END of build-data.mjs
// (right after `writeJson(path.join(GENERATED, "curated-relations.json"), curated);`)

writeJson(path.join(GENERATED, "similarity.json"), similarity);


// ─── [3] MANIFEST FIELDS ─────────────────────────────────────────────────────
// Inside `manifest.counts`, add:
//   aiEnrichedEntities: aiEnrichedCount,
//   inferredRelations:  inferredEdgesAdded,
//   bridgeConcepts:     bridgeRanking.length,
//
// At manifest top-level, add:
//   aiModel:            "onnx-community/Qwen3-4B-Instruct-2507-ONNX",
//   topBridges,         // top-20 entity IDs by bridge_score (for home page)
// ═════════════════════════════════════════════════════════════════════════════
