#!/usr/bin/env node
// Build a MITRE ATT&CK matrix index from generated entities.json.
// Runs AFTER scripts/build-data.mjs; consumed by src/pages/mitre/index.astro
// and the client-side MitreMatrix component.
//
// Output shape:
// {
//   tactics: [ { id, name, slug, order, techniqueCount, cardCount } ],
//   techniques: { "T1055": { id, tacticIds, entityIds, cardCount } },
//   byTactic: { "TA0004": { tacticId, techniqueIds, entities: [{id,title,mass,galaxyId,route}, ...] } },
//   meta: { generatedAt, totalEntities, totalWithMitre, coveragePercent }
// }

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TACTICS, TECHNIQUE_TO_TACTICS, getTacticsFor } from "./lib/mitre-tactics.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const ENTITIES_PATH = path.join(ROOT, "src/generated/entities.json");
const OUT_PATH = path.join(ROOT, "src/generated/mitre-index.json");

const MITRE_RE = /^T\d{4}(?:\.\d+)?$/;

function readEntities() {
  if (!fs.existsSync(ENTITIES_PATH)) {
    console.warn(`[mitre-index] entities.json not found at ${ENTITIES_PATH} — skipping (run data:build first).`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(ENTITIES_PATH, "utf8"));
  } catch (err) {
    console.warn(`[mitre-index] Failed to parse entities.json: ${err.message} — skipping.`);
    return null;
  }
}

/** Pull MITRE technique ids from an entity's tags[] and (if present) mitre[]. */
function extractMitreIds(entity) {
  const out = new Set();
  const push = (value) => {
    if (!value || typeof value !== "string") return;
    const norm = value.trim().toUpperCase();
    if (MITRE_RE.test(norm)) out.add(norm);
  };
  const tags = Array.isArray(entity.tags) ? entity.tags : [];
  for (const tag of tags) push(tag);
  const mitre = Array.isArray(entity.mitre) ? entity.mitre : [];
  for (const m of mitre) push(m);
  return Array.from(out);
}

function parentOf(id) {
  return id.split(".")[0];
}

function main() {
  const entities = readEntities();
  if (!entities) {
    process.exit(0);
  }

  // techniques: parent-technique id -> { entityIds:Set, tacticIds:Set }
  const techniques = new Map();
  // byTactic: tactic id -> { entityIds:Set, techniqueIds:Set }
  const byTactic = new Map();
  const entityMeta = new Map(); // id -> {id,title,mass,galaxyId,route}

  let totalWithMitre = 0;

  for (const entity of entities) {
    if (!entity || typeof entity !== "object") continue;
    const ids = extractMitreIds(entity);
    if (ids.length === 0) continue;
    totalWithMitre += 1;

    entityMeta.set(entity.id, {
      id: entity.id,
      title: entity.title || entity.id,
      mass: typeof entity.mass === "number" ? entity.mass : null,
      galaxyId: entity.galaxyId || "",
      route: entity.route || "",
    });

    for (const rawId of ids) {
      const parent = parentOf(rawId);
      const tactics = getTacticsFor(parent);

      let techEntry = techniques.get(parent);
      if (!techEntry) {
        techEntry = { id: parent, entityIds: new Set(), tacticIds: new Set(tactics) };
        techniques.set(parent, techEntry);
      } else {
        for (const t of tactics) techEntry.tacticIds.add(t);
      }
      techEntry.entityIds.add(entity.id);

      for (const tacticId of tactics) {
        let tEntry = byTactic.get(tacticId);
        if (!tEntry) {
          tEntry = { tacticId, entityIds: new Set(), techniqueIds: new Set() };
          byTactic.set(tacticId, tEntry);
        }
        tEntry.entityIds.add(entity.id);
        tEntry.techniqueIds.add(parent);
      }
    }
  }

  // Build serialized output.
  const tacticsOut = TACTICS
    .slice()
    .sort((a, b) => a.order - b.order)
    .map((t) => {
      const entry = byTactic.get(t.id);
      return {
        id: t.id,
        name: t.name,
        slug: t.slug,
        shortDesc: t.shortDesc,
        order: t.order,
        techniqueCount: entry ? entry.techniqueIds.size : 0,
        cardCount: entry ? entry.entityIds.size : 0,
      };
    });

  const techniquesOut = {};
  for (const [id, entry] of techniques) {
    techniquesOut[id] = {
      id,
      tacticIds: Array.from(entry.tacticIds),
      entityIds: Array.from(entry.entityIds),
      cardCount: entry.entityIds.size,
    };
  }

  const byTacticOut = {};
  for (const [tacticId, entry] of byTactic) {
    const entitiesList = Array.from(entry.entityIds)
      .map((id) => entityMeta.get(id))
      .filter(Boolean)
      .sort((a, b) => (b.mass ?? 0) - (a.mass ?? 0) || a.title.localeCompare(b.title));
    byTacticOut[tacticId] = {
      tacticId,
      techniqueIds: Array.from(entry.techniqueIds).sort(),
      entities: entitiesList,
    };
  }

  const totalKnownTechniques = Object.keys(TECHNIQUE_TO_TACTICS).length;
  const coveredTechniques = Object.keys(techniquesOut).length;
  const coveragePercent = totalKnownTechniques
    ? Number(((coveredTechniques / totalKnownTechniques) * 100).toFixed(1))
    : 0;

  const output = {
    tactics: tacticsOut,
    techniques: techniquesOut,
    byTactic: byTacticOut,
    meta: {
      generatedAt: new Date().toISOString(),
      totalEntities: entities.length,
      totalWithMitre,
      totalKnownTechniques,
      coveredTechniques,
      coveragePercent,
    },
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, `${JSON.stringify(output)}\n`);

  console.log(
    `[mitre-index] ${entities.length} entities · ${totalWithMitre} with MITRE tags · ` +
    `${coveredTechniques} techniques across ${tacticsOut.filter((t) => t.cardCount > 0).length} tactics ` +
    `(${coveragePercent}% of known corpus). Wrote ${path.relative(ROOT, OUT_PATH)}.`
  );
}

main();
