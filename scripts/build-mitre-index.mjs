#!/usr/bin/env node
// Build the static MITRE ATT&CK matrix index consumed by /mitre.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TACTICS, getTacticsFor } from "./lib/mitre-tactics.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const ENTITIES_PATH = path.join(ROOT, "src/generated/entities.json");
const REFERENCE_PATH = path.join(ROOT, "data/reference/mitre-enterprise.json");
const OUT_PATH = path.join(ROOT, "src/generated/mitre-index.json");
const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;
const UNMAPPED_TACTIC = {
  id: "UNMAPPED",
  name: "Unmapped",
  slug: "unmapped",
  shortDesc: "Technique IDs not present in the pinned ATT&CK release.",
  order: 99,
};

function readJson(filePath, label) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} not found at ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

/**
 * Extract every ATT&CK ID embedded in strings and nested arrays. This handles
 * legacy values such as "T1547, T1546, T1053" without silently dropping them.
 */
export function extractMitreIds(entity) {
  const out = new Set();
  const push = (value) => {
    if (!value) return;
    if (Array.isArray(value)) {
      for (const item of value) push(item);
      return;
    }
    if (typeof value !== "string") return;
    for (const match of value.matchAll(MITRE_RE)) out.add(match[0].toUpperCase());
  };

  push(entity.tags);
  push(entity.mitre);
  push(entity.mitre_secondary);
  push(entity.mitre_candidates);
  push(entity.mitre_technique);
  push(entity._ai?.mitre);
  push(entity._ai?.mitre_candidates);
  push(entity.facets?.mitre);
  push(entity.facets?.mitre_candidates);
  return Array.from(out).sort();
}

function tacticsFor(id, entity, referenceTechnique) {
  if (referenceTechnique?.tacticIds?.length) return referenceTechnique.tacticIds;
  const fallback = getTacticsFor(id, entity.category);
  return fallback.length > 0 ? fallback : [UNMAPPED_TACTIC.id];
}

function main() {
  const entities = readJson(ENTITIES_PATH, "entities.json");
  const reference = readJson(REFERENCE_PATH, "MITRE Enterprise reference");
  const officialTechniques = reference.techniques ?? {};
  const activeOfficialIds = new Set(
    Object.values(officialTechniques)
      .filter((technique) => !technique.revoked && !technique.deprecated)
      .map((technique) => technique.id),
  );

  const techniques = new Map();
  const byTactic = new Map();
  const entityMeta = new Map();
  const unknownTechniqueIds = new Set();
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

    for (const id of ids) {
      const official = officialTechniques[id];
      if (!official) unknownTechniqueIds.add(id);
      const tacticIds = tacticsFor(id, entity, official);
      let technique = techniques.get(id);
      if (!technique) {
        technique = {
          id,
          name: official?.name ?? "Unknown ATT&CK technique",
          parentId: official?.parentId ?? null,
          isSubtechnique: Boolean(official?.isSubtechnique || id.includes(".")),
          revoked: Boolean(official?.revoked),
          deprecated: Boolean(official?.deprecated),
          entityIds: new Set(),
          tacticIds: new Set(),
        };
        techniques.set(id, technique);
      }
      technique.entityIds.add(entity.id);
      for (const tacticId of tacticIds) {
        technique.tacticIds.add(tacticId);
        let group = byTactic.get(tacticId);
        if (!group) {
          group = { tacticId, entityIds: new Set(), techniqueIds: new Set() };
          byTactic.set(tacticId, group);
        }
        group.entityIds.add(entity.id);
        group.techniqueIds.add(id);
      }
    }
  }

  const tacticDefinitions = byTactic.has(UNMAPPED_TACTIC.id)
    ? [...TACTICS, UNMAPPED_TACTIC]
    : TACTICS;
  const tacticsOut = tacticDefinitions
    .slice()
    .sort((a, b) => a.order - b.order)
    .map((tactic) => {
      const group = byTactic.get(tactic.id);
      return {
        ...tactic,
        techniqueCount: group?.techniqueIds.size ?? 0,
        cardCount: group?.entityIds.size ?? 0,
      };
    });

  const techniquesOut = {};
  for (const [id, technique] of Array.from(techniques).sort(([a], [b]) => a.localeCompare(b))) {
    techniquesOut[id] = {
      id,
      name: technique.name,
      parentId: technique.parentId,
      isSubtechnique: technique.isSubtechnique,
      revoked: technique.revoked,
      deprecated: technique.deprecated,
      tacticIds: Array.from(technique.tacticIds).sort(),
      entityIds: Array.from(technique.entityIds).sort(),
      cardCount: technique.entityIds.size,
    };
  }

  const byTacticOut = {};
  for (const [tacticId, group] of byTactic) {
    byTacticOut[tacticId] = {
      tacticId,
      techniqueIds: Array.from(group.techniqueIds).sort(),
      entities: Array.from(group.entityIds)
        .map((id) => entityMeta.get(id))
        .filter(Boolean)
        .sort((a, b) => (b.mass ?? 0) - (a.mass ?? 0) || a.title.localeCompare(b.title)),
    };
  }

  const coveredKnownTechniques = Object.keys(techniquesOut).filter((id) =>
    activeOfficialIds.has(id),
  ).length;
  const totalKnownTechniques = activeOfficialIds.size;
  const coveragePercent = totalKnownTechniques
    ? Number(((coveredKnownTechniques / totalKnownTechniques) * 100).toFixed(1))
    : 0;
  const output = {
    tactics: tacticsOut,
    techniques: techniquesOut,
    byTactic: byTacticOut,
    meta: {
      generatedAt: new Date().toISOString(),
      attackVersion: reference.attackVersion,
      referenceSha256: reference.sourceSha256,
      totalEntities: entities.length,
      totalWithMitre,
      totalKnownTechniques,
      coveredTechniques: Object.keys(techniquesOut).length,
      coveredKnownTechniques,
      unknownTechniqueIds: Array.from(unknownTechniqueIds).sort(),
      coveragePercent,
    },
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, `${JSON.stringify(output)}\n`);
  console.log(
    `[mitre-index] ATT&CK v${reference.attackVersion}: ${entities.length} entities · ` +
    `${totalWithMitre} tagged · ${Object.keys(techniquesOut).length} exact techniques · ` +
    `${unknownTechniqueIds.size} unmapped · ${coveragePercent}% corpus coverage.`,
  );
}

main();
