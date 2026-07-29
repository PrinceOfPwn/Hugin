#!/usr/bin/env node
/**
 * Build a compact, reproducible MITRE ATT&CK Enterprise reference.
 *
 * The upstream STIX bundle is intentionally fetched only by this explicit
 * maintenance command. Normal builds consume the compact, versioned JSON and
 * never depend on network access.
 */

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const ATTACK_VERSION = "19.1";
const SOURCE_URL =
  `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v${ATTACK_VERSION}` +
  "/enterprise-attack/enterprise-attack.json";
const OUT_PATH = path.resolve("data/reference/mitre-enterprise.json");

function externalId(object) {
  return object.external_references
    ?.find((reference) => reference.source_name === "mitre-attack")?.external_id;
}

function tacticIds(object, tacticByPhase) {
  return Array.from(
    new Set(
      (object.kill_chain_phases ?? [])
        .filter((phase) => phase.kill_chain_name === "mitre-attack")
        .map((phase) => tacticByPhase.get(phase.phase_name))
        .filter(Boolean),
    ),
  );
}

const response = await fetch(SOURCE_URL, {
  headers: { "user-agent": "HUGIN-MITRE-index-builder/1.0" },
});
if (!response.ok) {
  throw new Error(`MITRE download failed: ${response.status} ${response.statusText}`);
}

const raw = await response.text();
const bundle = JSON.parse(raw);
const objects = Array.isArray(bundle.objects) ? bundle.objects : [];

const tacticByPhase = new Map();
for (const object of objects) {
  if (object.type !== "x-mitre-tactic") continue;
  const id = externalId(object);
  if (id && object.x_mitre_shortname) tacticByPhase.set(object.x_mitre_shortname, id);
}

const attackPatternByStixId = new Map(
  objects
    .filter((object) => object.type === "attack-pattern")
    .map((object) => [object.id, object]),
);
const parentByChildStixId = new Map();
for (const object of objects) {
  if (
    object.type === "relationship" &&
    object.relationship_type === "subtechnique-of" &&
    attackPatternByStixId.has(object.source_ref) &&
    attackPatternByStixId.has(object.target_ref)
  ) {
    parentByChildStixId.set(object.source_ref, object.target_ref);
  }
}

const techniques = {};
for (const [stixId, object] of attackPatternByStixId) {
  const id = externalId(object);
  if (!/^T\d{4}(?:\.\d{3})?$/.test(id ?? "")) continue;

  const parentObject = attackPatternByStixId.get(parentByChildStixId.get(stixId));
  const parentId = parentObject ? externalId(parentObject) : null;
  const mappedTactics = tacticIds(object, tacticByPhase);
  if (mappedTactics.length === 0 && parentObject) {
    mappedTactics.push(...tacticIds(parentObject, tacticByPhase));
  }

  techniques[id] = {
    id,
    name: object.name,
    tacticIds: mappedTactics.sort(),
    parentId: parentId || null,
    isSubtechnique: Boolean(object.x_mitre_is_subtechnique || parentId),
    revoked: Boolean(object.revoked),
    deprecated: Boolean(object.x_mitre_deprecated),
  };
}

const activeTechniqueCount = Object.values(techniques).filter(
  (technique) => !technique.revoked && !technique.deprecated,
).length;
const output = {
  schemaVersion: "1.0.0",
  attackVersion: ATTACK_VERSION,
  sourceUrl: SOURCE_URL,
  sourceSha256: createHash("sha256").update(raw).digest("hex"),
  generatedAt: new Date().toISOString(),
  activeTechniqueCount,
  techniques: Object.fromEntries(
    Object.entries(techniques).sort(([a], [b]) => a.localeCompare(b)),
  ),
};

fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
fs.writeFileSync(OUT_PATH, `${JSON.stringify(output)}\n`);
console.log(
  `[mitre-sync] ATT&CK v${ATTACK_VERSION}: ${Object.keys(techniques).length} total, ` +
  `${activeTechniqueCount} active techniques -> ${path.relative(process.cwd(), OUT_PATH)}`,
);
