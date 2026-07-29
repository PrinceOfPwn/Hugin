import assert from "node:assert/strict";
import fs from "node:fs";
import { execFileSync } from "node:child_process";

execFileSync("node", ["scripts/build-mitre-index.mjs"], { stdio: "inherit" });

const entities = JSON.parse(fs.readFileSync("src/generated/entities.json", "utf8"));
const index = JSON.parse(fs.readFileSync("src/generated/mitre-index.json", "utf8"));
const expectedIds = new Set();
const fields = (entity) => [
  entity.tags,
  entity.mitre,
  entity.mitre_secondary,
  entity.mitre_candidates,
  entity.mitre_technique,
  entity._ai?.mitre,
  entity._ai?.mitre_candidates,
  entity.facets?.mitre,
  entity.facets?.mitre_candidates,
];
const scan = (value) => {
  if (!value) return;
  if (Array.isArray(value)) {
    for (const item of value) scan(item);
    return;
  }
  if (typeof value !== "string") return;
  for (const match of value.matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)) {
    expectedIds.add(match[0].toUpperCase());
  }
};
for (const entity of entities) for (const value of fields(entity)) scan(value);

const actualIds = new Set(Object.keys(index.techniques));
assert.deepEqual(
  Array.from(actualIds).sort(),
  Array.from(expectedIds).sort(),
  "the MITRE index must preserve every exact technique and sub-technique ID",
);
assert.equal(index.meta.attackVersion, "19.1");
assert.equal(index.meta.unknownTechniqueIds.length, 0, "all corpus IDs must map to the pinned release");

for (const [id, technique] of Object.entries(index.techniques)) {
  assert.ok(technique.name && technique.name !== "Unknown ATT&CK technique", `${id} needs an official name`);
  assert.ok(technique.tacticIds.length > 0, `${id} needs at least one tactic`);
  assert.ok(technique.entityIds.length > 0, `${id} needs at least one entity`);
  for (const tacticId of technique.tacticIds) {
    assert.ok(index.byTactic[tacticId]?.techniqueIds.includes(id), `${id} missing from ${tacticId}`);
  }
  if (id.includes(".")) {
    assert.equal(technique.isSubtechnique, true, `${id} must remain a sub-technique`);
    assert.match(technique.parentId ?? "", /^T\d{4}$/, `${id} needs its parent`);
  }
}

console.log(
  `[mitre-test] ${actualIds.size} exact IDs mapped across ` +
  `${index.tactics.filter((tactic) => tactic.cardCount > 0).length} tactics`,
);
