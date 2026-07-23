import fs from "node:fs";
import path from "node:path";

const generated = path.resolve("src/generated");
const read = (name) => JSON.parse(fs.readFileSync(path.join(generated, name), "utf8"));
const manifest = read("manifest.json");
const entities = read("entities.json");
const curated = read("curated-relations.json");
const ids = new Set(entities.map((entity) => entity.id));
const slugs = new Set(entities.map((entity) => entity.slug));
const errors = [];

if (entities.length !== 5608) errors.push(`Expected exactly 5608 entities, found ${entities.length}`);
if (ids.size !== entities.length) errors.push("Entity IDs are not unique");
if (slugs.size !== entities.length) errors.push("Entity slugs are not unique");
if (curated.length !== 3795) errors.push(`Expected 3795 curated relations, found ${curated.length}`);
if (manifest.counts.quarantinedRelations !== 2) errors.push("Expected exactly two quarantined self-relations");
if (manifest.counts.similarityRelations !== entities.length * 8) errors.push("Every entity must have eight similarity neighbors");
if (entities.some((entity) => !entity.galaxyId || !entity.bodyRef || !entity.route)) errors.push("Every entity needs a galaxy, bodyRef, and route");
if (curated.some((edge) => edge.source === edge.target || !ids.has(edge.source) || !ids.has(edge.target))) errors.push("Curated relation integrity failed");

const publicText = fs.readFileSync(path.resolve("data/source/public-graph.json"), "utf8");
for (const forbidden of [/\/Users\//i, /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)/i, /emiperalta/i]) {
  if (forbidden.test(publicText)) errors.push(`Public projection contains forbidden pattern ${forbidden}`);
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}
console.log(`Validated ${entities.length} entities, ${curated.length} curated relations, and ${manifest.counts.similarityRelations} similarity relations.`);
