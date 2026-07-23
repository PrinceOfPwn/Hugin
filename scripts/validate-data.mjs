import fs from "node:fs";
import path from "node:path";

const generated = path.resolve("src/generated");
const sourceFile = path.resolve("data/source/public-graph.json");
const read = (name) => JSON.parse(fs.readFileSync(path.join(generated, name), "utf8"));

const source = JSON.parse(fs.readFileSync(sourceFile, "utf8"));
const manifest = read("manifest.json");
const entities = read("entities.json");
const evidence = read("evidence.json");
const curated = read("curated-relations.json");
const quality = read("quality.json");
const ids = new Set(entities.map((entity) => entity.id));
const slugs = new Set(entities.map((entity) => entity.slug));
const errors = [];

if (source.rawCounts.nodes !== 5608) errors.push(`Expected the audited 5,608-record import, found ${source.rawCounts.nodes}`);
if (source.rawCounts.relations !== 3797) errors.push(`Expected the audited 3,797-relation import, found ${source.rawCounts.relations}`);
if (entities.length !== source.quality.states.core + source.quality.states.support) {
  errors.push("Core and supporting entity counts do not match the sanitized projection");
}
if (evidence.length !== source.quality.states.evidence) {
  errors.push("Evidence count does not match the sanitized projection");
}
if (quality.quarantinedNodes.length !== source.quality.states.quarantined) {
  errors.push("Quarantine report is incomplete");
}
if (ids.size !== entities.length) errors.push("Entity IDs are not unique");
if (slugs.size !== entities.length) errors.push("Entity slugs are not unique");
if (entities.some((entity) => entity.kind === "atlas_reference" || entity.publishState === "evidence")) {
  errors.push("Raw evidence may not be promoted to catalog or graph entities");
}
if (entities.some((entity) => !entity.galaxyId || !entity.bodyRef || !entity.route || !entity.evidenceId)) {
  errors.push("Every public entity needs a galaxy, bodyRef, route, and anonymous evidence ID");
}
if (curated.some((edge) => edge.source === edge.target || !ids.has(edge.source) || !ids.has(edge.target))) {
  errors.push("Curated graph relation integrity failed");
}
if (manifest.counts.coreEntities !== source.quality.states.core) errors.push("Manifest core count is incorrect");
if (manifest.counts.supportEntities !== source.quality.states.support) errors.push("Manifest support count is incorrect");
if (manifest.counts.evidenceRecords !== source.quality.states.evidence) errors.push("Manifest evidence count is incorrect");
if (manifest.counts.quarantinedEvidence !== source.quality.states.quarantined) errors.push("Manifest quarantine count is incorrect");
if (manifest.counts.similarityRelations !== manifest.counts.coreEntities * 8) {
  errors.push("Every core entity must have eight generated similarity neighbors");
}
if (manifest.counts.galaxies !== 8) errors.push("Expected eight structural galaxies");

const publicFiles = [
  sourceFile,
  ...fs.readdirSync(generated).filter((name) => name.endsWith(".json")).map((name) => path.join(generated, name))
];
const forbidden = [
  { label: "absolute Unix owner path", pattern: /\/(?:Users|home)\/(?:emiperalta|tamarisk|source-owner)(?:\/|\\)/i },
  { label: "absolute Windows user path", pattern: /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)/i },
  { label: "local username", pattern: /\b(?:emiperalta|tamarisk)\b/i },
  { label: "named training provider", pattern: /\bSANS(?:\s+Institute)?\b/i },
  { label: "course identifier", pattern: /\bSEC\d{3}(?:\.\d+)?\b/i },
  { label: "named research course", pattern: /\bCRTO\b|\bCertified\s+Red\s+Team\s+Operator\b/i },
  { label: "named development course", pattern: /MalDev/i },
  { label: "named training provider", pattern: /OffSec|\bOffensive\s+Security\b/i },
  { label: "private source field", pattern: /"(?:source_path|source_key|file_path|absolute_path|local_path)"\s*:/i }
];

for (const file of publicFiles) {
  const text = fs.readFileSync(file, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(text)) {
      errors.push(`${path.relative(process.cwd(), file)} contains forbidden ${rule.label}`);
    }
  }
}

const evidenceText = JSON.stringify(evidence);
for (const phrase of [
  /\btitle\s+slide\b/i,
  /\btable\s+of\s+contents\b/i,
  /\blearning\s+objectives?\b/i,
  /\bcopyright\s+notice\b/i
]) {
  if (phrase.test(evidenceText)) errors.push(`Published evidence contains low-value pattern ${phrase}`);
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log(JSON.stringify({
  rawRecords: source.rawCounts.nodes,
  coreEntities: manifest.counts.coreEntities,
  supportEntities: manifest.counts.supportEntities,
  evidenceRecords: manifest.counts.evidenceRecords,
  quarantinedEvidence: manifest.counts.quarantinedEvidence,
  curatedRelations: manifest.counts.curatedRelations,
  similarityRelations: manifest.counts.similarityRelations
}, null, 2));
