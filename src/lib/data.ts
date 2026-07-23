import fs from "node:fs";
import path from "node:path";
import type {
  DatasetManifest,
  Entity,
  EvidenceRecord,
  Galaxy,
  QualityReport,
  Relation
} from "./types";

const generated = path.resolve("src/generated");

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(generated, name), "utf8")) as T;
}

export const manifest = readJson<DatasetManifest>("manifest.json");
export const entities = readJson<Entity[]>("entities.json");
export const galaxies = readJson<Galaxy[]>("galaxies.json");
export const curatedRelations = readJson<Relation[]>("curated-relations.json");
export const bodies = readJson<Record<string, string>>("bodies.json");
export const evidence = readJson<EvidenceRecord[]>("evidence.json");
export const evidenceByEntity = readJson<Record<string, string[]>>("evidence-by-entity.json");
export const quality = readJson<QualityReport>("quality.json");

export const entityById = new Map(entities.map((entity) => [entity.id, entity]));
export const evidenceById = new Map(evidence.map((item) => [item.id, item]));

export function bodyFor(entity: Entity): string {
  return bodies[entity.bodyRef] ?? "";
}

export function evidenceFor(entityId: string, limit = 8): EvidenceRecord[] {
  return (evidenceByEntity[entityId] || [])
    .map((id) => evidenceById.get(id))
    .filter((item): item is EvidenceRecord => Boolean(item))
    .sort((a, b) => b.qualityScore - a.qualityScore)
    .slice(0, limit);
}
