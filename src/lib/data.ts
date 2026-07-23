import fs from "node:fs";
import path from "node:path";
import type { DatasetManifest, Entity, Galaxy, Relation } from "./types";

const generated = path.resolve("src/generated");

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(generated, name), "utf8")) as T;
}

export const manifest = readJson<DatasetManifest>("manifest.json");
export const entities = readJson<Entity[]>("entities.json");
export const galaxies = readJson<Galaxy[]>("galaxies.json");
export const curatedRelations = readJson<Relation[]>("curated-relations.json");
export const bodies = readJson<Record<string, string>>("bodies.json");

export const entityById = new Map(entities.map((entity) => [entity.id, entity]));

export function bodyFor(entity: Entity): string {
  return bodies[entity.bodyRef] ?? "";
}
