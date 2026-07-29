import fs from "node:fs";
import path from "node:path";

export interface MitreIndexTactic {
  id: string;
  name: string;
  slug: string;
  shortDesc: string;
  order: number;
  techniqueCount: number;
  cardCount: number;
}

export interface MitreIndexTechnique {
  id: string;
  name: string;
  parentId: string | null;
  isSubtechnique: boolean;
  revoked: boolean;
  deprecated: boolean;
  tacticIds: string[];
  entityIds: string[];
  cardCount: number;
}

export interface MitreIndexEntity {
  id: string;
  title: string;
  mass: number | null;
  galaxyId: string;
  route: string;
}

export interface MitreIndexTacticGroup {
  tacticId: string;
  techniqueIds: string[];
  entities: MitreIndexEntity[];
}

export interface MitreIndexMeta {
  generatedAt: string;
  attackVersion: string;
  referenceSha256: string;
  totalEntities: number;
  totalWithMitre: number;
  totalKnownTechniques: number;
  coveredTechniques: number;
  coveredKnownTechniques: number;
  unknownTechniqueIds: string[];
  coveragePercent: number;
}

export interface MitreIndex {
  tactics: MitreIndexTactic[];
  techniques: Record<string, MitreIndexTechnique>;
  byTactic: Record<string, MitreIndexTacticGroup>;
  meta: MitreIndexMeta;
}

const INDEX_PATH = path.resolve("src/generated/mitre-index.json");

function readIndex(): MitreIndex {
  if (!fs.existsSync(INDEX_PATH)) {
    // Fresh checkout / prebuild not yet run — return an empty but well-typed shell
    // so pages don't crash during the initial `astro build` bootstrap.
    return {
      tactics: [],
      techniques: {},
      byTactic: {},
      meta: {
        generatedAt: new Date(0).toISOString(),
        attackVersion: "unknown",
        referenceSha256: "",
        totalEntities: 0,
        totalWithMitre: 0,
        totalKnownTechniques: 0,
        coveredTechniques: 0,
        coveredKnownTechniques: 0,
        unknownTechniqueIds: [],
        coveragePercent: 0,
      },
    };
  }
  return JSON.parse(fs.readFileSync(INDEX_PATH, "utf8")) as MitreIndex;
}

export const mitreIndex: MitreIndex = readIndex();
