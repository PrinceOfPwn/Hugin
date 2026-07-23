export interface Provenance {
  sourceKey: string;
  sourceLabel: string;
  sourceHash?: string;
}

export interface Entity {
  id: string;
  slug: string;
  route: string;
  title: string;
  kind: string;
  category: string;
  galaxyId: string;
  subgalaxy: string;
  summary: string;
  tags: string[];
  tier?: string;
  confidence?: string;
  mitre: string[];
  bodyRef: string;
  bodyShard: number;
  degree: number;
  provenance: Provenance[];
}

export interface Relation {
  id: string;
  source: string;
  target: string;
  type: string;
  origin: "curated" | "membership" | "similarity";
  rationale?: string;
  score?: number;
  rank?: number;
  modelRevision?: string;
}

export interface DatasetManifest {
  schemaVersion: string;
  datasetVersion: string;
  sourceHash: string;
  generatedAt: string;
  commit: string;
  counts: Record<string, number>;
  assets: Record<string, string>;
  similarityModel: string;
  similarityRevision: string;
}

export interface Galaxy {
  id: string;
  name: string;
  description: string;
  color: string;
  count: number;
}
