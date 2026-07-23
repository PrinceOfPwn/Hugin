export type PublishState = "core" | "support";

export interface Provenance {
  evidenceId: string;
  sourceClass: string;
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
  publishState: PublishState;
  evidenceId: string;
  provenance: Provenance[];
}

export interface EvidenceRecord {
  id: string;
  evidenceId: string;
  title: string;
  topic: string;
  summary: string;
  keyCues: string[];
  relatedEntityIds: string[];
  bodyRef: string;
  bodyShard: number;
  qualityScore: number;
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
  corpusHash?: string;
}

export interface DatasetManifest {
  schemaVersion: string;
  datasetVersion: string;
  sourceHash: string;
  generatedAt: string;
  commit: string;
  counts: {
    rawRecords: number;
    rawRelations: number;
    coreEntities: number;
    supportEntities: number;
    graphEntities: number;
    evidenceRecords: number;
    quarantinedEvidence: number;
    curatedRelations: number;
    evidenceLinks: number;
    membershipRelations: number;
    similarityRelations: number;
    quarantinedRelations: number;
    uniqueBodies: number;
    galaxies: number;
  };
  assets: Record<string, string>;
  similarityModel: string;
  similarityRevision: string;
  corpusHash: string;
}

export interface Galaxy {
  id: string;
  name: string;
  description: string;
  color: string;
  count: number;
  supportCount: number;
}

export interface QualityReport {
  rawCounts: { nodes: number; relations: number };
  states: Record<string, number>;
  quarantinedNodes: Array<{ id: string; type: string; reason: string }>;
  quarantinedRelations: Array<{ id: string; reason: string }>;
}
