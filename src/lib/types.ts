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
  mass?: number;
  charCount?: number;
  orbitOf?: string | null;
  orbitDistance?: number | null;
  position?: { x: number; y: number; z: number };
  firstSeenAt?: string | null;
  lastUpdatedAt?: string | null;
  // Kepler orbital elements — present only when orbitOf is set. Consumed by
  // the cinematic renderer to draw closed-form elliptic satellite orbits.
  orbit?: {
    a: number;
    e: number;
    omega: number;
    Omega: number;
    incl: number;
    M0: number;
    n: number;
  } | null;
  // Top-3 mass nodes per galaxy — rendered larger and brighter.
  isAttractor?: boolean;
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
    // AI pipeline fields (0 until enrich workflow runs)
    aiEnrichedEntities?: number;
    inferredRelations?: number;
    bridgeConcepts?: number;
  };
  assets: Record<string, string>;
  similarityModel: string;
  similarityRevision: string;
  corpusHash: string;
  // AI pipeline top-level fields
  aiModel?: string;
  topBridges?: string[];
  layout_version?: string;
}

export interface Galaxy {
  id: string;
  name: string;
  description: string;
  color: string;
  count: number;
  supportCount: number;
  totalMass?: number;
  centroid?: { x: number; y: number; z: number };
  // Deterministic per-galaxy unit vector — defines the preferred orbital plane
  // for satellites of attractors inside this galaxy.
  spinAxis?: { x: number; y: number; z: number };
}

export interface QualityReport {
  rawCounts: { nodes: number; relations: number };
  states: Record<string, number>;
  quarantinedNodes: Array<{ id: string; type: string; reason: string }>;
  quarantinedRelations: Array<{ id: string; reason: string }>;
}
