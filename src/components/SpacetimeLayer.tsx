/*
 * SpacetimeLayer — spacetime wireframe, grab-drag of heavy nodes OR whole
 * galaxies, and gravity ripple on release.
 *
 * grabTarget:
 *   "nodes"    (default) — legacy behavior. Individual heavy nodes grabbable.
 *   "galaxies" — each galaxy exposes ONE big invisible hitbox at its centroid,
 *                sized by log(totalMass). Dragging translates every member of
 *                that galaxy by the same delta, so the whole cluster follows.
 *                The gravity grid sees galaxy centroids as heavy attractors
 *                and warps accordingly — bigger, more dramatic than single-
 *                node dragging.
 */

import { useMemo, useRef, useState } from "react";
import type { Entity } from "../lib/types";
import SpacetimeGrid, { type SpacetimeHeavyNode } from "./SpacetimeGrid";
import PlanetGrabber, { type GrabCandidate } from "./PlanetGrabber";
import GravityPulse from "./GravityPulse";

interface Props {
  mode: "off" | "grid" | "playground";
  entities: Entity[];
  onNodeMoved?: (id: string, newPosition: [number, number, number]) => void;
  intensity?: number;
  paletteHint?: "cool" | "warm" | "duo";
  grabTarget?: "nodes" | "galaxies";
}

const HEAVY_K = 16;
const ATTRACTOR_MASS_MIN = 3.0;
// Sentinel prefix marks synthetic galaxy attractors so downstream code can
// filter them out (NodeCloud shouldn't try to render them, etc.).
const GALAXY_ID_PREFIX = "__galaxy:";

type GalaxyRecord = {
  galaxyId: string;
  centroid: [number, number, number];
  totalMass: number;
  memberInitialPositions: Map<string, [number, number, number]>;
};

function buildGalaxies(entities: Entity[]): GalaxyRecord[] {
  const acc = new Map<string, {
    sumX: number; sumY: number; sumZ: number; count: number;
    totalMass: number;
    members: Map<string, [number, number, number]>;
  }>();
  for (const e of entities) {
    const gid = e.galaxyId;
    if (!gid || !e.position) continue;
    let rec = acc.get(gid);
    if (!rec) {
      rec = { sumX: 0, sumY: 0, sumZ: 0, count: 0, totalMass: 0, members: new Map() };
      acc.set(gid, rec);
    }
    rec.sumX += e.position.x;
    rec.sumY += e.position.y;
    rec.sumZ += e.position.z;
    rec.count += 1;
    rec.totalMass += e.mass ?? 1;
    rec.members.set(e.id, [e.position.x, e.position.y, e.position.z]);
  }
  const out: GalaxyRecord[] = [];
  for (const [galaxyId, rec] of acc) {
    if (rec.count === 0) continue;
    out.push({
      galaxyId,
      centroid: [rec.sumX / rec.count, rec.sumY / rec.count, rec.sumZ / rec.count],
      totalMass: rec.totalMass,
      memberInitialPositions: rec.members,
    });
  }
  return out;
}

export default function SpacetimeLayer({
  mode,
  entities,
  onNodeMoved,
  intensity = 0.6,
  paletteHint = "duo",
  grabTarget = "nodes",
}: Props) {
  // ── Galaxy structure — computed once per entities/mode change ────────────
  const galaxies = useMemo(
    () => (mode === "off" ? [] : buildGalaxies(entities)),
    [entities, mode],
  );
  const galaxyById = useMemo(() => {
    const m = new Map<string, GalaxyRecord>();
    for (const g of galaxies) m.set(g.galaxyId, g);
    return m;
  }, [galaxies]);

  // ── Heavy attractors for the grid displacement ────────────────────────────
  // In "galaxies" mode we replace individual node attractors with galaxy
  // centroids. The grid vertex shader supports up to HEAVY_K entries; galaxies
  // are ranked by totalMass so the biggest clusters dominate the warp.
  const heavyNodes: SpacetimeHeavyNode[] = useMemo(() => {
    if (mode === "off") return [];
    if (grabTarget === "galaxies") {
      const sorted = [...galaxies].sort((a, b) => b.totalMass - a.totalMass);
      return sorted.slice(0, HEAVY_K).map((g) => ({
        id: GALAXY_ID_PREFIX + g.galaxyId,
        position: g.centroid,
        // Galaxy centroids get a moderate mass boost so their gravity wells
        // are visibly deeper than a single-node attractor at the same spot.
        mass: Math.max(3, Math.log2(g.totalMass + 1) * 2.5),
      }));
    }
    const withMass = entities.filter(
      (e) => (e.mass ?? 0) > 0 && e.position !== undefined,
    );
    withMass.sort((a, b) => (b.mass ?? 0) - (a.mass ?? 0));
    return withMass.slice(0, HEAVY_K).map((e) => ({
      id: e.id,
      position: [e.position!.x, e.position!.y, e.position!.z] as [number, number, number],
      mass: e.mass ?? 1,
    }));
  }, [entities, mode, grabTarget, galaxies]);

  // ── Grabber candidates ────────────────────────────────────────────────────
  const hitCandidates: GrabCandidate[] = useMemo(() => {
    if (mode !== "playground") return [];
    if (grabTarget === "galaxies") {
      // One giant hit sphere per galaxy at its centroid, radius scales with
      // sqrt(totalMass) so a 700-node cluster is much easier to grab than a
      // 12-node one.
      return galaxies.map((g) => ({
        id: GALAXY_ID_PREFIX + g.galaxyId,
        position: g.centroid,
        size: 40 + Math.min(160, Math.sqrt(g.totalMass) * 6),
        mass: g.totalMass,
      }));
    }
    const out: GrabCandidate[] = [];
    for (const e of entities) {
      const m = e.mass ?? 0;
      if (m < ATTRACTOR_MASS_MIN || !e.position) continue;
      const size = 8 + Math.min(24, m * 2.5);
      out.push({
        id: e.id,
        position: [e.position.x, e.position.y, e.position.z],
        size,
        mass: m,
      });
    }
    return out;
  }, [entities, mode, grabTarget, galaxies]);

  // ── Live overrides — position map that shadows entity.position while a
  // ── node OR whole galaxy is being dragged. NodeCloud (via GraphThreeV3)
  // ── reads back the same overrides, so members visibly translate with
  // ── their galaxy.
  const overridesRef = useRef<Map<string, [number, number, number]>>(new Map());
  const [pulse, setPulse] = useState<{ origin: [number, number, number]; triggerId: number } | null>(null);

  // Track the initial centroid so we can compute the delta each pointer tick.
  const galaxyDragOriginRef = useRef<[number, number, number] | null>(null);
  const galaxyDragMembersRef = useRef<Map<string, [number, number, number]> | null>(null);

  const heavyNodesLive = useMemo(() => {
    if (overridesRef.current.size === 0) return heavyNodes;
    return heavyNodes.map((n) => {
      const o = overridesRef.current.get(n.id);
      return o ? { ...n, position: o } : n;
    });
  }, [heavyNodes, pulse]);

  if (mode === "off") return null;

  const handleGrabStart = (id: string) => {
    if (!id.startsWith(GALAXY_ID_PREFIX)) return;
    const galaxyId = id.slice(GALAXY_ID_PREFIX.length);
    const g = galaxyById.get(galaxyId);
    if (!g) return;
    galaxyDragOriginRef.current = [...g.centroid];
    galaxyDragMembersRef.current = g.memberInitialPositions;
  };

  const handleGrabMove = (id: string, pos: { x: number; y: number; z: number }) => {
    if (id.startsWith(GALAXY_ID_PREFIX)) {
      // Compute delta from initial centroid and translate every member.
      const origin = galaxyDragOriginRef.current;
      const members = galaxyDragMembersRef.current;
      if (!origin || !members) return;
      const dx = pos.x - origin[0];
      const dy = pos.y - origin[1];
      const dz = pos.z - origin[2];
      overridesRef.current.set(id, [pos.x, pos.y, pos.z]);
      for (const [memberId, mp] of members) {
        const nx = mp[0] + dx, ny = mp[1] + dy, nz = mp[2] + dz;
        overridesRef.current.set(memberId, [nx, ny, nz]);
        onNodeMoved?.(memberId, [nx, ny, nz]);
      }
    } else {
      overridesRef.current.set(id, [pos.x, pos.y, pos.z]);
      onNodeMoved?.(id, [pos.x, pos.y, pos.z]);
    }
    // Bump pulse state to re-derive heavyNodesLive memo.
    setPulse((p) => (p ? { ...p } : p));
  };

  const handleGrabEnd = (id: string, finalPos: { x: number; y: number; z: number }) => {
    setPulse({
      origin: [finalPos.x, 0.1, finalPos.z],
      triggerId: Date.now(),
    });
    if (id.startsWith(GALAXY_ID_PREFIX)) {
      overridesRef.current.delete(id);
      const members = galaxyDragMembersRef.current;
      if (members) for (const memberId of members.keys()) overridesRef.current.delete(memberId);
      galaxyDragOriginRef.current = null;
      galaxyDragMembersRef.current = null;
    } else {
      overridesRef.current.delete(id);
    }
  };

  return (
    <group>
      <SpacetimeGrid
        heavyNodes={heavyNodesLive}
        visible={true}
        intensity={intensity}
        paletteHint={paletteHint}
      />

      {mode === "playground" && (
        <>
          <PlanetGrabber
            hitCandidates={hitCandidates}
            enabled={true}
            mode="spring-back"
            onGrabStart={handleGrabStart}
            onGrabMove={handleGrabMove}
            onGrabEnd={handleGrabEnd}
          />

          <GravityPulse
            origin={pulse?.origin ?? null}
            triggerId={pulse?.triggerId}
            color={grabTarget === "galaxies" ? "#ff6f00" : "#00f0ff"}
            speed={grabTarget === "galaxies" ? 400 : 250}
            duration={grabTarget === "galaxies" ? 2.4 : 1.8}
          />
        </>
      )}
    </group>
  );
}
