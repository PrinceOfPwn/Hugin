import {
  useCallback, useEffect, useMemo, useState,
} from "react";
import { Canvas } from "@react-three/fiber";
import { Stars } from "@react-three/drei";
import { EffectComposer, Bloom, DepthOfField } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest } from "../lib/types";

import NodeCloud, { buildSpinRotation } from "./NodeCloud";
import type { NodeDatum, OrbitDescriptor } from "./NodeCloud";
import EdgeSet, { EDGE_COLOR } from "./EdgeSet";
import SpacetimeWarp, { type HeavyNode } from "./SpacetimeWarp";
import CinematicCamera from "./CinematicCamera";
import NebulaField, { type NebulaGalaxy } from "./NebulaField";
import SatelliteTrails, { type TrailOrbit } from "./SatelliteTrails";
import UniverseControls, { type UniverseSettings, type EdgesMode } from "./UniverseControls";

type Mode = "universe" | "galaxy" | "neighborhood";

type OrbitalElementsIn = {
  a: number; e: number; omega: number; Omega: number; incl: number; M0: number; n: number;
};

type GraphNodeIn = {
  id: string; label: string; kind: string; galaxyId: string; category: string;
  route: string; summary: string;
  scope: "core" | "support" | "structure" | "evidence";
  degree: number; size: number; color: string; isGalaxy?: boolean;
  tier?: "S" | "A" | "B" | "C";
  mass?: number;
  orbitOf?: string | null;
  orbitDistance?: number | null;
  orbit?: OrbitalElementsIn | null;
  isAttractor?: boolean;
  position?: { x: number; y: number; z: number };
};
type GraphEdgeIn = {
  id: string; source: string; target: string; type: string;
  origin?: "curated" | "similarity" | "inferred" | "membership" | "evidence";
};
type GraphDataIn = {
  nodes: GraphNodeIn[];
  edges: GraphEdgeIn[];
  positions?: Map<string, THREE.Vector3> | Record<string, { x: number; y: number; z: number }>;
  spinAxes?: Record<string, { x: number; y: number; z: number }>;
};

// ═════════════════════════════════════════════════════════════════════════════
//  Palette + labels
// ═════════════════════════════════════════════════════════════════════════════

const GALAXY_COLORS: Record<string, string> = {
  techniques:    "#ff2244",
  internals:     "#00f0ff",
  defenses:      "#39ff14",
  chains:        "#ffb700",
  evidence:      "#00e5ff",
  sources:       "#e040fb",
  gaps:          "#ff5555",
  architecture:  "#9d4edd",
  tradecraft_qa: "#00e5bf",
};
const GALAXY_LABELS: Record<string, string> = {
  techniques: "Techniques", internals: "Internals", defenses: "Defenses",
  chains: "Attack Chains", evidence: "Evidence", sources: "Sources",
  gaps: "Gaps", architecture: "Architecture", tradecraft_qa: "Q&A",
};

// Fallback spin axis when the server-provided map is missing an entry.
// (Doesn't match the server hash — only used defensively; the real axes come
// through graphData.spinAxes.)
const FALLBACK_SPIN: { x: number; y: number; z: number } = { x: 0, y: 1, z: 0 };

const NOISE_EDGE = new Set(["similar_to"]);

// ═════════════════════════════════════════════════════════════════════════════
//  Galaxy orbs — glowing markers at each galaxy centroid.
// ═════════════════════════════════════════════════════════════════════════════

function GalaxyOrbs({
  centers,
  onSelect,
}: {
  centers: Array<[string, [number, number, number]]>;
  onSelect: (galaxyId: string) => void;
}) {
  const [geo, mat] = useMemo(() => {
    const positions = new Float32Array(centers.length * 3);
    const colors = new Float32Array(centers.length * 3);
    const c = new THREE.Color();
    for (let i = 0; i < centers.length; i++) {
      const [gid, pos] = centers[i];
      positions[i * 3]     = pos[0];
      positions[i * 3 + 1] = pos[1];
      positions[i * 3 + 2] = pos[2];
      c.set(GALAXY_COLORS[gid] || "#ffffff");
      colors[i * 3]     = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    g.setAttribute("color",    new THREE.BufferAttribute(colors, 3));
    const m = new THREE.PointsMaterial({
      size: 140, sizeAttenuation: true, vertexColors: true,
      transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    return [g, m];
  }, [centers]);

  const ids = useMemo(() => centers.map(([gid]) => gid), [centers]);

  return (
    <points
      geometry={geo}
      material={mat}
      onClick={(e) => { e.stopPropagation(); const i = (e as any).index; if (i != null) onSelect(ids[i]); }}
    />
  );
}

// ═════════════════════════════════════════════════════════════════════════════
//  Main
// ═════════════════════════════════════════════════════════════════════════════

interface Props {
  graphData: GraphDataIn;
  manifest: DatasetManifest;
  filteredIds?: Set<string> | null;
  universe?: UniverseSettings;
  onUniverseChange?: (next: UniverseSettings) => void;
}

const DEFAULT_UNIVERSE: UniverseSettings = {
  edgesMode: "selected",
  autoOrbit: true,
  cinematic: true,
};

export default function GraphThreeV3({
  graphData, manifest, filteredIds,
  universe: universeProp, onUniverseChange,
}: Props) {
  const [mode, setMode] = useState<Mode>("universe");
  const [selected, setSelected] = useState<GraphNodeIn | null>(null);
  const [hovered, setHovered] = useState<{ id: string; screen: { x: number; y: number } } | null>(null);
  const [focusPos, setFocusPos] = useState<THREE.Vector3 | null>(null);
  const [galaxyFilter, setGalaxyFilter] = useState<string | null>(null);

  // Local fallback if parent doesn't lift universe settings.
  const [universeLocal, setUniverseLocal] = useState<UniverseSettings>(DEFAULT_UNIVERSE);
  const universe = universeProp ?? universeLocal;
  const setUniverse = onUniverseChange ?? setUniverseLocal;

  // ─── Positions ───────────────────────────────────────────────────────────
  const positionsMap = useMemo<Map<string, THREE.Vector3>>(() => {
    const m = new Map<string, THREE.Vector3>();
    const raw = graphData.positions;

    if (raw instanceof Map) {
      for (const [k, v] of raw) m.set(k, v.clone());
    } else if (raw && typeof raw === "object") {
      for (const k of Object.keys(raw)) {
        const v = (raw as any)[k];
        m.set(k, new THREE.Vector3(v.x, v.y, v.z));
      }
    }

    for (const n of graphData.nodes) {
      if (m.has(n.id)) continue;
      if (n.position) {
        m.set(n.id, new THREE.Vector3(n.position.x, n.position.y, n.position.z));
      } else {
        m.set(n.id, new THREE.Vector3(
          (Math.random() - 0.5) * 4,
          (Math.random() - 0.5) * 4,
          (Math.random() - 0.5) * 4,
        ));
      }
    }
    return m;
  }, [graphData]);

  // ─── Galaxy centroids ────────────────────────────────────────────────────
  const galaxyCenters = useMemo<Record<string, [number, number, number]>>(() => {
    const acc = new Map<string, { x: number; y: number; z: number; n: number }>();
    for (const n of graphData.nodes) {
      if (n.isGalaxy) continue;
      const p = positionsMap.get(n.id);
      if (!p) continue;
      const rec = acc.get(n.galaxyId) || { x: 0, y: 0, z: 0, n: 0 };
      rec.x += p.x; rec.y += p.y; rec.z += p.z; rec.n += 1;
      acc.set(n.galaxyId, rec);
    }
    const out: Record<string, [number, number, number]> = {};
    for (const [gid, r] of acc) {
      out[gid] = r.n > 0 ? [r.x / r.n, r.y / r.n, r.z / r.n] : [0, 0, 0];
    }
    return out;
  }, [graphData.nodes, positionsMap]);

  // ─── Universe bounds — used to frame the cinematic warp-in ──────────────
  const universeBounds = useMemo(() => {
    let minX = Infinity, minY = Infinity, minZ = Infinity;
    let maxX = -Infinity, maxY = -Infinity, maxZ = -Infinity;
    let any = false;
    for (const p of positionsMap.values()) {
      any = true;
      if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
      if (p.z < minZ) minZ = p.z; if (p.z > maxZ) maxZ = p.z;
    }
    if (!any) return { center: [0, 0, 0] as [number, number, number], size: 3000 };
    const size = Math.max(maxX - minX, maxY - minY, maxZ - minZ);
    return {
      center: [(minX + maxX) / 2, (minY + maxY) / 2, (minZ + maxZ) / 2] as [number, number, number],
      size,
    };
  }, [positionsMap]);

  // ─── Adjacency (curated only) ────────────────────────────────────────────
  const adjacency = useMemo(() => {
    const a = new Map<string, string[]>();
    for (const n of graphData.nodes) a.set(n.id, []);
    for (const e of graphData.edges) {
      if (NOISE_EDGE.has(e.type)) continue;
      a.get(e.source)?.push(e.target);
      a.get(e.target)?.push(e.source);
    }
    return a;
  }, [graphData]);

  // ─── Visible nodes ───────────────────────────────────────────────────────
  const visibleNodes = useMemo<NodeDatum[]>(() => {
    return graphData.nodes
      .filter((n) => !n.isGalaxy)
      .filter((n) => !galaxyFilter || n.galaxyId === galaxyFilter)
      .map((n) => {
        // Dramatic mass-driven size + attractor boost, clamped.
        let size = 1.6 + (n.mass ?? 2) * 0.9;
        if (n.isAttractor) size *= 1.7;
        size = Math.min(24, Math.max(1.6, size));
        return {
          id: n.id,
          position: positionsMap.get(n.id) ?? new THREE.Vector3(),
          color: GALAXY_COLORS[n.galaxyId] || n.color || "#888",
          size,
          kind: n.kind,
          galaxyId: n.galaxyId,
          isAttractor: n.isAttractor,
        } satisfies NodeDatum;
      });
  }, [graphData.nodes, positionsMap, galaxyFilter]);

  // ─── Per-galaxy spin rotation matrices ───────────────────────────────────
  // Server emits `spinAxes` keyed by galaxyId; we build the 9-element
  // rotation matrix once so the frame loop just multiplies against it.
  const spinRotByGalaxy = useMemo<Record<string, Float32Array>>(() => {
    const out: Record<string, Float32Array> = {};
    const axes = graphData.spinAxes || {};
    for (const n of graphData.nodes) {
      if (out[n.galaxyId]) continue;
      const axis = axes[n.galaxyId] || FALLBACK_SPIN;
      out[n.galaxyId] = buildSpinRotation(axis);
    }
    return out;
  }, [graphData.nodes, graphData.spinAxes]);

  // ─── Kepler orbit descriptors ────────────────────────────────────────────
  const orbits = useMemo<OrbitDescriptor[]>(() => {
    const indexById = new Map<string, number>();
    visibleNodes.forEach((n, i) => indexById.set(n.id, i));
    const nodeById = new Map(graphData.nodes.map((n) => [n.id, n]));
    const list: OrbitDescriptor[] = [];
    for (let i = 0; i < visibleNodes.length; i++) {
      const nd = visibleNodes[i];
      const meta = nodeById.get(nd.id);
      if (!meta?.orbitOf || !meta.orbit) continue;
      const pIdx = indexById.get(meta.orbitOf);
      if (pIdx == null) continue;
      const spin = spinRotByGalaxy[meta.galaxyId];
      if (!spin) continue;
      list.push({
        nodeIndex: i,
        parentIndex: pIdx,
        elements: meta.orbit,
        spinRot: spin,
      });
    }
    return list;
  }, [visibleNodes, graphData.nodes, spinRotByGalaxy]);

  // ─── Trail data for SatelliteTrails — one entry per orbiter ─────────────
  const trailOrbits = useMemo<TrailOrbit[]>(() => {
    const nodeById = new Map(graphData.nodes.map((n) => [n.id, n]));
    const list: TrailOrbit[] = [];
    for (const nd of visibleNodes) {
      const meta = nodeById.get(nd.id);
      if (!meta?.orbitOf || !meta.orbit) continue;
      const parentPos = positionsMap.get(meta.orbitOf);
      if (!parentPos) continue;
      const axis = graphData.spinAxes?.[meta.galaxyId] || FALLBACK_SPIN;
      list.push({
        id: nd.id,
        parentPos: [parentPos.x, parentPos.y, parentPos.z],
        elements: meta.orbit,
        spinAxis: axis,
        color: GALAXY_COLORS[meta.galaxyId] || "#888",
      });
    }
    // Trails are expensive-ish per satellite (24 samples × solve). Cap.
    return list.slice(0, 400);
  }, [visibleNodes, graphData.nodes, positionsMap, graphData.spinAxes]);

  // ─── Nebula field data ───────────────────────────────────────────────────
  const nebulaGalaxies = useMemo<NebulaGalaxy[]>(() => {
    const massByG = new Map<string, number>();
    for (const n of graphData.nodes) {
      if (n.isGalaxy) continue;
      massByG.set(n.galaxyId, (massByG.get(n.galaxyId) ?? 0) + (n.mass ?? 0));
    }
    const out: NebulaGalaxy[] = [];
    for (const [gid, center] of Object.entries(galaxyCenters)) {
      out.push({
        id: gid,
        color: GALAXY_COLORS[gid] || "#7fbfff",
        centroid: { x: center[0], y: center[1], z: center[2] },
        totalMass: massByG.get(gid) ?? 1,
      });
    }
    return out;
  }, [galaxyCenters, graphData.nodes]);

  // ─── Heavy nodes for spacetime-warp halos ────────────────────────────────
  const heavyNodes = useMemo<HeavyNode[]>(() => {
    const scored = graphData.nodes
      .filter((n) => !n.isGalaxy && (n.mass ?? 0) > 0)
      .map((n) => ({ n, mass: n.mass ?? 0 }))
      .sort((a, b) => b.mass - a.mass)
      .slice(0, 8);
    return scored
      .map(({ n, mass }) => {
        const p = positionsMap.get(n.id);
        if (!p) return null;
        return {
          id: n.id,
          mass,
          position: p,
          color: GALAXY_COLORS[n.galaxyId] || "#7fbfff",
        } as HeavyNode;
      })
      .filter((x): x is HeavyNode => x !== null);
  }, [graphData.nodes, positionsMap]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNodeIn>();
    for (const n of graphData.nodes) m.set(n.id, n);
    return m;
  }, [graphData]);

  // ─── Edges — mode-gated. Hidden by default, "selected only" when focused,
  //     and optional global top-N% by combined endpoint degree.
  const focusId = selected?.id ?? hovered?.id ?? null;

  const globalEdges = useMemo(() => {
    if (universe.edgesMode !== "top5" && universe.edgesMode !== "top20" && universe.edgesMode !== "all") return [];
    const relevant = graphData.edges.filter((e) => !NOISE_EDGE.has(e.type));
    if (universe.edgesMode === "all") return relevant;
    // Rank by combined endpoint degree.
    const degOf = (id: string) => nodeById.get(id)?.degree ?? 0;
    const ranked = [...relevant].sort((a, b) => (degOf(b.source) + degOf(b.target)) - (degOf(a.source) + degOf(a.target)));
    const pct = universe.edgesMode === "top5" ? 0.05 : 0.20;
    return ranked.slice(0, Math.max(1, Math.floor(ranked.length * pct)));
  }, [graphData.edges, universe.edgesMode, nodeById]);

  const focusEdges = useMemo(() => {
    if (universe.edgesMode === "none") return [];
    if (!focusId) return [];
    return graphData.edges.filter(
      (e) => !NOISE_EDGE.has(e.type) && (e.source === focusId || e.target === focusId)
    );
  }, [graphData.edges, focusId, universe.edgesMode]);

  const dimmedSet = useMemo<Set<string> | null>(() => {
    let selBase: Set<string> | null = null;
    if (selected) {
      selBase = new Set([selected.id]);
      for (const nid of adjacency.get(selected.id) ?? []) selBase.add(nid);
    }
    if (filteredIds && selBase) {
      const out = new Set<string>();
      for (const id of selBase) if (filteredIds.has(id)) out.add(id);
      out.add(selected!.id);
      return out;
    }
    if (filteredIds) return filteredIds;
    return selBase;
  }, [selected, adjacency, filteredIds]);

  const related = useMemo(() => {
    if (!selected) return [];
    const grouped = new Map<string, Array<{ id: string; label: string; kind: string; direction: "out" | "in" }>>();
    for (const e of graphData.edges) {
      if (NOISE_EDGE.has(e.type)) continue;
      const isOut = e.source === selected.id;
      const isIn  = e.target === selected.id;
      if (!isOut && !isIn) continue;
      const otherId = isOut ? e.target : e.source;
      const other = nodeById.get(otherId);
      if (!other) continue;
      if (!grouped.has(e.type)) grouped.set(e.type, []);
      grouped.get(e.type)!.push({ id: other.id, label: other.label, kind: other.kind, direction: isOut ? "out" : "in" });
    }
    return [...grouped.entries()].map(([type, items]) => ({ type, items })).sort((a, b) => b.items.length - a.items.length);
  }, [selected, graphData.edges, nodeById]);

  const handleNodeClick = useCallback((id: string) => {
    const node = nodeById.get(id);
    if (!node) return;
    setSelected(node);
    const pos = positionsMap.get(id);
    if (pos) setFocusPos(pos.clone());
  }, [nodeById, positionsMap]);

  const handleGalaxyClick = useCallback((gid: string) => {
    setGalaxyFilter(gid);
    setMode("galaxy");
    const c = galaxyCenters[gid];
    if (c) setFocusPos(new THREE.Vector3(c[0], c[1], c[2]));
  }, [galaxyCenters]);

  const handleReset = useCallback(() => {
    setSelected(null);
    setGalaxyFilter(null);
    setMode("universe");
    setFocusPos(null);
  }, []);

  useEffect(() => {
    console.log(`[GraphThreeV3] nodes=${visibleNodes.length}/${graphData.nodes.length}  orbits=${orbits.length}  edges_visible=${focusEdges.length + globalEdges.length}/${graphData.edges.length}  mode=${mode}  galaxy=${galaxyFilter ?? "all"}  edgesMode=${universe.edgesMode}`);
  }, [visibleNodes.length, orbits.length, focusEdges.length, globalEdges.length, mode, galaxyFilter, graphData.nodes.length, graphData.edges.length, universe.edgesMode]);

  const selectedRoute = selected?.route;
  const galaxies = Object.entries(galaxyCenters) as Array<[string, [number, number, number]]>;

  // Focus target passed to CinematicCamera — memoised so we don't retrigger
  // the tween every render.
  const cameraFocus = useMemo(() => {
    if (!focusPos) return null;
    return { position: focusPos, distance: selected ? 220 : 500 };
  }, [focusPos, selected]);

  // Stable world-space focus for the DOF pass. Prefer the selected node's
  // position; else fall back to the universe centroid.
  const dofTarget = useMemo(() => {
    if (focusPos) return focusPos;
    return new THREE.Vector3(universeBounds.center[0], universeBounds.center[1], universeBounds.center[2]);
  }, [focusPos, universeBounds]);

  return (
    <div style={{ position: "relative", width: "100%", height: "100vh", background: "#000005", color: "#e8f0ff", overflow: "hidden" }}>
      {/* ─── LEFT RAIL ───────────────────────────────────────────────────── */}
      <aside style={{
        position: "absolute", top: 0, left: 0, bottom: 0, width: 240,
        padding: "20px 18px", background: "linear-gradient(180deg, rgba(0,8,20,0.85), rgba(0,4,12,0.65))",
        borderRight: "1px solid rgba(0,240,255,0.15)", backdropFilter: "blur(8px)",
        fontFamily: "'Fira Code', ui-monospace, monospace", fontSize: 12, zIndex: 5, overflowY: "auto",
      }}>
        <div style={{ marginBottom: 22 }}>
          <div style={{ fontSize: 10, opacity: 0.6, letterSpacing: "0.14em", textTransform: "uppercase", color: "#00f0ff" }}>3D Knowledge Universe</div>
          <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: "0.05em", marginTop: 4 }}>HUGIN</div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, opacity: 0.55, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 8 }}>Mode</div>
          <button onClick={handleReset} style={btnStyle(mode === "universe")}>Universe (all)</button>
          {galaxyFilter && (
            <div style={{ marginTop: 6, fontSize: 11, opacity: 0.7 }}>
              Filtering: <span style={{ color: GALAXY_COLORS[galaxyFilter] }}>● {GALAXY_LABELS[galaxyFilter] ?? galaxyFilter}</span>
            </div>
          )}
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, opacity: 0.55, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 8 }}>Galaxies</div>
          {galaxies.map(([gid]) => (
            <button key={gid} onClick={() => handleGalaxyClick(gid)}
              style={{ ...btnStyle(galaxyFilter === gid), textAlign: "left", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: GALAXY_COLORS[gid], fontSize: 14, lineHeight: 1 }}>●</span>
              <span>{GALAXY_LABELS[gid] ?? gid}</span>
            </button>
          ))}
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, opacity: 0.55, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 8 }}>Signals</div>
          <div style={{ fontSize: 10, opacity: 0.55, lineHeight: 1.6, marginBottom: 8 }}>Hover a node to see its links. Click to inspect.</div>
          {Object.entries(EDGE_COLOR).filter(([t]) => t !== "similar_to" && t !== "reference").slice(0, 8).map(([t, c]) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, opacity: 0.75, marginBottom: 3 }}>
              <span style={{ width: 18, height: 2, background: c, display: "inline-block" }} />
              <span>{t.replace(/_/g, " ")}</span>
            </div>
          ))}
        </div>

        <div style={{ position: "absolute", bottom: 16, left: 18, right: 18, fontSize: 10, opacity: 0.5, lineHeight: 1.5 }}>
          {graphData.nodes.filter((n) => !n.isGalaxy).length.toLocaleString()} nodes<br />
          {graphData.edges.filter((e) => !NOISE_EDGE.has(e.type)).length.toLocaleString()} curated edges<br />
          {manifest.counts.galaxies} galaxies
        </div>
      </aside>

      {/* ─── CANVAS ──────────────────────────────────────────────────────── */}
      <div style={{ position: "absolute", top: 0, left: 240, right: selected ? 360 : 0, bottom: 0, transition: "right 0.25s ease" }}>
        <Canvas
          camera={{ position: [0, 0, 8000], fov: 55, near: 0.1, far: 20000 }}
          dpr={[1, 1.6]}
          gl={{ antialias: true, powerPreference: "high-performance", alpha: false }}
        >
          <color attach="background" args={["#000005"]} />
          <fogExp2 attach="fog" args={["#0a0a15", universe.cinematic ? 0.00025 : 0.00045]} />

          <ambientLight intensity={0.15} color="#4455ff" />
          <pointLight position={[400, 400, 300]}  intensity={1.2} color="#00d0ff" distance={2500} />
          <pointLight position={[-400, -300, -300]} intensity={1.0} color="#ff2288" distance={2000} />

          <Stars radius={universeBounds.size * 2} depth={universeBounds.size} count={6000} factor={6} saturation={0} fade speed={0.3} />

          <NebulaField galaxies={nebulaGalaxies} intensity={universe.cinematic ? 0.18 : 0.10} />
          <GalaxyOrbs centers={galaxies} onSelect={handleGalaxyClick} />
          <SpacetimeWarp heavyNodes={heavyNodes} />

          {universe.cinematic && (
            <SatelliteTrails orbits={trailOrbits} trailLength={24} intensity={0.55} />
          )}

          <NodeCloud
            nodes={visibleNodes}
            orbits={orbits}
            hoveredId={hovered?.id ?? null}
            selectedId={selected?.id ?? null}
            dimmedSet={dimmedSet}
            onHover={(id, screen) => setHovered(id ? { id, screen: screen ?? { x: 0, y: 0 } } : null)}
            onClick={handleNodeClick}
          />

          {globalEdges.length > 0 && (
            <EdgeSet edges={globalEdges} positions={positionsMap} opacity={0.10} />
          )}
          {focusEdges.length > 0 && (
            <EdgeSet
              edges={focusEdges}
              positions={positionsMap}
              opacity={selected ? 0.9 : 0.45}
              focusColor={selected ? undefined : "#00e5ff"}
            />
          )}

          <CinematicCamera
            bounds={universeBounds}
            autoOrbit={universe.autoOrbit}
            focus={cameraFocus}
          />

          <EffectComposer>
            <Bloom intensity={0.45} luminanceThreshold={0.75} luminanceSmoothing={0.9} radius={0.6} mipmapBlur />
            {universe.cinematic ? (
              <DepthOfField target={dofTarget} focalLength={0.05} bokehScale={3} height={480} />
            ) : <></>}
          </EffectComposer>
        </Canvas>

        <button onClick={handleReset} style={{
          position: "absolute", top: 16, right: 16, zIndex: 4,
          background: "rgba(0,8,20,0.75)", border: "1px solid rgba(0,240,255,0.35)",
          color: "#00f0ff", padding: "6px 14px", fontFamily: "monospace",
          fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em",
          cursor: "pointer", backdropFilter: "blur(6px)",
        }}>Reset view</button>

        <UniverseControls value={universe} onChange={setUniverse} />

        {hovered && !selected && (() => {
          const node = nodeById.get(hovered.id);
          if (!node) return null;
          const gc = GALAXY_COLORS[node.galaxyId] || "#00f0ff";
          return (
            <div style={{
              position: "fixed", left: hovered.screen.x + 16, top: hovered.screen.y + 16,
              background: "rgba(0,8,20,0.92)", border: `1px solid ${gc}`,
              boxShadow: `0 0 24px ${gc}44`,
              padding: "8px 14px", fontFamily: "monospace", fontSize: 12, color: "#fff",
              maxWidth: 360, pointerEvents: "none", zIndex: 100,
              backdropFilter: "blur(6px)",
            }}>
              <div style={{ fontSize: 9, opacity: 0.6, letterSpacing: "0.14em", textTransform: "uppercase", color: gc, marginBottom: 3 }}>
                {GALAXY_LABELS[node.galaxyId] ?? node.galaxyId} · {node.kind.replace(/_/g, " ")}{node.tier ? ` · Tier ${node.tier}` : ""}
              </div>
              <div style={{ fontWeight: 700, marginBottom: 3 }}>{node.label}</div>
              <div style={{ fontSize: 10, opacity: 0.7 }}>{node.degree} connections · click to inspect</div>
            </div>
          );
        })()}
      </div>

      {/* ─── RIGHT INSPECTOR ─────────────────────────────────────────────── */}
      {selected && (
        <aside style={{
          position: "absolute", top: 0, right: 0, bottom: 0, width: 360,
          background: "linear-gradient(180deg, rgba(0,10,24,0.95), rgba(0,4,12,0.85))",
          borderLeft: `1px solid ${GALAXY_COLORS[selected.galaxyId] ?? "#00f0ff"}55`,
          backdropFilter: "blur(10px)", padding: "18px 20px", overflowY: "auto", zIndex: 6,
          fontFamily: "system-ui, sans-serif", fontSize: 13, lineHeight: 1.55,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div style={{ fontSize: 10, opacity: 0.6, letterSpacing: "0.14em", textTransform: "uppercase", fontFamily: "monospace", color: GALAXY_COLORS[selected.galaxyId] }}>
              {GALAXY_LABELS[selected.galaxyId] ?? selected.galaxyId} · {selected.kind.replace(/_/g, " ")}
              {selected.tier && <span> · Tier {selected.tier}</span>}
            </div>
            <button onClick={() => { setSelected(null); }} style={{
              background: "transparent", border: "none", color: "#88a", fontSize: 18, cursor: "pointer",
              fontFamily: "monospace", padding: 0, lineHeight: 1,
            }} aria-label="Close">×</button>
          </div>

          <h2 style={{ margin: "0 0 12px 0", fontSize: 20, fontWeight: 700, letterSpacing: "-0.01em" }}>{selected.label}</h2>

          <div style={{ fontSize: 12, opacity: 0.82, marginBottom: 16 }}>{selected.summary}</div>

          {selectedRoute && (
            <a href={`/Hugin${selectedRoute}`} style={{
              display: "inline-block", padding: "8px 14px", background: GALAXY_COLORS[selected.galaxyId] ?? "#00f0ff",
              color: "#000", textDecoration: "none", fontFamily: "monospace", fontSize: 11,
              textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 20,
            }}>Open full record →</a>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 20 }}>
            <div><div style={{ fontSize: 9, opacity: 0.5, textTransform: "uppercase", letterSpacing: "0.14em" }}>Category</div><div style={{ fontSize: 12, marginTop: 2 }}>{selected.category}</div></div>
            <div><div style={{ fontSize: 9, opacity: 0.5, textTransform: "uppercase", letterSpacing: "0.14em" }}>Connections</div><div style={{ fontSize: 12, marginTop: 2 }}>{selected.degree}</div></div>
          </div>

          {related.length > 0 && (
            <div>
              <div style={{ fontSize: 10, opacity: 0.55, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>Signal Traffic</div>
              {related.map(({ type, items }) => (
                <div key={type} style={{ marginBottom: 12, borderLeft: `2px solid ${EDGE_COLOR[type] ?? "#556"}`, paddingLeft: 10 }}>
                  <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", opacity: 0.65, marginBottom: 4, color: EDGE_COLOR[type] }}>
                    {type.replace(/_/g, " ")} ({items.length})
                  </div>
                  {items.slice(0, 12).map((it) => (
                    <button key={it.id + it.direction} onClick={() => handleNodeClick(it.id)} style={{
                      display: "block", width: "100%", textAlign: "left", background: "transparent",
                      border: "none", color: "#e8f0ff", padding: "3px 0", fontSize: 12, cursor: "pointer",
                      opacity: 0.85, fontFamily: "inherit",
                    }}>
                      <span style={{ opacity: 0.5 }}>{it.direction === "out" ? "→" : "←"}</span> {it.label}
                      <span style={{ opacity: 0.4, fontSize: 10, marginLeft: 4 }}>· {it.kind.replace(/_/g, " ")}</span>
                    </button>
                  ))}
                  {items.length > 12 && <div style={{ fontSize: 10, opacity: 0.4, marginTop: 3 }}>+ {items.length - 12} more</div>}
                </div>
              ))}
            </div>
          )}
        </aside>
      )}
    </div>
  );
}

function btnStyle(active: boolean): React.CSSProperties {
  return {
    display: "block", width: "100%", padding: "6px 10px", marginBottom: 4,
    background: active ? "rgba(0,240,255,0.15)" : "transparent",
    border: `1px solid ${active ? "rgba(0,240,255,0.4)" : "rgba(255,255,255,0.08)"}`,
    color: active ? "#00f0ff" : "#c8d4e8",
    fontFamily: "monospace", fontSize: 11, cursor: "pointer", textAlign: "left",
  };
}

// Re-export types for GraphPageShell.
export type { UniverseSettings, EdgesMode };
