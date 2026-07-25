import {
  useCallback, useEffect, useMemo, useRef, useState,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Stars, CameraControls } from "@react-three/drei";
import { EffectComposer, Bloom, ChromaticAberration } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest, EvidenceRecord } from "../lib/types";

import GlyphNodes from "./GlyphNodes";
import type { GlyphNodeData, NodeKind } from "./GlyphNodes";
import SemanticEdges from "./SemanticEdges";
import type { EdgeType, SemanticEdge } from "./SemanticEdges";
import FreeFlyCamera from "./FreeFlyCamera";
import ClickShockwave from "./ClickShockwave";
import HolographicGrid from "./HolographicGrid";
import AmbientDust from "./AmbientDust";
import WarpJump from "./WarpJump";
import KindLegend from "./KindLegend";
import RichInspector from "./RichInspector";

type Mode = "universe" | "galaxy" | "neighborhood" | "path";
type CameraMode = "orbit" | "freefly";

type GraphNodeIn = {
  id: string; label: string; kind: string; galaxyId: string; category: string;
  route: string; summary: string; scope: "core" | "support" | "structure" | "evidence";
  degree: number; size: number; color: string; isGalaxy?: boolean;
  tier?: "S" | "A" | "B" | "C";
  rawEvidence?: EvidenceRecord;
};
type GraphEdgeIn = {
  id: string; source: string; target: string; type: string;
  origin?: "curated" | "similarity" | "inferred" | "membership" | "evidence";
};
type GraphDataIn = {
  nodes: GraphNodeIn[];
  edges: GraphEdgeIn[];
  positions?: Map<string, THREE.Vector3> | Record<string, { x: number; y: number; z: number }>;
};

const GALAXY_CENTERS: Record<string, [number, number, number]> = {
  techniques: [280,40,60], internals: [-200,180,-80], defenses: [-240,-150,40],
  chains: [100,-220,120], evidence: [-80,80,-260], sources: [60,200,220],
  gaps: [200,-80,-180], architecture: [-120,-200,-140], tradecraft_qa: [0,300,150],
};
const GALAXY_COLORS: Record<string, string> = {
  techniques: "#ff2244", internals: "#00f0ff", defenses: "#39ff14",
  chains: "#ffb700", evidence: "#00e5ff", sources: "#e040fb",
  gaps: "#ff5555", architecture: "#9d4edd", tradecraft_qa: "#00e5bf",
};

const VALID_EDGE_TYPES: EdgeType[] = [
  "enables", "counters", "detects", "chains_to", "requires",
  "implements", "derived_from", "alternative_to", "related",
  "concept_link", "reference", "enhances",
];
const VALID_NODE_KINDS: NodeKind[] = [
  "technique", "chain", "detection", "concept", "lgtm_note",
  "playbook", "source", "source-extract", "documentation", "reference", "pattern",
];

// similarity edges are exploratory noise — off by default (75K would blow the GPU)
const NOISE_EDGE_TYPES = new Set<string>(["similar_to"]);
const MAX_EDGES_RENDERED = 4000;

interface Props {
  graphData: GraphDataIn;
  manifest: DatasetManifest;
}

// ═════════════════════════════════════════════════════════════════════════════
//  DETERMINISTIC 3D LAYOUT
//
//  The previous version ran spring-physics on 9445 nodes × 78K edges in the
//  browser — that collapses every galaxy into a tight clump (each node has
//  ~15 neighbors all pulling toward the same centroid).
//
//  This layout is O(N), hash-derived, always spread. Nodes stay clickable
//  because they never overlap: each entity gets a stable spherical position
//  around its galaxy center, distance 40..180 units, evenly distributed in
//  spherical coordinates.
// ═════════════════════════════════════════════════════════════════════════════
function shortHash(s: string, len = 8): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(16).padStart(8, "0").slice(0, len);
}
function derivedPositions(nodes: GraphNodeIn[]): Map<string, THREE.Vector3> {
  // Distribute nodes evenly in a sphere shell around each galaxy center.
  // Larger galaxies get proportionally bigger shells so density stays constant.
  const perGalaxy = new Map<string, number>();
  for (const n of nodes) if (!n.isGalaxy) perGalaxy.set(n.galaxyId, (perGalaxy.get(n.galaxyId) || 0) + 1);

  const galaxyRadius = new Map<string, number>();
  for (const [gid, count] of perGalaxy) {
    // radius ∝ cbrt(count) so density (nodes per volume) stays constant across galaxies
    galaxyRadius.set(gid, 55 + Math.cbrt(count) * 22);
  }

  const galaxyCursor = new Map<string, number>();
  const galaxyTotal = perGalaxy;
  const m = new Map<string, THREE.Vector3>();

  // pre-sort by ID so positions are deterministic across builds
  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));

  for (const n of sorted) {
    if (n.isGalaxy) {
      const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
      m.set(n.id, new THREE.Vector3(c[0], c[1], c[2]));
      continue;
    }
    const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
    const R = galaxyRadius.get(n.galaxyId) ?? 100;

    // Fibonacci-sphere for even distribution within the shell
    const idx   = galaxyCursor.get(n.galaxyId) ?? 0;
    const total = galaxyTotal.get(n.galaxyId) ?? 1;
    galaxyCursor.set(n.galaxyId, idx + 1);

    const phi     = Math.acos(1 - 2 * (idx + 0.5) / total);
    const theta   = Math.PI * (1 + Math.sqrt(5)) * idx;

    // radial jitter from hash so it doesn't look like a perfect shell
    const h = parseInt(shortHash(`${n.id}:r`, 6), 16) / 0xffffff;
    const r = R * (0.55 + h * 0.45);

    m.set(n.id, new THREE.Vector3(
      c[0] + r * Math.sin(phi) * Math.cos(theta),
      c[1] + r * Math.sin(phi) * Math.sin(theta),
      c[2] + r * Math.cos(phi),
    ));
  }
  return m;
}

function GalaxyCloud({ center, color }: { center: [number, number, number]; color: string }) {
  const ref = useRef<THREE.Points>(null);
  const [geo, mat] = useMemo(() => {
    const N = 800;   // reduced from 2000 — each galaxy had 2K particles × 9 = 18K point overhead
    const pos = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    const c = new THREE.Color(color);
    for (let i = 0; i < N; i++) {
      const r = Math.pow(Math.random(), 0.5) * 160;
      const branch = Math.random() * Math.PI * 2;
      const spin = r * 0.04;
      pos[i*3]   = Math.cos(branch+spin)*r + (Math.random()-0.5)*20*(1-r/160);
      pos[i*3+1] = (Math.random()-0.5)*12*(1-r/160);
      pos[i*3+2] = Math.sin(branch+spin)*r + (Math.random()-0.5)*20*(1-r/160);
      const f = 1 - r/160;
      col[i*3]=c.r*f; col[i*3+1]=c.g*f; col[i*3+2]=c.b*f;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const m = new THREE.PointsMaterial({
      size: 1.6, sizeAttenuation: true, vertexColors: true, transparent: true,
      opacity: 0.28, blending: THREE.AdditiveBlending, depthWrite: false,
    });
    return [g, m];
  }, [color]);
  useFrame(({ clock }) => { if (ref.current) ref.current.rotation.y = clock.getElapsedTime() * 0.04; });
  return <points ref={ref} geometry={geo} material={mat} position={center} />;
}

function CameraVelocityTracker({ onVelocity }: { onVelocity: (v: number) => void }) {
  const { camera } = useThree();
  const prev = useRef(new THREE.Vector3());
  useFrame(() => {
    const d = camera.position.distanceTo(prev.current);
    onVelocity(d);
    prev.current.copy(camera.position);
  });
  return null;
}

export default function GraphThreeV3({ graphData, manifest }: Props) {
  const [mode, setMode] = useState<Mode>("universe");
  const [cameraMode, setCameraMode] = useState<CameraMode>("orbit");
  const [selected, setSelected] = useState<GraphNodeIn | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [depth, setDepth] = useState(1);
  const [showSimilarity, setShowSimilarity] = useState(false);

  const [activeKinds, setActiveKinds] = useState<Set<string>>(new Set(VALID_NODE_KINDS));
  const [activeEdgeTypes, setActiveEdgeTypes] = useState<Set<string>>(new Set(VALID_EDGE_TYPES));

  const [shockwave, setShockwave] = useState<{ origin: THREE.Vector3; id: string; color: string } | null>(null);
  const [warp, setWarp] = useState<{ from: THREE.Vector3; to: THREE.Vector3; color: string } | null>(null);
  const [camVelocity, setCamVelocity] = useState(0);
  const controlsRef = useRef<CameraControls>(null);

  // Positions — server-supplied if present, else derive deterministically.
  const positionsMap = useMemo<Map<string, THREE.Vector3>>(() => {
    const raw = graphData.positions;
    if (raw instanceof Map && raw.size > 0) return raw;
    if (raw && typeof raw === "object" && !(raw instanceof Map)) {
      const keys = Object.keys(raw);
      if (keys.length > 0) {
        const m = new Map<string, THREE.Vector3>();
        for (const k of keys) {
          const v = (raw as Record<string, { x: number; y: number; z: number }>)[k];
          m.set(k, new THREE.Vector3(v.x, v.y, v.z));
        }
        return m;
      }
    }
    return derivedPositions(graphData.nodes);
  }, [graphData]);

  // Adjacency (curated + inferred only — similarity ignored)
  const adjacency = useMemo(() => {
    const a = new Map<string, string[]>();
    graphData.nodes.forEach((n) => a.set(n.id, []));
    for (const e of graphData.edges) {
      if (NOISE_EDGE_TYPES.has(e.type)) continue;
      a.get(e.source)?.push(e.target);
      a.get(e.target)?.push(e.source);
    }
    return a;
  }, [graphData]);

  const visibleSet = useMemo<Set<string> | null>(() => {
    if (mode === "neighborhood" && selected) {
      const vis = new Set([selected.id]);
      let frontier = new Set([selected.id]);
      for (let h = 0; h < depth; h++) {
        const next = new Set<string>();
        for (const id of frontier) for (const nid of adjacency.get(id) ?? []) if (!vis.has(nid)) { vis.add(nid); next.add(nid); }
        frontier = next;
      }
      return vis;
    }
    return null;
  }, [mode, selected, depth, adjacency]);

  const glyphNodes: GlyphNodeData[] = useMemo(() => {
    return graphData.nodes
      .filter((n) => !n.isGalaxy && activeKinds.has(n.kind))
      .map((n) => ({
        id: n.id,
        position: positionsMap.get(n.id) ?? new THREE.Vector3(),
        color: GALAXY_COLORS[n.galaxyId] || n.color,
        // Bumped baseline size so clicks are easier at ~500 unit distance.
        // techniques get a larger baseline (readable at overview zoom).
        size: Math.max(4.5, n.size * 1.7),
        kind: (VALID_NODE_KINDS.includes(n.kind as NodeKind) ? n.kind : "reference") as NodeKind,
        tier: n.tier,
      }));
  }, [graphData, activeKinds, positionsMap]);

  // Edges — filter aggressively so the GPU doesn't melt.
  //
  //   1. similarity edges hidden by default (toggle to show)
  //   2. When hidden but selected is set, show only similarity edges touching selected
  //   3. Hard cap MAX_EDGES_RENDERED — priority to edges touching selected/hovered.
  const semanticEdges: SemanticEdge[] = useMemo(() => {
    const collected: SemanticEdge[] = [];
    for (const e of graphData.edges) {
      if (visibleSet && (!visibleSet.has(e.source) || !visibleSet.has(e.target))) continue;
      if (!activeEdgeTypes.has(e.type)) continue;
      if (NOISE_EDGE_TYPES.has(e.type)) {
        if (!showSimilarity) {
          // still allow similarity edges touching selected — helpful for exploration
          if (!selected || (e.source !== selected.id && e.target !== selected.id)) continue;
        }
      }
      collected.push({
        id: e.id, source: e.source, target: e.target,
        type: (VALID_EDGE_TYPES.includes(e.type as EdgeType) ? e.type : "related") as EdgeType,
      });
    }
    if (collected.length <= MAX_EDGES_RENDERED) return collected;

    const focusId = selected?.id ?? hovered ?? null;
    const priority: SemanticEdge[] = [];
    const rest: SemanticEdge[] = [];
    for (const e of collected) {
      if (focusId && (e.source === focusId || e.target === focusId)) priority.push(e);
      else rest.push(e);
    }
    const budget = MAX_EDGES_RENDERED - priority.length;
    return budget > 0 ? [...priority, ...rest.slice(0, budget)] : priority.slice(0, MAX_EDGES_RENDERED);
  }, [graphData.edges, activeEdgeTypes, visibleSet, selected, hovered, showSimilarity]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNodeIn>();
    graphData.nodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [graphData]);

  const relatedItems = useMemo(() => {
    if (!selected) return [];
    return graphData.edges
      .filter((e) => (e.source === selected.id || e.target === selected.id) && !NOISE_EDGE_TYPES.has(e.type))
      .map((e) => {
        const isOut = e.source === selected.id;
        const otherId = isOut ? e.target : e.source;
        const other = nodeById.get(otherId);
        if (!other) return null;
        return {
          edgeType: e.type,
          direction: (isOut ? "outgoing" : "incoming") as "outgoing" | "incoming",
          otherId,
          otherLabel: other.label,
          otherKind: other.kind,
          otherGalaxy: other.galaxyId,
        };
      })
      .filter(Boolean) as any;
  }, [selected, graphData.edges, nodeById]);

  const handleNodeClick = useCallback((id: string) => {
    const node = nodeById.get(id);
    if (!node) return;
    setSelected(node);
    const pos = positionsMap.get(id);
    if (pos) {
      setShockwave({ origin: pos.clone(), id, color: GALAXY_COLORS[node.galaxyId] || "#00f0ff" });
      if (cameraMode === "orbit" && controlsRef.current) {
        controlsRef.current.setLookAt(
          pos.x + 90, pos.y + 40, pos.z + 90,
          pos.x, pos.y, pos.z, true,
        );
      }
    }
  }, [nodeById, positionsMap, cameraMode]);

  const handleGalaxyWarp = useCallback((galaxyId: string) => {
    const to = new THREE.Vector3(...GALAXY_CENTERS[galaxyId]);
    const cam = controlsRef.current?.camera;
    if (!cam) return;
    setWarp({ from: cam.position.clone(), to, color: GALAXY_COLORS[galaxyId] || "#00f0ff" });
  }, []);

  const toggleKind = useCallback((id: string) => {
    setActiveKinds(prev => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }, []);
  const toggleEdgeType = useCallback((id: string) => {
    setActiveEdgeTypes(prev => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }, []);

  const chromatic: [number, number] = useMemo(() => {
    const base = 0.0003;
    const boost = Math.min(camVelocity * 0.0004, 0.004);
    return [base + boost, base + boost];
  }, [camVelocity]);

  // Diagnostic — one log so you can see actual counts in the console.
  useEffect(() => {
    const total = graphData.edges.length;
    const noise = graphData.edges.filter((e) => NOISE_EDGE_TYPES.has(e.type)).length;
    console.log(`[GraphThreeV3] nodes=${graphData.nodes.length}  edges_total=${total}  similarity=${noise}  rendering_edges=${semanticEdges.length}  rendering_nodes=${glyphNodes.length}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData.nodes.length, graphData.edges.length, semanticEdges.length, glyphNodes.length]);

  return (
    <div className="graph-page">
      <header className="graph-topbar">
        <div className="graph-title">
          <p className="eyebrow">3D Knowledge Universe · WebGL + GLSL</p>
          <h1>HUGIN</h1>
        </div>
      </header>

      <div className="graph-shell">
        <aside className="graph-rail">
          <fieldset>
            <legend>Camera</legend>
            <button className="button" type="button"
              onClick={() => setCameraMode(cameraMode === "orbit" ? "freefly" : "orbit")}>
              {cameraMode === "orbit" ? "→ Free flight" : "← Orbit"}
            </button>
            {cameraMode === "freefly" && (
              <p style={{ fontSize: 11, opacity: 0.65, marginTop: 8, lineHeight: 1.4 }}>
                Click canvas · WASD thrust · Space/Shift · Q/E roll · Esc exit
              </p>
            )}
          </fieldset>

          <fieldset>
            <legend>View</legend>
            {(["universe", "galaxy", "neighborhood"] as Mode[]).map((val) => (
              <div className="graph-mode" key={val}>
                <input id={`mode-${val}`} type="radio" name="graph-mode" value={val}
                  checked={mode === val} onChange={() => setMode(val)} />
                <label htmlFor={`mode-${val}`}>{val[0].toUpperCase() + val.slice(1)}</label>
              </div>
            ))}
          </fieldset>

          <fieldset>
            <legend>Edges</legend>
            <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>
              <input type="checkbox" checked={showSimilarity}
                onChange={(e) => setShowSimilarity(e.target.checked)} />
              Show all similarity edges
            </label>
            <p style={{ fontSize: 10, opacity: 0.55, marginTop: 6, lineHeight: 1.4 }}>
              75K similarity edges are hidden by default. When you click a node,
              its similarity edges show automatically.
            </p>
          </fieldset>

          {mode === "galaxy" && (
            <fieldset>
              <legend>Warp to</legend>
              {Object.keys(GALAXY_CENTERS).map((g) => (
                <button key={g} className="button" type="button"
                  onClick={() => handleGalaxyWarp(g)}
                  style={{ display: "block", width: "100%", marginBottom: 4, textAlign: "left" }}>
                  <span style={{ color: GALAXY_COLORS[g] }}>●</span> {g}
                </button>
              ))}
            </fieldset>
          )}

          {mode === "neighborhood" && (
            <fieldset>
              <legend>Depth</legend>
              <select value={depth} onChange={(e) => setDepth(Number(e.target.value))}>
                <option value={1}>1 hop</option>
                <option value={2}>2 hops</option>
                <option value={3}>3 hops</option>
              </select>
            </fieldset>
          )}
        </aside>

        <div className="graph-canvas-wrap" style={{ position: "relative" }}>
          <Canvas
            // Wider FOV + closer start so the whole universe is visible from frame 1
            camera={{ position: [540, 360, 620], fov: 60, near: 0.1, far: 6000 }}
            style={{ background: "#000005" }}
            dpr={[1, 1.6]}
            gl={{ antialias: true, powerPreference: "high-performance" }}
          >
            <color attach="background" args={["#000005"]} />
            <fogExp2 attach="fog" args={["#000814", 0.0006]} />

            <ambientLight intensity={0.12} color="#3322ff" />
            <pointLight position={[300, 300, 200]} intensity={1.4} color="#00ffff" distance={1500} />
            <pointLight position={[-300, -200, -300]} intensity={1.2} color="#ff00aa" distance={1200} />

            <Stars radius={500} depth={100} count={5000} factor={4} saturation={0} fade speed={0.6} />
            <AmbientDust count={5000} radius={1500} opacity={0.10} />
            <HolographicGrid y={-400} size={3000} divisions={240} color="#00e5ff" pulseSpeed={0.6} />

            {Object.entries(GALAXY_CENTERS).map(([key, c]) => (
              <GalaxyCloud key={key} center={c} color={GALAXY_COLORS[key] || "#ffffff"} />
            ))}

            {glyphNodes.length > 0 && (
              <GlyphNodes
                nodes={glyphNodes}
                hoveredId={hovered}
                selectedId={selected?.id ?? null}
                visibleSet={visibleSet}
                onHover={setHovered}
                onClick={handleNodeClick}
              />
            )}

            {semanticEdges.length > 0 && (
              <SemanticEdges
                edges={semanticEdges}
                positions={positionsMap}
                selectedId={selected?.id ?? null}
                visibleSet={visibleSet}
                hoveredId={hovered}
              />
            )}

            {shockwave && (
              <ClickShockwave
                active
                origin={shockwave.origin}
                originId={shockwave.id}
                originColor={shockwave.color}
                adjacency={adjacency}
                onFadeComplete={() => setShockwave(null)}
              />
            )}

            {warp && (
              <WarpJump
                from={warp.from} to={warp.to} targetColor={warp.color}
                active duration={2.4}
                onComplete={() => setWarp(null)}
              />
            )}

            {cameraMode === "freefly"
              ? <FreeFlyCamera active onExit={() => setCameraMode("orbit")} />
              : <CameraControls ref={controlsRef} smoothTime={0.35} draggingSmoothTime={0.15}
                                minDistance={20} maxDistance={2800} makeDefault />}

            <CameraVelocityTracker onVelocity={setCamVelocity} />

            <EffectComposer>
              <Bloom
                intensity={0.55}
                luminanceThreshold={0.7}
                luminanceSmoothing={0.85}
                radius={0.5}
                mipmapBlur
              />
              <ChromaticAberration offset={chromatic} radialModulation={false} modulationOffset={0} />
            </EffectComposer>
          </Canvas>

          <KindLegend
            activeKinds={activeKinds} onToggleKind={toggleKind}
            activeEdgeTypes={activeEdgeTypes} onToggleEdgeType={toggleEdgeType}
          />

          {hovered && !selected && (
            <div style={{
              position: "absolute", bottom: 20, left: 20,
              background: "rgba(0,8,20,0.9)", backdropFilter: "blur(6px)",
              border: `1px solid ${GALAXY_COLORS[nodeById.get(hovered)?.galaxyId ?? ""] || "#00f0ff"}`,
              boxShadow: `0 0 16px ${GALAXY_COLORS[nodeById.get(hovered)?.galaxyId ?? ""] || "#00f0ff"}55`,
              padding: "8px 14px", fontFamily: "monospace", fontSize: 12,
              color: "#fff", pointerEvents: "none", maxWidth: 380,
            }}>
              <div style={{
                fontSize: 10, opacity: 0.6, letterSpacing: "0.1em", textTransform: "uppercase",
                color: GALAXY_COLORS[nodeById.get(hovered)?.galaxyId ?? ""] || "#00f0ff",
                marginBottom: 4,
              }}>
                {nodeById.get(hovered)?.galaxyId} · {nodeById.get(hovered)?.kind.replace(/_/g, " ")}
              </div>
              <div style={{ fontWeight: 700 }}>{nodeById.get(hovered)?.label}</div>
            </div>
          )}
        </div>

        <RichInspector
          node={selected}
          related={relatedItems}
          galaxyColors={GALAXY_COLORS}
          totals={{
            entities: manifest.counts.coreEntities,
            edges: manifest.counts.curatedRelations,
            galaxies: manifest.counts.galaxies,
          }}
          onNavigate={handleNodeClick}
          onEnterNeighborhood={() => setMode("neighborhood")}
        />
      </div>
    </div>
  );
}
