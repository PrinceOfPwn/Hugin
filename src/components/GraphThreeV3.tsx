import {
  useCallback, useMemo, useRef, useState,
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
type GraphEdgeIn = { id: string; source: string; target: string; type: string };
type GraphDataIn = { nodes: GraphNodeIn[]; edges: GraphEdgeIn[]; positions: Map<string, THREE.Vector3> | Record<string, { x: number; y: number; z: number }> | Record<string, never>; };

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

interface Props {
  graphData: GraphDataIn;
  manifest: DatasetManifest;
}

function GalaxyCloud({ center, color }: { center: [number, number, number]; color: string }) {
  const ref = useRef<THREE.Points>(null);
  const [geo, mat] = useMemo(() => {
    const N = 2000;
    const pos = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    const c = new THREE.Color(color);
    for (let i = 0; i < N; i++) {
      const r = Math.pow(Math.random(), 0.5) * 140;
      const branch = Math.random() * Math.PI * 2;
      const spin = r * 0.04;
      pos[i*3]   = Math.cos(branch+spin)*r + (Math.random()-0.5)*20*(1-r/140);
      pos[i*3+1] = (Math.random()-0.5)*12*(1-r/140);
      pos[i*3+2] = Math.sin(branch+spin)*r + (Math.random()-0.5)*20*(1-r/140);
      const f = 1 - r/140;
      col[i*3]=c.r*f; col[i*3+1]=c.g*f; col[i*3+2]=c.b*f;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const m = new THREE.PointsMaterial({
      size: 2.5, sizeAttenuation: true, vertexColors: true, transparent: true,
      opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false,
    });
    return [g, m];
  }, [color]);
  useFrame(({ clock }) => { if (ref.current) ref.current.rotation.y = clock.getElapsedTime() * 0.05; });
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

  const [activeKinds, setActiveKinds] = useState<Set<string>>(new Set(VALID_NODE_KINDS));
  const [activeEdgeTypes, setActiveEdgeTypes] = useState<Set<string>>(new Set(VALID_EDGE_TYPES));

  const [shockwave, setShockwave] = useState<{ origin: THREE.Vector3; id: string; color: string } | null>(null);
  const [warp, setWarp] = useState<{ from: THREE.Vector3; to: THREE.Vector3; color: string } | null>(null);
  const [camVelocity, setCamVelocity] = useState(0);
  const controlsRef = useRef<CameraControls>(null);

  // Normalise positions: accept Map, plain {id:{x,y,z}} record, or empty object.
  // When positions is empty (Astro page passes {}) we compute 3D layout from
  // galaxy centers + deterministic per-node offsets matching build-data.mjs.
  const positionsMap = useMemo<Map<string, THREE.Vector3>>(() => {
    const raw = graphData.positions;
    if (raw instanceof Map) return raw as Map<string, THREE.Vector3>;

    // If it's a non-empty plain record, convert it
    const keys = Object.keys(raw);
    if (keys.length > 0) {
      const m = new Map<string, THREE.Vector3>();
      for (const k of keys) {
        const v = (raw as Record<string, { x: number; y: number; z: number }>)[k];
        m.set(k, new THREE.Vector3(v.x, v.y, v.z));
      }
      return m;
    }

    // Empty — compute layout from GALAXY_CENTERS + hash-based offsets
    const m = new Map<string, THREE.Vector3>();
    const galaxyIds = Object.keys(GALAXY_CENTERS);
    const nodesByGalaxy = new Map<string, string[]>();
    for (const n of graphData.nodes) {
      if (!nodesByGalaxy.has(n.galaxyId)) nodesByGalaxy.set(n.galaxyId, []);
      nodesByGalaxy.get(n.galaxyId)!.push(n.id);
    }
    for (const gId of galaxyIds) {
      const center = GALAXY_CENTERS[gId] ?? [0, 0, 0];
      const members = nodesByGalaxy.get(gId) ?? [];
      members.forEach((id, i) => {
        const angle = (i / Math.max(members.length, 1)) * Math.PI * 2;
        const radius = 40 + (id.charCodeAt(0) % 80);
        m.set(id, new THREE.Vector3(
          center[0] + Math.cos(angle) * radius,
          center[1] + (id.charCodeAt(1) % 30) - 15,
          center[2] + Math.sin(angle) * radius,
        ));
      });
    }
    return m;
  }, [graphData]);

  // Adjacency & typed adjacency
  const adjacency = useMemo(() => {
    const a = new Map<string, string[]>();
    graphData.nodes.forEach((n) => a.set(n.id, []));
    graphData.edges.forEach((e) => {
      a.get(e.source)?.push(e.target);
      a.get(e.target)?.push(e.source);
    });
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

  // Build glyph nodes with kind + tier
  const glyphNodes: GlyphNodeData[] = useMemo(() => {
    return graphData.nodes
      .filter((n) => !n.isGalaxy && activeKinds.has(n.kind))
      .map((n) => ({
        id: n.id,
        position: positionsMap.get(n.id) ?? new THREE.Vector3(),
        color: GALAXY_COLORS[n.galaxyId] || n.color,
        size: Math.max(3.4, n.size * 1.4),
        kind: (VALID_NODE_KINDS.includes(n.kind as NodeKind) ? n.kind : "reference") as NodeKind,
        tier: n.tier,
      }));
  }, [graphData, activeKinds]);

  // Build semantic edges filtered by type
  const semanticEdges: SemanticEdge[] = useMemo(() => {
    return graphData.edges
      .filter((e) => activeEdgeTypes.has(e.type))
      .map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        type: (VALID_EDGE_TYPES.includes(e.type as EdgeType) ? e.type : "related") as EdgeType,
      }));
  }, [graphData.edges, activeEdgeTypes]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNodeIn>();
    graphData.nodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [graphData]);

  // Related items for the inspector (grouped by direction+type)
  const relatedItems = useMemo(() => {
    if (!selected) return [];
    return graphData.edges
      .filter((e) => e.source === selected.id || e.target === selected.id)
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
  }, [nodeById, graphData.positions, cameraMode]);

  const handleGalaxyWarp = useCallback((galaxyId: string) => {
    const to = new THREE.Vector3(...GALAXY_CENTERS[galaxyId]);
    const cam = controlsRef.current?.camera;
    if (!cam) return;
    setWarp({ from: cam.position.clone(), to, color: GALAXY_COLORS[galaxyId] || "#00f0ff" });
  }, []);

  const toggleKind = useCallback((id: string) => {
    setActiveKinds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);
  const toggleEdgeType = useCallback((id: string) => {
    setActiveEdgeTypes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const chromatic: [number, number] = useMemo(() => {
    const base = 0.0004;
    const boost = Math.min(camVelocity * 0.0006, 0.006);
    return [base + boost, base + boost];
  }, [camVelocity]);

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
            camera={{ position: [420, 240, 480], fov: 62, near: 0.1, far: 5000 }}
            style={{ background: "#000005" }}
            dpr={[1, 1.6]}
            gl={{ antialias: true, powerPreference: "high-performance" }}
          >
            <color attach="background" args={["#000005"]} />
            <fogExp2 attach="fog" args={["#000814", 0.0008]} />

            <ambientLight intensity={0.08} color="#3322ff" />
            <pointLight position={[300, 300, 200]} intensity={1.8} color="#00ffff" distance={1500} />
            <pointLight position={[-300, -200, -300]} intensity={1.5} color="#ff00aa" distance={1200} />

            <Stars radius={500} depth={100} count={8000} factor={4} saturation={0} fade speed={0.6} />
            <AmbientDust count={12000} radius={1500} opacity={0.18} />
            <HolographicGrid y={-400} size={3000} divisions={300} color="#00e5ff" pulseSpeed={0.6} />

            {Object.entries(GALAXY_CENTERS).map(([key, c]) => (
              <GalaxyCloud key={key} center={c} color={GALAXY_COLORS[key] || "#ffffff"} />
            ))}

            <GlyphNodes
              nodes={glyphNodes}
              hoveredId={hovered}
              selectedId={selected?.id ?? null}
              visibleSet={visibleSet}
              onHover={setHovered}
              onClick={handleNodeClick}
            />

            <SemanticEdges
              edges={semanticEdges}
              positions={positionsMap}
              selectedId={selected?.id ?? null}
              visibleSet={visibleSet}
              hoveredId={hovered}
            />

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
                                minDistance={20} maxDistance={2400} makeDefault />}

            <CameraVelocityTracker onVelocity={setCamVelocity} />

            <EffectComposer>
              <Bloom intensity={2.8} luminanceThreshold={0.15} luminanceSmoothing={0.9} radius={0.85} mipmapBlur />
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
              background: "rgba(0,8,20,0.85)", backdropFilter: "blur(6px)",
              border: "1px solid rgba(0,240,255,0.3)", padding: "8px 12px",
              fontFamily: "monospace", fontSize: 11, color: "#00f0ff",
              textTransform: "uppercase", letterSpacing: "0.1em", pointerEvents: "none",
            }}>
              {nodeById.get(hovered)?.label}
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
