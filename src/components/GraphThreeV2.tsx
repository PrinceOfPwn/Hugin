import {
  useCallback, useEffect, useMemo, useRef, useState,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Stars, CameraControls } from "@react-three/drei";
import { EffectComposer, Bloom, ChromaticAberration } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest, EvidenceRecord } from "../lib/types";
import { parseAndCleanSummary } from "../lib/summaryParser";

import StarNodes from "./StarNodes";
import EdgeDataStream from "./EdgeDataStream";
import FreeFlyCamera from "./FreeFlyCamera";
import ClickShockwave, { useEdgeFlashState } from "./ClickShockwave";
import HolographicGrid from "./HolographicGrid";
import AmbientDust from "./AmbientDust";
import WarpJump from "./WarpJump";

type Mode = "universe" | "galaxy" | "neighborhood" | "path";
type CameraMode = "orbit" | "freefly";
type LayerName = "curated" | "membership" | "similarity";

type GraphNode = {
  id: string; label: string; kind: string; galaxyId: string; category: string;
  route: string; summary: string; scope: "core" | "support" | "structure" | "evidence";
  degree: number; size: number; color: string; isGalaxy?: boolean; rawEvidence?: EvidenceRecord;
};
type GraphEdge = { id: string; source: string; target: string; type: string; origin: LayerName | "evidence"; };
type GraphData = { nodes: GraphNode[]; edges: GraphEdge[]; positions: Map<string, THREE.Vector3>; };

const GALAXY_CENTERS: Record<string, [number, number, number]> = {
  techniques:    [ 280,   40,   60], internals:     [-200,  180,  -80],
  defenses:      [-240, -150,   40], chains:        [ 100, -220,  120],
  evidence:      [ -80,   80, -260], sources:       [  60,  200,  220],
  gaps:          [ 200,  -80, -180], architecture:  [-120, -200, -140],
  tradecraft_qa: [   0,  300,  150],
};
const GALAXY_COLORS: Record<string, string> = {
  techniques: "#ff2244", internals: "#00f0ff", defenses: "#39ff14",
  chains: "#ffb700", evidence: "#00e5ff", sources: "#e040fb",
  gaps: "#ff5555", architecture: "#9d4edd", tradecraft_qa: "#00e5bf",
};

const EDGE_TYPE_MAP: Record<string, "curated" | "membership" | "similarity" | "evidence"> = {
  curated: "curated", membership: "membership", similarity: "similarity", evidence: "evidence",
};

interface Props {
  graphData: GraphData;
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
      pos[i * 3]     = Math.cos(branch + spin) * r + (Math.random() - 0.5) * 20 * (1 - r / 140);
      pos[i * 3 + 1] = (Math.random() - 0.5) * 12 * (1 - r / 140);
      pos[i * 3 + 2] = Math.sin(branch + spin) * r + (Math.random() - 0.5) * 20 * (1 - r / 140);
      const f = 1 - r / 140;
      col[i * 3] = c.r * f; col[i * 3 + 1] = c.g * f; col[i * 3 + 2] = c.b * f;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const m = new THREE.PointsMaterial({
      size: 2.5, sizeAttenuation: true, vertexColors: true,
      transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false,
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

export default function GraphThreeV2({ graphData, manifest }: Props) {
  const [mode, setMode] = useState<Mode>("universe");
  const [cameraMode, setCameraMode] = useState<CameraMode>("orbit");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [layers, setLayers] = useState<Record<LayerName, boolean>>({ curated: true, membership: true, similarity: true });
  const [depth, setDepth] = useState(1);
  const [shockwave, setShockwave] = useState<{ origin: THREE.Vector3; id: string; color: string } | null>(null);
  const [warp, setWarp] = useState<{ from: THREE.Vector3; to: THREE.Vector3; color: string } | null>(null);
  const [camVelocity, setCamVelocity] = useState(0);
  const controlsRef = useRef<CameraControls>(null);

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

  const starNodes = useMemo(() => {
    return graphData.nodes.filter((n) => !n.isGalaxy).map((n) => ({
      id: n.id,
      position: graphData.positions.get(n.id) ?? new THREE.Vector3(),
      color: GALAXY_COLORS[n.galaxyId] || n.color,
      size: Math.max(3.6, n.size * 1.5),
    }));
  }, [graphData]);

  const streamEdges = useMemo(() => {
    return graphData.edges
      .filter((e) => layers[e.origin as LayerName] !== false)
      .map((e) => ({
        id: e.id, source: e.source, target: e.target,
        type: EDGE_TYPE_MAP[e.origin] ?? "curated",
      }));
  }, [graphData.edges, layers]);

  const handleNodeClick = useCallback((id: string) => {
    const node = graphData.nodes.find((n) => n.id === id);
    if (!node) return;
    setSelected(node);
    const pos = graphData.positions.get(id);
    if (pos) {
      setShockwave({ origin: pos.clone(), id, color: GALAXY_COLORS[node.galaxyId] || "#00f0ff" });
      if (cameraMode === "orbit" && controlsRef.current) {
        controlsRef.current.setLookAt(
          pos.x + 90, pos.y + 40, pos.z + 90,
          pos.x, pos.y, pos.z, true,
        );
      }
    }
  }, [graphData, cameraMode]);

  const handleGalaxyWarp = useCallback((galaxyId: string) => {
    const to = new THREE.Vector3(...GALAXY_CENTERS[galaxyId]);
    const cam = controlsRef.current?.camera;
    if (!cam) return;
    setWarp({ from: cam.position.clone(), to, color: GALAXY_COLORS[galaxyId] || "#00f0ff" });
  }, []);

  const chromatic: [number, number] = useMemo(() => {
    const base = 0.0004;
    const boost = Math.min(camVelocity * 0.0006, 0.006);
    return [base + boost, base + boost];
  }, [camVelocity]);

  const selectedPos = selected ? graphData.positions.get(selected.id) ?? null : null;
  const structuredInfo = useMemo(() => selected ? parseAndCleanSummary(selected.summary, selected.label) : null, [selected]);

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
            <button className="button" type="button" onClick={() => setCameraMode(cameraMode === "orbit" ? "freefly" : "orbit")}>
              {cameraMode === "orbit" ? "→ Free Flight" : "← Orbit"}
            </button>
            {cameraMode === "freefly" && (
              <p style={{ fontSize: 11, opacity: 0.65, marginTop: 8 }}>
                Click canvas to lock cursor · WASD to thrust · Space/Shift · Q/E roll · Esc to exit
              </p>
            )}
          </fieldset>

          <fieldset>
            <legend>View</legend>
            {(["universe", "galaxy", "neighborhood", "path"] as Mode[]).map((val) => (
              <div className="graph-mode" key={val}>
                <input id={`mode-${val}`} type="radio" name="graph-mode" value={val}
                  checked={mode === val} onChange={() => setMode(val)} />
                <label htmlFor={`mode-${val}`}>{val[0].toUpperCase() + val.slice(1)}</label>
              </div>
            ))}
          </fieldset>

          {mode === "galaxy" && (
            <fieldset>
              <legend>Warp to galaxy</legend>
              {Object.keys(GALAXY_CENTERS).map((g) => (
                <button key={g} className="button" type="button" onClick={() => handleGalaxyWarp(g)}
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
                <option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option>
              </select>
            </fieldset>
          )}

          <fieldset>
            <legend>Edge layers</legend>
            {(["curated", "membership", "similarity"] as LayerName[]).map((l) => (
              <label className="layer-toggle" key={l}>
                <input type="checkbox" checked={layers[l]}
                  onChange={() => setLayers({ ...layers, [l]: !layers[l] })} />
                <span>{l}</span>
              </label>
            ))}
          </fieldset>
        </aside>

        <div className="graph-canvas-wrap">
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
            <AmbientDust count={15000} radius={1500} opacity={0.18} />
            <HolographicGrid y={-400} size={3000} divisions={300} color="#00e5ff" pulseSpeed={0.6} />

            {Object.entries(GALAXY_CENTERS).map(([key, c]) => (
              <GalaxyCloud key={key} center={c} color={GALAXY_COLORS[key] || "#ffffff"} />
            ))}

            <StarNodes
              nodes={starNodes}
              hoveredId={hovered}
              selectedId={selected?.id ?? null}
              visibleSet={visibleSet}
              onHover={setHovered}
              onClick={handleNodeClick}
            />

            <EdgeDataStream
              edges={streamEdges}
              positions={graphData.positions}
              selectedId={selected?.id ?? null}
              visibleSet={visibleSet}
            />

            {shockwave && (
              <ClickShockwave
                active={!!shockwave}
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
                active={!!warp} duration={2.4}
                onComplete={() => setWarp(null)}
              />
            )}

            {cameraMode === "freefly"
              ? <FreeFlyCamera active={true} onExit={() => setCameraMode("orbit")} />
              : <CameraControls ref={controlsRef} smoothTime={0.35} draggingSmoothTime={0.15}
                  minDistance={20} maxDistance={2400} makeDefault />}

            <CameraVelocityTracker onVelocity={setCamVelocity} />

            <EffectComposer>
              <Bloom intensity={2.8} luminanceThreshold={0.15} luminanceSmoothing={0.9} radius={0.85} mipmapBlur />
              <ChromaticAberration offset={chromatic} radialModulation={false} modulationOffset={0} />
            </EffectComposer>
          </Canvas>
        </div>

        <aside className="inspector">
          {selected ? (
            <>
              <span className="eyebrow-bright" style={{ color: GALAXY_COLORS[selected.galaxyId] }}>
                {selected.galaxyId} :: {selected.kind}
              </span>
              <h2>{selected.label}</h2>
              <p>{structuredInfo?.cleanSummary ?? selected.summary}</p>
              <dl>
                <dt>ID</dt><dd>{selected.id}</dd>
                <dt>Category</dt><dd>{selected.category}</dd>
                <dt>Relations</dt><dd>{selected.degree}</dd>
              </dl>
            </>
          ) : (
            <>
              <span className="eyebrow-bright">Universe Inspector</span>
              <h2>{manifest.counts.coreEntities.toLocaleString()} knowledge stars</h2>
              <p>Click any star to inspect. Switch to Galaxy view to warp between clusters.</p>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
