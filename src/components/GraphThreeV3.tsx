import {
  useCallback, useEffect, useMemo, useRef, useState,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Stars, OrbitControls } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest } from "../lib/types";

import NodeCloud from "./NodeCloud";
import type { NodeDatum } from "./NodeCloud";
import EdgeSet, { EDGE_COLOR } from "./EdgeSet";

type Mode = "universe" | "galaxy" | "neighborhood";

type GraphNodeIn = {
  id: string; label: string; kind: string; galaxyId: string; category: string;
  route: string; summary: string;
  scope: "core" | "support" | "structure" | "evidence";
  degree: number; size: number; color: string; isGalaxy?: boolean;
  tier?: "S" | "A" | "B" | "C";
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

// ═════════════════════════════════════════════════════════════════════════════
//  Layout constants
// ═════════════════════════════════════════════════════════════════════════════

const GALAXY_CENTERS: Record<string, [number, number, number]> = {
  techniques:    [ 340,   40,   60],
  internals:     [-260,  200,  -80],
  defenses:      [-300, -180,   40],
  chains:        [ 120, -260,  140],
  evidence:      [-100,  100, -300],
  sources:       [  80,  240,  260],
  gaps:          [ 240, -100, -220],
  architecture:  [-140, -240, -160],
  tradecraft_qa: [   0,  360,  180],
};
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

const NOISE_EDGE = new Set(["similar_to"]);

// ═════════════════════════════════════════════════════════════════════════════
//  Deterministic 3D layout — hash-based Fibonacci sphere per galaxy.
//  Guaranteed to spread nodes evenly, never collapses, O(N).
// ═════════════════════════════════════════════════════════════════════════════

function shortHash(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) / 0xffffffff;
}
function derivedPositions(nodes: GraphNodeIn[]): Map<string, THREE.Vector3> {
  const perGalaxy = new Map<string, number>();
  for (const n of nodes) if (!n.isGalaxy) perGalaxy.set(n.galaxyId, (perGalaxy.get(n.galaxyId) || 0) + 1);

  const radius = new Map<string, number>();
  for (const [g, c] of perGalaxy) radius.set(g, 90 + Math.cbrt(c) * 28);

  const cursor = new Map<string, number>();
  const result = new Map<string, THREE.Vector3>();
  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));

  for (const n of sorted) {
    if (n.isGalaxy) {
      const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
      result.set(n.id, new THREE.Vector3(c[0], c[1], c[2]));
      continue;
    }
    const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
    const R = radius.get(n.galaxyId) ?? 140;
    const idx   = cursor.get(n.galaxyId) ?? 0;
    const total = perGalaxy.get(n.galaxyId) ?? 1;
    cursor.set(n.galaxyId, idx + 1);

    const phi   = Math.acos(1 - 2 * (idx + 0.5) / total);
    const theta = Math.PI * (1 + Math.sqrt(5)) * idx;
    const jitter = 0.6 + shortHash(n.id + ":r") * 0.4;
    const r = R * jitter;
    result.set(n.id, new THREE.Vector3(
      c[0] + r * Math.sin(phi) * Math.cos(theta),
      c[1] + r * Math.sin(phi) * Math.sin(theta),
      c[2] + r * Math.cos(phi),
    ));
  }
  return result;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Galaxy orbs — 9 big glowing points marking each galaxy center. Always
//  visible, always clickable to warp/zoom.
// ═════════════════════════════════════════════════════════════════════════════

function GalaxyOrbs({ onSelect }: { onSelect: (galaxyId: string) => void }) {
  const [geo, mat] = useMemo(() => {
    const entries = Object.entries(GALAXY_CENTERS);
    const positions = new Float32Array(entries.length * 3);
    const colors = new Float32Array(entries.length * 3);
    const c = new THREE.Color();
    for (let i = 0; i < entries.length; i++) {
      const [gid, pos] = entries[i];
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
      size: 90, sizeAttenuation: true, vertexColors: true,
      transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    return [g, m];
  }, []);

  const ids = useMemo(() => Object.keys(GALAXY_CENTERS), []);

  return (
    <points
      geometry={geo}
      material={mat}
      onClick={(e) => { e.stopPropagation(); const i = (e as any).index; if (i != null) onSelect(ids[i]); }}
    />
  );
}

// ═════════════════════════════════════════════════════════════════════════════
//  Camera focus animator — smooth lerp to a target on selection
// ═════════════════════════════════════════════════════════════════════════════

function CameraFocuser({ target, distance = 180 }: { target: THREE.Vector3 | null; distance?: number }) {
  const { camera } = useThree();
  const tgt = useRef(new THREE.Vector3());
  const cur = useRef(new THREE.Vector3());
  const active = useRef(false);

  useEffect(() => {
    if (!target) return;
    tgt.current.copy(target);
    cur.current.set(target.x + distance, target.y + distance * 0.6, target.z + distance);
    active.current = true;
  }, [target, distance]);

  useFrame(() => {
    if (!active.current) return;
    camera.position.lerp(cur.current, 0.06);
    camera.lookAt(tgt.current);
    if (camera.position.distanceTo(cur.current) < 2) active.current = false;
  });
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Main
// ═════════════════════════════════════════════════════════════════════════════

interface Props {
  graphData: GraphDataIn;
  manifest: DatasetManifest;
}

export default function GraphThreeV3({ graphData, manifest }: Props) {
  const [mode, setMode] = useState<Mode>("universe");
  const [selected, setSelected] = useState<GraphNodeIn | null>(null);
  const [hovered, setHovered] = useState<{ id: string; screen: { x: number; y: number } } | null>(null);
  const [focusPos, setFocusPos] = useState<THREE.Vector3 | null>(null);
  const [galaxyFilter, setGalaxyFilter] = useState<string | null>(null);

  // ─── Positions ────────────────────────────────────────────────────────────
  const positionsMap = useMemo<Map<string, THREE.Vector3>>(() => {
    const raw = graphData.positions;
    if (raw instanceof Map && raw.size > 0) {
      // sanity: reject if all positions are (0,0,0)
      let nonZero = 0;
      for (const v of raw.values()) if (v.x !== 0 || v.y !== 0 || v.z !== 0) { nonZero++; break; }
      if (nonZero > 0) return raw;
    }
    if (raw && !(raw instanceof Map) && typeof raw === "object") {
      const keys = Object.keys(raw);
      if (keys.length > 0) {
        const m = new Map<string, THREE.Vector3>();
        for (const k of keys) {
          const v = (raw as any)[k];
          m.set(k, new THREE.Vector3(v.x, v.y, v.z));
        }
        return m;
      }
    }
    return derivedPositions(graphData.nodes);
  }, [graphData]);

  // ─── Adjacency (curated only, no similarity noise) ────────────────────────
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

  // ─── Node list — filtered by galaxy in galaxy mode ────────────────────────
  const visibleNodes = useMemo<NodeDatum[]>(() => {
    return graphData.nodes
      .filter((n) => !n.isGalaxy)
      .filter((n) => !galaxyFilter || n.galaxyId === galaxyFilter)
      .map((n) => ({
        id: n.id,
        position: positionsMap.get(n.id) ?? new THREE.Vector3(),
        color: GALAXY_COLORS[n.galaxyId] || n.color || "#888",
        size: Math.max(2.4, (n.tier === "S" ? 5.5 : n.tier === "A" ? 4.2 : n.tier === "B" ? 3.2 : 2.6) + Math.log2(n.degree + 1) * 0.4),
        kind: n.kind,
        galaxyId: n.galaxyId,
      }));
  }, [graphData.nodes, positionsMap, galaxyFilter]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNodeIn>();
    for (const n of graphData.nodes) m.set(n.id, n);
    return m;
  }, [graphData]);

  // ─── Edges — hidden unless a node is focused ──────────────────────────────
  // Design decision: showing ALL 2945 curated edges at once was a visual mess.
  // Instead, show edges progressively: on hover show that node's edges muted;
  // on select show that node's edges highlighted. Zero edges shown otherwise.
  const focusId = selected?.id ?? hovered?.id ?? null;

  const focusEdges = useMemo(() => {
    if (!focusId) return [];
    return graphData.edges.filter(
      (e) => !NOISE_EDGE.has(e.type) && (e.source === focusId || e.target === focusId)
    );
  }, [graphData.edges, focusId]);

  // ─── Dimmed set — when a node is selected, dim everything not connected ──
  const dimmedSet = useMemo<Set<string> | null>(() => {
    if (!selected) return null;
    const connected = new Set([selected.id]);
    for (const nid of adjacency.get(selected.id) ?? []) connected.add(nid);
    return connected;
  }, [selected, adjacency]);

  // ─── Related items for the inspector, grouped by edge type ────────────────
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

  // ─── Handlers ─────────────────────────────────────────────────────────────
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
    const c = GALAXY_CENTERS[gid];
    if (c) setFocusPos(new THREE.Vector3(c[0], c[1], c[2]));
  }, []);

  const handleReset = useCallback(() => {
    setSelected(null);
    setGalaxyFilter(null);
    setMode("universe");
    setFocusPos(null);
  }, []);

  // Diagnostic
  useEffect(() => {
    console.log(`[GraphThreeV3] nodes=${visibleNodes.length}/${graphData.nodes.length}  edges_visible=${focusEdges.length}/${graphData.edges.length}  mode=${mode}  galaxy=${galaxyFilter ?? "all"}`);
  }, [visibleNodes.length, focusEdges.length, mode, galaxyFilter, graphData.nodes.length, graphData.edges.length]);

  const selectedRoute = selected?.route;
  const galaxies = Object.entries(GALAXY_CENTERS);

  return (
    <div style={{ position: "relative", width: "100%", height: "100vh", background: "#000005", color: "#e8f0ff", overflow: "hidden" }}>
      {/* ─── LEFT RAIL: navigation + filters ─────────────────────────────── */}
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
          camera={{ position: [520, 340, 640], fov: 55, near: 0.1, far: 8000 }}
          dpr={[1, 1.6]}
          gl={{ antialias: true, powerPreference: "high-performance", alpha: false }}
        >
          <color attach="background" args={["#000005"]} />
          <fogExp2 attach="fog" args={["#02061a", 0.00045]} />

          <ambientLight intensity={0.15} color="#4455ff" />
          <pointLight position={[400, 400, 300]}  intensity={1.2} color="#00d0ff" distance={2500} />
          <pointLight position={[-400, -300, -300]} intensity={1.0} color="#ff2288" distance={2000} />

          <Stars radius={800} depth={200} count={5000} factor={5} saturation={0} fade speed={0.3} />

          <GalaxyOrbs onSelect={handleGalaxyClick} />

          <NodeCloud
            nodes={visibleNodes}
            hoveredId={hovered?.id ?? null}
            selectedId={selected?.id ?? null}
            dimmedSet={dimmedSet}
            onHover={(id, screen) => setHovered(id ? { id, screen: screen ?? { x: 0, y: 0 } } : null)}
            onClick={handleNodeClick}
          />

          {focusEdges.length > 0 && (
            <EdgeSet
              edges={focusEdges}
              positions={positionsMap}
              opacity={selected ? 0.9 : 0.45}
              focusColor={selected ? undefined : "#00e5ff"}
            />
          )}

          <CameraFocuser target={focusPos} distance={selected ? 160 : 380} />

          <OrbitControls
            enableDamping dampingFactor={0.08}
            rotateSpeed={0.7} zoomSpeed={1.2} panSpeed={1.0}
            minDistance={30} maxDistance={3200}
            makeDefault
          />

          <EffectComposer>
            <Bloom intensity={0.45} luminanceThreshold={0.75} luminanceSmoothing={0.9} radius={0.6} mipmapBlur />
          </EffectComposer>
        </Canvas>

        {/* Reset button, top-right of canvas */}
        <button onClick={handleReset} style={{
          position: "absolute", top: 16, right: 16, zIndex: 4,
          background: "rgba(0,8,20,0.75)", border: "1px solid rgba(0,240,255,0.35)",
          color: "#00f0ff", padding: "6px 14px", fontFamily: "monospace",
          fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em",
          cursor: "pointer", backdropFilter: "blur(6px)",
        }}>Reset view</button>

        {/* Cursor-following hover tooltip */}
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

      {/* ─── RIGHT INSPECTOR: opens on click, closes with X or Esc ───────── */}
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
