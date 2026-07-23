import {
  useEffect,
  useRef,
  useState,
  useMemo,
  useCallback,
  Suspense,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest } from "../lib/types";

// ─── Types ────────────────────────────────────────────────────────────────────

type Mode = "universe" | "galaxy" | "neighborhood" | "path";
type LayerName = "curated" | "membership" | "similarity";

type GraphNode = {
  id: string;
  label: string;
  kind: string;
  galaxyId: string;
  category: string;
  route: string;
  summary: string;
  scope: "core" | "support" | "structure";
  degree: number;
  size: number;
  color: string;
  isGalaxy?: boolean;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
  origin: LayerName;
  score?: number;
  rank?: number;
};

type GraphData = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  positions: Map<string, THREE.Vector3>;
};

// ─── 3D Layout ────────────────────────────────────────────────────────────────

const GALAXY_CENTERS: Record<string, [number, number, number]> = {
  techniques:   [  280,   40,   60],
  internals:    [ -200,  180,  -80],
  defenses:     [ -240, -150,   40],
  chains:       [  100, -220,  120],
  evidence:     [  -80,   80, -260],
  sources:      [   60,  200,  220],
  gaps:         [  200,  -80, -180],
  architecture: [ -120, -200, -140],
};

function compute3DLayout(nodes: GraphNode[], edges: GraphEdge[]): Map<string, THREE.Vector3> {
  // Initialise with galaxy-seeded random positions
  type Particle = { x: number; y: number; z: number; vx: number; vy: number; vz: number };
  const particles = new Map<string, Particle>();

  nodes.forEach((n) => {
    const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
    const spread = n.isGalaxy ? 10 : 160;
    particles.set(n.id, {
      x: c[0] + (Math.random() - 0.5) * spread,
      y: c[1] + (Math.random() - 0.5) * spread,
      z: c[2] + (Math.random() - 0.5) * spread,
      vx: 0, vy: 0, vz: 0,
    });
  });

  // Adjacency list
  const adj = new Map<string, string[]>();
  nodes.forEach((n) => adj.set(n.id, []));
  edges.forEach((e) => {
    adj.get(e.source)?.push(e.target);
    adj.get(e.target)?.push(e.source);
  });

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const SPRING_K = 0.009;
  const REST = 72;
  const GAL_K = 0.004;
  const DAMP = 0.80;
  const ITERS = 90;

  for (let iter = 0; iter < ITERS; iter++) {
    const alpha = Math.pow(1 - iter / ITERS, 1.4);

    particles.forEach((p, id) => {
      let fx = 0, fy = 0, fz = 0;

      // Edge spring attraction
      for (const nid of adj.get(id) ?? []) {
        const q = particles.get(nid);
        if (!q) continue;
        const dx = q.x - p.x, dy = q.y - p.y, dz = q.z - p.z;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.01;
        const f = SPRING_K * (dist - REST) / dist;
        fx += f * dx; fy += f * dy; fz += f * dz;
      }

      // Galaxy gravity — pulls cluster together
      const gid = nodeById.get(id)?.galaxyId ?? "";
      const [cx, cy, cz] = GALAXY_CENTERS[gid] ?? [0, 0, 0];
      fx += (cx - p.x) * GAL_K * alpha;
      fy += (cy - p.y) * GAL_K * alpha;
      fz += (cz - p.z) * GAL_K * alpha;

      p.vx = (p.vx + fx) * DAMP;
      p.vy = (p.vy + fy) * DAMP;
      p.vz = (p.vz + fz) * DAMP;
      p.x += p.vx;
      p.y += p.vy;
      p.z += p.vz;
    });
  }

  const result = new Map<string, THREE.Vector3>();
  particles.forEach((p, id) => result.set(id, new THREE.Vector3(p.x, p.y, p.z)));
  return result;
}

// ─── Three.js shared geometry ─────────────────────────────────────────────────

const SPHERE = new THREE.SphereGeometry(1, 10, 7);

// ─── Star field ───────────────────────────────────────────────────────────────

function StarField() {
  const ref = useRef<THREE.Points>(null);

  const [geo, mat] = useMemo(() => {
    const N = 4000;
    const pos = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
      const r = 600 + Math.random() * 400;
      const th = Math.random() * Math.PI * 2;
      const ph = Math.acos(2 * Math.random() - 1);
      pos[i * 3]     = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
      pos[i * 3 + 2] = r * Math.cos(ph);
      // Slight colour variation: white-blue to white-purple
      const t = Math.random();
      col[i * 3]     = 0.75 + t * 0.25;
      col[i * 3 + 1] = 0.75 + t * 0.15;
      col[i * 3 + 2] = 0.85 + t * 0.15;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const m = new THREE.PointsMaterial({
      size: 0.9,
      sizeAttenuation: true,
      vertexColors: true,
      transparent: true,
      opacity: 0.7,
    });
    return [g, m] as const;
  }, []);

  useFrame(({ clock }) => {
    if (ref.current) ref.current.rotation.y = clock.getElapsedTime() * 0.008;
  });

  return <points ref={ref} geometry={geo} material={mat} />;
}

// ─── Node instanced mesh ──────────────────────────────────────────────────────

function GraphNodes({
  nodes,
  positions,
  visibleSet,
  selectedId,
  hoveredId,
  onHover,
  onClick,
}: {
  nodes: GraphNode[];
  positions: Map<string, THREE.Vector3>;
  visibleSet: Set<string> | null;
  selectedId: string | null;
  hoveredId: string | null;
  onHover: (id: string | null) => void;
  onClick: (id: string) => void;
}) {
  const meshRef = useRef<THREE.InstancedMesh>(null);

  const phases = useMemo(() => nodes.map(() => Math.random() * Math.PI * 2), [nodes]);

  const mat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        roughness: 0.25,
        metalness: 0.55,
        emissive: new THREE.Color(0x000000),
        emissiveIntensity: 0,
      }),
    []
  );

  // Set initial instance transforms once
  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const m = new THREE.Matrix4();
    const color = new THREE.Color();
    nodes.forEach((n, i) => {
      const pos = positions.get(n.id) ?? new THREE.Vector3();
      const s = Math.max(2.2, n.size * 0.95);
      m.makeScale(s, s, s);
      m.setPosition(pos.x, pos.y, pos.z);
      mesh.setMatrixAt(i, m);
      color.set(n.color);
      mesh.setColorAt(i, color);
    });
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  }, [nodes, positions]);

  // Per-frame animation
  useFrame(({ clock }) => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const t = clock.getElapsedTime();
    const m = new THREE.Matrix4();
    const color = new THREE.Color();
    const WHITE = new THREE.Color(0xffffff);
    const SELECTED_COLOR = new THREE.Color(0xff8899);

    nodes.forEach((n, i) => {
      const pos = positions.get(n.id) ?? new THREE.Vector3();
      const isSelected = n.id === selectedId;
      const isHovered = n.id === hoveredId;
      const isVisible = visibleSet === null || visibleSet.has(n.id);

      const floatY = Math.sin(t * 0.38 + phases[i]) * 2.0;
      const floatX = Math.cos(t * 0.22 + phases[i] * 0.7) * 0.8;

      let s = Math.max(2.2, n.size * 0.95);
      if (!isVisible) {
        s = 0.001;
      } else if (isSelected) {
        // Pulse selected node
        s *= 1.9 + Math.sin(t * 3) * 0.15;
      } else if (isHovered) {
        s *= 1.45;
      }

      m.makeScale(s, s, s);
      m.setPosition(pos.x + floatX, pos.y + floatY, pos.z);
      mesh.setMatrixAt(i, m);

      if (isSelected) {
        color.copy(SELECTED_COLOR);
      } else if (isHovered) {
        color.set(n.color);
        color.lerp(WHITE, 0.45);
      } else {
        color.set(n.color);
        if (!isVisible) color.set(0x080808);
      }
      mesh.setColorAt(i, color);
    });

    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  });

  const handleMove = useCallback(
    (e: any) => {
      e.stopPropagation();
      onHover(nodes[e.instanceId as number]?.id ?? null);
    },
    [nodes, onHover]
  );
  const handleOut = useCallback(() => onHover(null), [onHover]);
  const handleClick = useCallback(
    (e: any) => {
      e.stopPropagation();
      const id = nodes[e.instanceId as number]?.id;
      if (id) onClick(id);
    },
    [nodes, onClick]
  );

  return (
    <instancedMesh
      ref={meshRef}
      args={[SPHERE, mat, nodes.length]}
      onPointerMove={handleMove}
      onPointerOut={handleOut}
      onClick={handleClick}
    />
  );
}

// ─── Edge lines ───────────────────────────────────────────────────────────────

function GraphEdges({
  edges,
  positions,
  visibleSet,
  selectedId,
}: {
  edges: GraphEdge[];
  positions: Map<string, THREE.Vector3>;
  visibleSet: Set<string> | null;
  selectedId: string | null;
}) {
  const [geo, mat] = useMemo(() => {
    const active: GraphEdge[] = [];
    const inactive: GraphEdge[] = [];

    for (const e of edges) {
      if (!positions.has(e.source) || !positions.has(e.target)) continue;
      if (visibleSet && (!visibleSet.has(e.source) || !visibleSet.has(e.target))) continue;
      if (selectedId && (e.source === selectedId || e.target === selectedId)) {
        active.push(e);
      } else {
        inactive.push(e);
      }
    }

    const all = [...inactive, ...active];
    const verts = new Float32Array(all.length * 6);
    const colors = new Float32Array(all.length * 6);
    const DIM = new THREE.Color(0x2a2440);
    const LIT = new THREE.Color(0xdf7880);

    all.forEach((e, i) => {
      const sp = positions.get(e.source)!;
      const tp = positions.get(e.target)!;
      verts.set([sp.x, sp.y, sp.z, tp.x, tp.y, tp.z], i * 6);
      const c = i >= inactive.length ? LIT : DIM;
      colors.set([c.r, c.g, c.b, c.r, c.g, c.b], i * 6);
    });

    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(verts, 3));
    g.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    const m = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: visibleSet ? 0.65 : 0.28,
    });
    return [g, m] as const;
  }, [edges, positions, visibleSet, selectedId]);

  return <lineSegments geometry={geo} material={mat} />;
}

// ─── Galaxy label sprites ─────────────────────────────────────────────────────

function GalaxyLabels({
  nodes,
  positions,
}: {
  nodes: GraphNode[];
  positions: Map<string, THREE.Vector3>;
}) {
  const galaxyNodes = useMemo(() => nodes.filter((n) => n.isGalaxy), [nodes]);

  return (
    <>
      {galaxyNodes.map((n) => {
        const pos = positions.get(n.id);
        if (!pos) return null;
        return (
          <sprite key={n.id} position={[pos.x, pos.y + 18, pos.z]}>
            <spriteMaterial
              attach="material"
              color={n.color}
              transparent
              opacity={0.0}
            />
          </sprite>
        );
      })}
    </>
  );
}

// ─── Smooth camera rig ────────────────────────────────────────────────────────

function CameraRig({
  target,
  onReady,
}: {
  target: THREE.Vector3 | null;
  onReady?: () => void;
}) {
  const { camera } = useThree();
  const dest = useRef<THREE.Vector3 | null>(null);
  const ready = useRef(false);

  useEffect(() => {
    dest.current = target;
  }, [target]);

  useEffect(() => {
    if (!ready.current) {
      ready.current = true;
      onReady?.();
    }
  }, [onReady]);

  useFrame(() => {
    if (!dest.current) return;
    const look = new THREE.Vector3(dest.current.x + 55, dest.current.y + 25, dest.current.z + 75);
    camera.position.lerp(look, 0.045);
    camera.lookAt(dest.current);
  });

  return null;
}

// ─── Ambient pulse ring around selected node ──────────────────────────────────

function SelectionRing({
  position,
}: {
  position: THREE.Vector3;
}) {
  const ref = useRef<THREE.Mesh>(null);
  const mat = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: 0xff8899,
        transparent: true,
        opacity: 0.6,
        side: THREE.BackSide,
      }),
    []
  );
  const geo = useMemo(() => new THREE.TorusGeometry(12, 0.5, 8, 48), []);

  useFrame(({ clock }) => {
    const m = ref.current;
    if (!m) return;
    const t = clock.getElapsedTime();
    const s = 1 + Math.sin(t * 2.5) * 0.18;
    m.scale.setScalar(s);
    mat.opacity = 0.35 + Math.sin(t * 2.5) * 0.25;
    m.position.copy(position);
  });

  return <mesh ref={ref} geometry={geo} material={mat} />;
}

// ─── Main component ───────────────────────────────────────────────────────────

function initialParams() {
  return new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
}

export default function GraphThree({ manifest }: { manifest: DatasetManifest }) {
  const params = initialParams();

  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [status, setStatus] = useState("Loading graph…");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>((params.get("mode") as Mode) || "universe");
  const [depth, setDepth] = useState(Number(params.get("depth") || 1));
  const [activeGalaxy, setActiveGalaxy] = useState(params.get("galaxy") || "");
  const [showSources, setShowSources] = useState(params.get("sources") === "1");
  const [layers, setLayers] = useState<Record<LayerName, boolean>>({
    curated: (params.get("edges") || "curated").includes("curated"),
    membership: (params.get("edges") || "").includes("membership"),
    similarity: (params.get("edges") || "").includes("similarity"),
  });
  const [cameraTarget, setCameraTarget] = useState<THREE.Vector3 | null>(null);
  const [relations, setRelations] = useState<Array<{ edge: string; type: string; node: GraphNode }>>([]);

  // Cursor style for hover
  const [cursorGrab, setCursorGrab] = useState(false);

  // ── Fetch & layout ──────────────────────────────────────────────────────────
  useEffect(() => {
    const base = "/Hugin";
    const fetches: Promise<any>[] = [
      fetch(`${base}${manifest.assets.graph}`).then((r) => r.json()),
    ];
    if (layers.similarity) {
      fetches.push(fetch(`${base}${manifest.assets.similarity}`).then((r) => r.json()));
    } else {
      fetches.push(Promise.resolve([]));
    }
    if (layers.membership) {
      fetches.push(fetch(`${base}${manifest.assets.membership}`).then((r) => r.json()));
    } else {
      fetches.push(Promise.resolve([]));
    }

    Promise.all(fetches).then(([payload, simEdges, memEdges]) => {
      setStatus("Computing 3D layout…");
      setTimeout(() => {
        let allEdges: GraphEdge[] = [...payload.edges];
        if (layers.curated) { /* already in payload */ }
        if (layers.similarity) allEdges = [...allEdges, ...simEdges];
        if (layers.membership) allEdges = [...allEdges, ...memEdges];

        const positions = compute3DLayout(payload.nodes, payload.edges);
        setGraphData({ nodes: payload.nodes, edges: allEdges, positions });
        setStatus(`${manifest.counts.coreEntities.toLocaleString()} knowledge nodes ready.`);

        // Check URL focus param
        const focus = initialParams().get("focus");
        if (focus) {
          const n = payload.nodes.find((x: GraphNode) => x.id === focus);
          if (n) {
            setSelected(n);
            const pos = positions.get(n.id);
            if (pos) setCameraTarget(pos.clone());
          }
        }
      }, 30);
    });
  }, [manifest, layers.curated, layers.similarity, layers.membership]);

  // ── Adjacency (for neighborhood mode) ───────────────────────────────────────
  const adj = useMemo(() => {
    if (!graphData) return null;
    const map = new Map<string, string[]>();
    graphData.nodes.forEach((n) => map.set(n.id, []));
    graphData.edges.forEach((e) => {
      map.get(e.source)?.push(e.target);
      map.get(e.target)?.push(e.source);
    });
    return map;
  }, [graphData]);

  // ── Visible set ─────────────────────────────────────────────────────────────
  const visibleSet = useMemo<Set<string> | null>(() => {
    if (!graphData || !adj) return null;

    if (mode === "galaxy" && activeGalaxy) {
      return new Set(graphData.nodes.filter((n) => n.galaxyId === activeGalaxy).map((n) => n.id));
    }

    if (mode === "neighborhood" && selected) {
      const vis = new Set([selected.id]);
      let frontier = new Set([selected.id]);
      for (let h = 0; h < depth; h++) {
        const next = new Set<string>();
        for (const id of frontier) {
          for (const nid of adj.get(id) ?? []) {
            if (!vis.has(nid)) { vis.add(nid); next.add(nid); }
          }
        }
        frontier = next;
      }
      return vis;
    }

    return null;
  }, [mode, activeGalaxy, selected, depth, graphData, adj]);

  // ── Display nodes (filter support if needed) ─────────────────────────────────
  const displayNodes = useMemo(() => {
    if (!graphData) return [];
    return showSources
      ? graphData.nodes
      : graphData.nodes.filter((n) => n.scope !== "support");
  }, [graphData, showSources]);

  // ── Node click handler ───────────────────────────────────────────────────────
  const handleNodeClick = useCallback(
    (id: string) => {
      if (!graphData) return;
      const node = graphData.nodes.find((n) => n.id === id);
      if (!node) return;

      setSelected(node);
      const pos = graphData.positions.get(id);
      if (pos) setCameraTarget(pos.clone());
      setStatus(`${node.label} selected.`);

      const nodeRelations = graphData.edges
        .filter((e) => e.source === id || e.target === id)
        .slice(0, 12)
        .map((e) => {
          const otherId = e.source === id ? e.target : e.source;
          return {
            edge: e.id,
            type: e.type ?? "related_to",
            node: graphData.nodes.find((n) => n.id === otherId)!,
          };
        })
        .filter((r) => r.node);
      setRelations(nodeRelations);
    },
    [graphData]
  );

  const handleHover = useCallback((id: string | null) => {
    setHovered(id);
    setCursorGrab(id !== null);
  }, []);

  const resetView = () => {
    setSelected(null);
    setMode("universe");
    setActiveGalaxy("");
    setCameraTarget(null);
    setRelations([]);
    setStatus("Universe view restored.");
  };

  const toggleLayer = (layer: LayerName) =>
    setLayers((prev) => ({ ...prev, [layer]: !prev[layer] }));

  // ── Selected node 3D position ────────────────────────────────────────────────
  const selectedPos = useMemo(() => {
    if (!selected || !graphData) return null;
    return graphData.positions.get(selected.id) ?? null;
  }, [selected, graphData]);

  return (
    <div className="graph-page">
      <header className="graph-topbar">
        <div className="graph-title">
          <p className="eyebrow">3D Knowledge Map · WebGL</p>
          <h1>HUGIN Universe</h1>
        </div>
        <p className="search-status" aria-live="polite">{status}</p>
      </header>

      <div className="graph-shell">
        {/* ── Left rail ── */}
        <aside className="graph-rail" aria-label="Graph view controls">
          <fieldset>
            <legend>View</legend>
            {(["universe", "galaxy", "neighborhood"] as Mode[]).map((val) => (
              <div className="graph-mode" key={val}>
                <input
                  id={`mode-${val}`}
                  type="radio"
                  name="graph-mode"
                  value={val}
                  checked={mode === val}
                  onChange={() => setMode(val)}
                />
                <label htmlFor={`mode-${val}`}>
                  <span>{val[0].toUpperCase() + val.slice(1)}</span>
                  <span aria-hidden="true">→</span>
                </label>
              </div>
            ))}
          </fieldset>

          {mode === "galaxy" && (
            <fieldset>
              <legend>Galaxy</legend>
              <select
                value={activeGalaxy}
                onChange={(e) => setActiveGalaxy(e.target.value)}
                aria-label="Select galaxy"
              >
                <option value="">— All —</option>
                {Object.keys(GALAXY_CENTERS).map((g) => (
                  <option key={g} value={g}>{g}</option>
                ))}
              </select>
            </fieldset>
          )}

          {mode === "neighborhood" && (
            <fieldset>
              <legend>Depth</legend>
              <select
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                aria-label="Neighborhood depth"
              >
                <option value={1}>One hop</option>
                <option value={2}>Two hops</option>
                <option value={3}>Three hops</option>
              </select>
            </fieldset>
          )}

          <fieldset>
            <legend>Edge layers</legend>
            {(["curated", "membership", "similarity"] as LayerName[]).map((l) => (
              <label className="layer-toggle" key={l}>
                <input type="checkbox" checked={layers[l]} onChange={() => toggleLayer(l)} />
                <span className={`layer-key ${l !== "curated" ? l : ""}`} />
                {l[0].toUpperCase() + l.slice(1)}
              </label>
            ))}
            <label className="layer-toggle">
              <input type="checkbox" checked={showSources} onChange={() => setShowSources((v) => !v)} />
              <span className="layer-key sources" />
              Source layer
            </label>
          </fieldset>

          <button className="button" type="button" onClick={resetView} style={{ width: "100%", marginTop: 8 }}>
            Reset view
          </button>
          <a className="button" href="/Hugin/explore/" style={{ display: "block", marginTop: 8, textAlign: "center" }}>
            Catalog
          </a>
        </aside>

        {/* ── 3D Canvas ── */}
        <div
          className="graph-stage"
          style={{ cursor: cursorGrab ? "pointer" : "grab" }}
        >
          <Canvas
            camera={{ position: [0, 0, 620], fov: 58, near: 1, far: 4000 }}
            gl={{ antialias: true, alpha: false, powerPreference: "high-performance" }}
            style={{ background: "#04030d" }}
            dpr={[1, 1.5]}
          >
            <color attach="background" args={["#04030d"]} />

            {/* Lighting */}
            <ambientLight intensity={0.4} color="#8877cc" />
            <pointLight position={[300, 300, 200]} intensity={2.5} color="#9988ff" distance={1200} />
            <pointLight position={[-300, -200, -300]} intensity={1.5} color="#ff6644" distance={1000} />
            <pointLight position={[0, -400, 200]} intensity={1.0} color="#44aaff" distance={800} />

            <StarField />

            {graphData && (
              <>
                <GraphNodes
                  nodes={displayNodes}
                  positions={graphData.positions}
                  visibleSet={visibleSet}
                  selectedId={selected?.id ?? null}
                  hoveredId={hovered}
                  onHover={handleHover}
                  onClick={handleNodeClick}
                />
                <GraphEdges
                  edges={graphData.edges}
                  positions={graphData.positions}
                  visibleSet={visibleSet}
                  selectedId={selected?.id ?? null}
                />
                {selectedPos && <SelectionRing position={selectedPos} />}
              </>
            )}

            <CameraRig target={cameraTarget} />
            <OrbitControls
              enableDamping
              dampingFactor={0.07}
              rotateSpeed={0.55}
              zoomSpeed={0.8}
              panSpeed={0.6}
              makeDefault
            />

            <EffectComposer>
              <Bloom
                luminanceThreshold={0.12}
                luminanceSmoothing={0.9}
                intensity={1.4}
                radius={0.85}
              />
            </EffectComposer>
          </Canvas>

          <p className="graph-hint">
            Drag to rotate · scroll to zoom · click a node to inspect · right-drag to pan
          </p>
        </div>

        {/* ── Inspector ── */}
        <aside className="inspector" aria-live="polite">
          {selected ? (
            <>
              <p className="eyebrow">{selected.kind} · {selected.galaxyId}</p>
              <h2>{selected.label}</h2>
              <p className="inspector-summary">{selected.summary}</p>
              <dl>
                <dt>ID</dt><dd>{selected.id}</dd>
                <dt>Category</dt><dd>{selected.category}</dd>
                <dt>Relations</dt><dd>{selected.degree.toLocaleString()}</dd>
                <dt>Layer</dt><dd>{selected.scope}</dd>
              </dl>
              <div className="actions">
                <a className="button primary" href={`/Hugin${selected.route}`}>
                  Open {selected.isGalaxy ? "catalog" : "record"}
                </a>
                {!selected.isGalaxy && (
                  <button
                    className="button"
                    type="button"
                    onClick={() => setMode("neighborhood")}
                  >
                    Neighborhood
                  </button>
                )}
              </div>
              {relations.length > 0 && (
                <>
                  <p className="meta-label" style={{ marginTop: 26 }}>Visible relations</p>
                  <ul className="inspector-relations">
                    {relations.map(({ edge, type, node }) => (
                      <li key={edge}>
                        <button
                          type="button"
                          className="inspector-relation-btn"
                          onClick={() => handleNodeClick(node.id)}
                        >
                          <strong>{node.label}</strong>
                          <span>{type.replace(/_/g, " ")}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          ) : (
            <>
              <p className="eyebrow">Universe inspector</p>
              <h2>{manifest.counts.coreEntities.toLocaleString()} knowledge nodes</h2>
              <p className="inspector-summary">
                Rotate to explore the 3D knowledge universe. Click any node to inspect its
                connections, open its full record, or enter neighborhood mode to trace relationships.
              </p>
              <dl>
                <dt>Curated edges</dt><dd>{manifest.counts.curatedRelations.toLocaleString()}</dd>
                <dt>Galaxies</dt><dd>{manifest.counts.galaxies}</dd>
                <dt>Support nodes</dt><dd>{manifest.counts.supportEntities.toLocaleString()}</dd>
                <dt>Evidence records</dt><dd>{manifest.counts.evidenceRecords.toLocaleString()}</dd>
              </dl>
              <a href="/Hugin/explore/" className="button" style={{ display: "block", textAlign: "center", marginTop: 16 }}>
                Open accessible catalog →
              </a>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
