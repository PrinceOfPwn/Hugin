import {
  useEffect,
  useRef,
  useState,
  useMemo,
  useCallback,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Html } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";
import type { DatasetManifest, EvidenceRecord } from "../lib/types";
import { parseAndCleanSummary } from "../lib/summaryParser";

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
  scope: "core" | "support" | "structure" | "evidence";
  degree: number;
  size: number;
  color: string;
  isGalaxy?: boolean;
  rawEvidence?: EvidenceRecord;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
  origin: LayerName | "evidence";
  score?: number;
  rank?: number;
};

type GraphData = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  positions: Map<string, THREE.Vector3>;
};

// ─── 3D Layout & Constants ────────────────────────────────────────────────────

const GALAXY_CENTERS: Record<string, [number, number, number]> = {
  techniques:   [  280,   40,   60],
  internals:    [ -200,  180,  -80],
  defenses:     [ -240, -150,   40],
  chains:       [  100, -220,  120],
  evidence:     [  -80,   80, -260],
  sources:      [   60,  200,  220],
  gaps:         [  200,  -80, -180],
  architecture: [ -120, -200, -140],
  tradecraft_qa: [ 0,   300,  150],
};

const GALAXY_COLORS: Record<string, string> = {
  techniques: "#ff0055", // Bright Neon Crimson / Pink
  internals: "#00f0ff",  // Electric Cyan
  defenses: "#00ff66",   // Neon Lime Green
  chains: "#ffb703",     // Electric Gold / Amber
  evidence: "#00e5ff",   // Bright Turquoise
  sources: "#e056fd",    // Neon Magenta
  gaps: "#ff3366",       // Hot Coral
  architecture: "#9d4edd", // Deep Neon Violet
  tradecraft_qa: "#00e5bf", // Bright Neon Teal
};

function compute3DLayout(nodes: GraphNode[], edges: GraphEdge[]): Map<string, THREE.Vector3> {
  type Particle = { x: number; y: number; z: number; vx: number; vy: number; vz: number };
  const particles = new Map<string, Particle>();

  nodes.forEach((n) => {
    const c = GALAXY_CENTERS[n.galaxyId] ?? [0, 0, 0];
    const spread = n.isGalaxy ? 10 : n.scope === "evidence" ? 80 : 160;
    particles.set(n.id, {
      x: c[0] + (Math.random() - 0.5) * spread,
      y: c[1] + (Math.random() - 0.5) * spread,
      z: c[2] + (Math.random() - 0.5) * spread,
      vx: 0, vy: 0, vz: 0,
    });
  });

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
  const ITERS = 80;

  for (let iter = 0; iter < ITERS; iter++) {
    const alpha = Math.pow(1 - iter / ITERS, 1.4);

    particles.forEach((p, id) => {
      let fx = 0, fy = 0, fz = 0;

      for (const nid of adj.get(id) ?? []) {
        const q = particles.get(nid);
        if (!q) continue;
        const dx = q.x - p.x, dy = q.y - p.y, dz = q.z - p.z;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.01;
        const f = SPRING_K * (dist - REST) / dist;
        fx += f * dx; fy += f * dy; fz += f * dz;
      }

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

const SPHERE = new THREE.SphereGeometry(1, 12, 8);

// ─── Galaxy Clouds (Animación de Fondo) ───────────────────────────────────────

function GalaxyCloud({ center, color }: { center: [number, number, number], color: string }) {
  const ref = useRef<THREE.Points>(null);

  const [geo, mat] = useMemo(() => {
    const N = 1500;
    const pos = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    const c = new THREE.Color(color);

    for (let i = 0; i < N; i++) {
      // Distribución espiral para efecto galaxia
      const r = Math.pow(Math.random(), 0.5) * 140;
      const branchAngle = Math.random() * Math.PI * 2;
      const spinAngle = r * 0.04; // Fuerza de los brazos espirales
      
      const randomX = (Math.random() - 0.5) * 20 * (1 - r / 140);
      const randomY = (Math.random() - 0.5) * 12 * (1 - r / 140); // Aplanado en Y
      const randomZ = (Math.random() - 0.5) * 20 * (1 - r / 140);

      pos[i * 3]     = Math.cos(branchAngle + spinAngle) * r + randomX;
      pos[i * 3 + 1] = randomY;
      pos[i * 3 + 2] = Math.sin(branchAngle + spinAngle) * r + randomZ;

      // Degradar el color hacia el borde
      const fade = 1 - r / 140;
      col[i * 3]     = c.r * fade;
      col[i * 3 + 1] = c.g * fade;
      col[i * 3 + 2] = c.b * fade;
    }

    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    
    const m = new THREE.PointsMaterial({
      size: 2.5,
      sizeAttenuation: true,
      vertexColors: true,
      transparent: true,
      opacity: 0.4,
      blending: THREE.AdditiveBlending, // Brillo aditivo
      depthWrite: false,
    });
    return [g, m] as const;
  }, [color]);

  useFrame(({ clock }) => {
    if (ref.current) {
      const t = clock.getElapsedTime();
      // Rotación lenta de la galaxia sobre su eje
      ref.current.rotation.y = t * 0.05;
    }
  });

  return <points ref={ref} geometry={geo} material={mat} position={center} />;
}

function GalaxyClouds() {
  return (
    <>
      {Object.entries(GALAXY_CENTERS).map(([key, center]) => (
        <GalaxyCloud key={key} center={center} color={GALAXY_COLORS[key] || "#ffffff"} />
      ))}
    </>
  );
}

// ─── Star field ───────────────────────────────────────────────────────────────

function StarField() {
  const ref = useRef<THREE.Points>(null);

  const [geo, mat] = useMemo(() => {
    const N = 4000;
    const pos = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
      const r = 650 + Math.random() * 450;
      const th = Math.random() * Math.PI * 2;
      const ph = Math.acos(2 * Math.random() - 1);
      pos[i * 3]     = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
      pos[i * 3 + 2] = r * Math.cos(ph);

      const t = Math.random();
      col[i * 3]     = 0.4 + t * 0.4;
      col[i * 3 + 1] = 0.4 + t * 0.3;
      col[i * 3 + 2] = 0.6 + t * 0.4;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const m = new THREE.PointsMaterial({
      size: 1.2,
      sizeAttenuation: true,
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
    });
    return [g, m] as const;
  }, []);

  useFrame(({ clock }) => {
    if (ref.current) ref.current.rotation.y = clock.getElapsedTime() * 0.005;
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

  const hoveredNode = useMemo(
    () => (hoveredId ? nodes.find((n) => n.id === hoveredId) : null),
    [hoveredId, nodes]
  );
  const hoveredPos = useMemo(
    () => (hoveredNode ? positions.get(hoveredNode.id) : null),
    [hoveredNode, positions]
  );

  // Material estandarizado con Tone Mapping correcto para que no sature a blanco
  const mat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        roughness: 0.35,
        metalness: 0.15,
        toneMapped: true,
        emissiveIntensity: 0.8, 
      }),
    []
  );

  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const m = new THREE.Matrix4();
    const color = new THREE.Color();
    nodes.forEach((n, i) => {
      const pos = positions.get(n.id) ?? new THREE.Vector3();
      const s = n.scope === "evidence" ? 2.2 : Math.max(3.6, n.size * 1.5);
      m.makeScale(s, s, s);
      m.setPosition(pos.x, pos.y, pos.z);
      mesh.setMatrixAt(i, m);
      const nodeColor = GALAXY_COLORS[n.galaxyId] || n.color;
      color.set(nodeColor);
      mesh.setColorAt(i, color);
    });
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  }, [nodes, positions]);

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

      let s = n.scope === "evidence" ? 2.2 : Math.max(3.6, n.size * 1.5);
      if (!isVisible) {
        s = 0.001;
      } else if (isSelected) {
        s *= 2.2 + Math.sin(t * 3.5) * 0.25;
      } else if (isHovered) {
        s *= 1.8;
      }

      m.makeScale(s, s, s);
      m.setPosition(pos.x + floatX, pos.y + floatY, pos.z);
      mesh.setMatrixAt(i, m);

      const baseColorStr = GALAXY_COLORS[n.galaxyId] || n.color;
      if (isSelected) {
        color.copy(SELECTED_COLOR);
        // El emisivo ayuda a que el Bloom lo detecte más fuertemente
        mesh.material instanceof THREE.MeshStandardMaterial && (mesh.material.emissive = color.clone());
      } else if (isHovered) {
        color.set(baseColorStr).lerp(WHITE, 0.4);
        mesh.material instanceof THREE.MeshStandardMaterial && (mesh.material.emissive = color.clone());
      } else {
        color.set(baseColorStr);
        mesh.material instanceof THREE.MeshStandardMaterial && (mesh.material.emissive = color.clone().multiplyScalar(0.6)); // Brillo base moderado
        if (!isVisible) color.set(0x05050a);
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
    <>
      <instancedMesh
        ref={meshRef}
        args={[SPHERE, mat, nodes.length]}
        onPointerMove={handleMove}
        onPointerOut={handleOut}
        onClick={handleClick}
      />
      {hoveredNode && hoveredPos && (
        <Html
          position={[hoveredPos.x, hoveredPos.y + 14, hoveredPos.z]}
          center
          distanceFactor={450}
          style={{ pointerEvents: "none" }}
        >
          <div
            style={{
              background: "rgba(4, 3, 13, 0.92)",
              border: `1px solid ${GALAXY_COLORS[hoveredNode.galaxyId] || "#38bdf8"}`,
              boxShadow: `0 0 16px ${GALAXY_COLORS[hoveredNode.galaxyId] || "#38bdf8"}66`,
              borderRadius: "8px",
              padding: "8px 14px",
              whiteSpace: "nowrap",
              color: "#ffffff",
              fontFamily: "Inter, sans-serif",
              backdropFilter: "blur(8px)",
              zIndex: 1000,
            }}
          >
            <div style={{ fontSize: "0.68rem", color: GALAXY_COLORS[hoveredNode.galaxyId] || "#38bdf8", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {hoveredNode.galaxyId} · {hoveredNode.kind.replace(/_/g, " ")}
            </div>
            <div style={{ fontSize: "0.95rem", fontWeight: 700, marginTop: "2px" }}>
              {hoveredNode.label}
            </div>
          </div>
        </Html>
      )}
    </>
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
    const DIM = new THREE.Color(0x1d1730);
    const LIT = new THREE.Color(0x38bdf8);

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
      opacity: visibleSet ? 0.85 : 0.18,
    });
    return [g, m] as const;
  }, [edges, positions, visibleSet, selectedId]);

  return <lineSegments geometry={geo} material={mat} />;
}

// ─── Smooth camera rig ────────────────────────────────────────────────────────

function CameraRig({ target }: { target: THREE.Vector3 | null }) {
  const { camera, controls } = useThree();
  const dest = useRef<THREE.Vector3 | null>(null);

  useEffect(() => {
    dest.current = target;
  }, [target]);

  useFrame(() => {
    if (!dest.current) return;
    const orbit = controls as any;
    if (orbit && orbit.target) {
      orbit.target.lerp(dest.current, 0.08);
    }
    const offset = new THREE.Vector3(dest.current.x + 40, dest.current.y + 25, dest.current.z + 85);
    camera.position.lerp(offset, 0.08);
  });

  return null;
}

// ─── Selection ring ───────────────────────────────────────────────────────────

function SelectionRing({ position }: { position: THREE.Vector3 }) {
  const ref = useRef<THREE.Mesh>(null);
  const mat = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: 0xff8899,
        transparent: true,
        opacity: 0.65,
        side: THREE.BackSide,
      }),
    []
  );
  const geo = useMemo(() => new THREE.TorusGeometry(12, 0.6, 8, 48), []);

  useFrame(({ clock }) => {
    const m = ref.current;
    if (!m) return;
    const t = clock.getElapsedTime();
    const s = 1 + Math.sin(t * 2.8) * 0.2;
    m.scale.setScalar(s);
    mat.opacity = 0.4 + Math.sin(t * 2.8) * 0.25;
    m.position.copy(position);
  });

  return <mesh ref={ref} geometry={geo} material={mat} />;
}

// ─── Main Component ───────────────────────────────────────────────────────────

function initialParams() {
  return new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
}

export default function GraphThree({ manifest }: { manifest: DatasetManifest }) {
  const params = initialParams();

  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [status, setStatus] = useState("Loading 3D knowledge map…");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>((params.get("mode") as Mode) || "universe");
  const [depth, setDepth] = useState(Number(params.get("depth") || 1));
  const [activeGalaxy, setActiveGalaxy] = useState(params.get("galaxy") || "");
  const [showSources, setShowSources] = useState(params.get("sources") === "1");
  const [showEvidence, setShowEvidence] = useState(false);
  const [evidenceData, setEvidenceData] = useState<EvidenceRecord[] | null>(null);
  const [layers, setLayers] = useState<Record<LayerName, boolean>>({
    curated: (params.get("edges") || "curated").includes("curated"),
    membership: (params.get("edges") || "").includes("membership"),
    similarity: (params.get("edges") || "").includes("similarity"),
  });
  const [cameraTarget, setCameraTarget] = useState<THREE.Vector3 | null>(null);
  const [relations, setRelations] = useState<Array<{ edge: string; type: string; node: GraphNode }>>([]);

  const [cursorGrab, setCursorGrab] = useState(false);

  useEffect(() => {
    if (showEvidence && !evidenceData) {
      setStatus("Fetching 3,256 raw evidence records…");
      fetch(`/Hugin${manifest.assets.evidence}`)
        .then((r) => r.json())
        .then((items: EvidenceRecord[]) => {
          setEvidenceData(items);
          setStatus(`3,256 raw evidence records loaded.`);
        })
        .catch(() => setStatus("Error loading evidence records."));
    }
  }, [showEvidence, evidenceData, manifest.assets.evidence]);

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
        let allNodes: GraphNode[] = [...payload.nodes];
        let allEdges: GraphEdge[] = [...payload.edges];

        if (layers.similarity) allEdges = [...allEdges, ...simEdges];
        if (layers.membership) allEdges = [...allEdges, ...memEdges];

        if (showEvidence && evidenceData) {
          const evNodes: GraphNode[] = evidenceData.slice(0, 1500).map((ev) => ({
            id: ev.id,
            label: ev.title || `Evidence ${ev.id}`,
            kind: "evidence",
            galaxyId: "evidence",
            category: ev.topic || "raw_evidence",
            route: `/dataset/#${ev.id}`,
            summary: ev.summary || "Raw evidence extraction document.",
            scope: "evidence",
            degree: 1,
            size: 1.2,
            color: "#22d3ee",
            rawEvidence: ev,
          }));

          const evEdges: GraphEdge[] = [];
          evidenceData.slice(0, 1500).forEach((ev) => {
            if (ev.relatedEntityIds && ev.relatedEntityIds[0]) {
              evEdges.push({
                id: `edge-ev-${ev.id}`,
                source: ev.id,
                target: ev.relatedEntityIds[0],
                type: "evidence_of",
                origin: "evidence",
              });
            }
          });

          allNodes = [...allNodes, ...evNodes];
          allEdges = [...allEdges, ...evEdges];
        }

        const positions = compute3DLayout(allNodes, allEdges);
        setGraphData({ nodes: allNodes, edges: allEdges, positions });
        setStatus(`${payload.nodes.length.toLocaleString()} knowledge nodes ready.`);

        const focus = initialParams().get("focus");
        if (focus) {
          const n = allNodes.find((x) => x.id === focus);
          if (n) {
            setSelected(n);
            const pos = positions.get(n.id);
            if (pos) setCameraTarget(pos.clone());
          }
        }
      }, 30);
    });
  }, [manifest, layers.curated, layers.similarity, layers.membership, showEvidence, evidenceData]);

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

  const displayNodes = useMemo(() => {
    if (!graphData) return [];
    return showSources
      ? graphData.nodes
      : graphData.nodes.filter((n) => n.scope !== "support");
  }, [graphData, showSources]);

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

  const selectedPos = useMemo(() => {
    if (!selected || !graphData) return null;
    return graphData.positions.get(selected.id) ?? null;
  }, [selected, graphData]);

  const structuredInfo = useMemo(() => {
    if (!selected) return null;
    return parseAndCleanSummary(selected.summary, selected.label);
  }, [selected]);

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
            <label className="layer-toggle" style={{ marginTop: 6 }}>
              <input
                type="checkbox"
                checked={showEvidence}
                onChange={() => setShowEvidence((v) => !v)}
              />
              <span className="layer-key" style={{ background: "#22d3ee" }} />
              Raw Evidence (3,256)
            </label>
          </fieldset>

          <button className="button" type="button" onClick={resetView} style={{ width: "100%", marginTop: 8 }}>
            Reset view
          </button>
          <a className="button" href="/Hugin/explore/" style={{ display: "block", marginTop: 8, textAlign: "center" }}>
            Catalog
          </a>
        </aside>

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

            {/* Iluminación re-balanceda para no saturar a blanco los neón */}
            <ambientLight intensity={0.15} color="#5566ff" />
            <pointLight position={[300, 300, 200]} intensity={1.5} color="#00ffff" distance={1500} />
            <pointLight position={[-300, -200, -300]} intensity={1.2} color="#ff00aa" distance={1200} />
            <pointLight position={[0, -400, 200]} intensity={0.8} color="#a855f7" distance={1000} />

            <StarField />
            {/* Nubes animadas representando las galaxias */}
            <GalaxyClouds />

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
              dampingFactor={0.06}
              rotateSpeed={0.85}
              zoomSpeed={1.4}
              panSpeed={1.1}
              minDistance={15}
              maxDistance={2400}
              screenSpacePanning={true}
              makeDefault
            />

            <EffectComposer>
              <Bloom
                luminanceThreshold={0.2} // Subimos el umbral para que el fondo no brille
                luminanceSmoothing={0.9}
                intensity={0.8} // Menos intensidad para evitar la mancha blanca
                radius={0.8}
                mipmapBlur // Mejora calidad del blur
              />
            </EffectComposer>
          </Canvas>

          <p className="graph-hint">
            Drag to rotate · scroll to zoom · click a node to inspect · right-drag to pan
          </p>
        </div>

        <aside className="inspector" aria-live="polite">
          {selected ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                <span className="eyebrow-galaxy">{selected.galaxyId}</span>
                <span className="eyebrow-bright">{selected.kind}</span>
                {structuredInfo?.tier && (
                  <span className="tech-badge tier">Tier {structuredInfo.tier}</span>
                )}
              </div>

              <h2>{selected.label}</h2>

              <a className="inspector-action-primary" href={`/Hugin${selected.route}`}>
                Open Full Technical Record →
              </a>

              <p className="inspector-summary">
                {structuredInfo?.cleanSummary ?? selected.summary}
              </p>

              {(structuredInfo?.mitre || structuredInfo?.tags) && (
                <div className="tech-section">
                  <p className="tech-section-title">Classifications & Tags</p>
                  <div className="tech-badges">
                    {structuredInfo.mitre?.map((m) => (
                      <span key={m} className="tech-badge mitre">MITRE {m}</span>
                    ))}
                    {structuredInfo.tags?.map((t) => (
                      <span key={t} className="tech-badge">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {structuredInfo?.files && structuredInfo.files.length > 0 && (
                <div className="tech-section">
                  <p className="tech-section-title">Implementation Files</p>
                  {structuredInfo.files.map((file) => (
                    <div key={file} className="tech-file-box">
                      📄 {file}
                    </div>
                  ))}
                </div>
              )}

              {structuredInfo?.linesOfInterest && structuredInfo.linesOfInterest.length > 0 && (
                <div className="tech-section">
                  <p className="tech-section-title">Key Code Locations</p>
                  {structuredInfo.linesOfInterest.map((loi) => (
                    <div key={loi} className="tech-loi-item">
                      ⚡ {loi}
                    </div>
                  ))}
                </div>
              )}

              {selected.rawEvidence && (
                <div className="tech-section">
                  <p className="tech-section-title">Evidence Extract</p>
                  <p style={{ fontSize: "0.82rem", color: "#cbd5e1" }}>
                    {selected.rawEvidence.summary}
                  </p>
                  <div className="tech-badges" style={{ marginTop: 8 }}>
                    <span className="tech-badge">Score: {selected.rawEvidence.qualityScore}</span>
                    <span className="tech-badge">Topic: {selected.rawEvidence.topic}</span>
                  </div>
                </div>
              )}

              <dl>
                <dt>ID</dt><dd>{selected.id}</dd>
                <dt>Category</dt><dd>{selected.category}</dd>
                <dt>Relations</dt><dd>{selected.degree.toLocaleString()}</dd>
                <dt>Scope</dt><dd>{selected.scope}</dd>
              </dl>

              {!selected.isGalaxy && (
                <button
                  className="button"
                  type="button"
                  onClick={() => setMode("neighborhood")}
                  style={{ width: "100%", marginTop: 8 }}
                >
                  Explore Neighborhood →
                </button>
              )}

              {relations.length > 0 && (
                <div className="tech-section">
                  <p className="tech-section-title">Connected Knowledge Nodes</p>
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
                </div>
              )}
            </>
          ) : (
            <>
              <span className="eyebrow-bright">Universe Inspector</span>
              <h2 style={{ marginTop: 8 }}>{manifest.counts.coreEntities.toLocaleString()} knowledge nodes</h2>
              <p className="inspector-summary">
                Rotate and zoom to explore the 3D knowledge universe. Click any node to inspect its
                clean technical specification, implementation code locations, or enter neighborhood mode to trace connections.
              </p>
              <dl>
                <dt>Curated Edges</dt><dd>{manifest.counts.curatedRelations.toLocaleString()}</dd>
                <dt>Galaxies</dt><dd>{manifest.counts.galaxies}</dd>
                <dt>Support Nodes</dt><dd>{manifest.counts.supportEntities.toLocaleString()}</dd>
                <dt>Evidence Records</dt><dd>{manifest.counts.evidenceRecords.toLocaleString()}</dd>
              </dl>
              <a href="/Hugin/explore/" className="inspector-action-primary">
                Open Full Catalog →
              </a>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
