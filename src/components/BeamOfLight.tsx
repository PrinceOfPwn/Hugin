import { useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export type BeamEdge = { source: string; target: string; type?: string };

interface Props {
  selectedId: string | null;
  edges: BeamEdge[];
  positions: Map<string, THREE.Vector3>;
  color?: string;
}

// ═════════════════════════════════════════════════════════════════════════════
//  BeamOfLight — highlight edges that touch the selected node.
//
//  Renders a bright, additively-blended LineSegments with a traveling
//  glow: each edge has a phase-offset "packet" of light that races along the
//  segment from source → target. Everything is shader-driven, so we push zero
//  work per frame from JS (only the geometry rebuild when selection changes).
// ═════════════════════════════════════════════════════════════════════════════

const vert = /* glsl */`
  attribute float aParam;   // 0.0 at source, 1.0 at target (interpolated)
  attribute float aPhase;   // per-edge phase offset (both endpoints share)
  varying float vParam;
  varying float vPhase;
  void main() {
    vParam = aParam;
    vPhase = aPhase;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const frag = /* glsl */`
  precision highp float;
  varying float vParam;
  varying float vPhase;
  uniform float uTime;
  uniform vec3  uColor;      // cyan-ish base
  uniform vec3  uHighlight;  // bright core (white)

  void main() {
    // Traveling glow: a bright dot at position tHead(t) along the segment.
    float t = fract(uTime * 0.85 + vPhase);
    // Wrap distance so the head glows across the seam.
    float d = abs(vParam - t);
    d = min(d, 1.0 - d);
    float head = smoothstep(0.14, 0.0, d);
    // Faint pulsing base along the whole edge.
    float base = 0.55 + 0.20 * sin(uTime * 2.2 + vPhase * 6.28);
    vec3 col = mix(uColor, uHighlight, head) * (base + head * 1.4);
    float a  = clamp(base * 0.65 + head * 0.9, 0.0, 1.0);
    gl_FragColor = vec4(col, a);
  }
`;

// Cheap deterministic hash → [0,1). Used to give each edge a stable phase.
function hash01(str: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return (h & 0xffff) / 0xffff;
}

export default function BeamOfLight({ selectedId, edges, positions, color = "#00e5ff" }: Props) {

  // Filter to edges touching selection; build one LineSegments geometry.
  const geometry = useMemo(() => {
    if (!selectedId) return null;
    const touching: Array<{ e: BeamEdge; key: string }> = [];
    for (const e of edges) {
      if (e.source !== selectedId && e.target !== selectedId) continue;
      if (!positions.has(e.source) || !positions.has(e.target)) continue;
      touching.push({ e, key: `${e.source}|${e.target}` });
    }
    if (touching.length === 0) return null;

    const n = touching.length;
    const pos = new Float32Array(n * 6);
    const param = new Float32Array(n * 2);
    const phase = new Float32Array(n * 2);

    for (let i = 0; i < n; i++) {
      const { e, key } = touching[i];
      const s = positions.get(e.source)!;
      const t = positions.get(e.target)!;
      // Orient so the "head" always races AWAY from the selected node:
      // param=0 at selected, param=1 at neighbor.
      const selectedIsSource = e.source === selectedId;
      const from = selectedIsSource ? s : t;
      const to   = selectedIsSource ? t : s;
      const b6 = i * 6;
      pos[b6]     = from.x; pos[b6+1] = from.y; pos[b6+2] = from.z;
      pos[b6+3]   = to.x;   pos[b6+4] = to.y;   pos[b6+5] = to.z;
      param[i * 2]     = 0.0;
      param[i * 2 + 1] = 1.0;
      const ph = hash01(key);
      phase[i * 2]     = ph;
      phase[i * 2 + 1] = ph;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    geo.setAttribute("aParam",   new THREE.BufferAttribute(param, 1));
    geo.setAttribute("aPhase",   new THREE.BufferAttribute(phase, 1));
    return geo;
  }, [selectedId, edges, positions]);

  const material = useMemo(() => {
    const c = new THREE.Color(color);
    return new THREE.ShaderMaterial({
      vertexShader: vert,
      fragmentShader: frag,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        uTime:      { value: 0 },
        uColor:     { value: new THREE.Vector3(c.r, c.g, c.b) },
        uHighlight: { value: new THREE.Vector3(1, 1, 1) },
      },
    });
  }, [color]);

  // Drive uTime — one uniform write per frame, no allocations.
  useFrame(({ clock }) => {
    material.uniforms.uTime.value = clock.getElapsedTime();
  });

  if (!geometry) return null;
  return (
    <lineSegments
      geometry={geometry}
      material={material}
      frustumCulled={false}
      renderOrder={20}
    />
  );
}
