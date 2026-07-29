// ═════════════════════════════════════════════════════════════════════════════
//  SpacetimeGrid — a fine wireframe plane on the XZ world-plane that deforms
//  under the influence of nearby heavy-mass nodes.
//
//  Spacetime displacement is a Newtonian approximation of spatial curvature:
//
//      y(p) = − Σ_k  G · m_k / ( |p.xz − q_k.xz|² + ε² )
//
//  where G is a *visual* scale factor (not the physical gravitational
//  constant), ε is a softening length that prevents the divergence at r → 0,
//  and the sum runs over the K heaviest nodes. This is *not* general
//  relativity — GR predicts a metric perturbation h_{μν} whose spatial part
//  goes like 2Φ/c² with Φ the Newtonian potential — but the same 1/r² well
//  shape is what you'd see if you Taylor-expanded Schwarzschild in the weak
//  field limit. We render this as a downward Y-displacement of the plane;
//  it's a visual analog, not GR-accurate.
//
//  Everything happens in the vertex shader — one draw call, zero JS math per
//  frame. Heavy-node uniforms are only re-written when they change (dirty
//  check on incoming props via reference identity + numeric compare).
// ═════════════════════════════════════════════════════════════════════════════

import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export type SpacetimeHeavyNode = {
  id: string;
  position: [number, number, number];
  mass: number;
};

interface Props {
  heavyNodes: SpacetimeHeavyNode[];
  visible: boolean;
  intensity?: number;
  size?: number;
  subdivisions?: number;
  paletteHint?: "cool" | "warm" | "duo";
}

// Compile-time constant — must match the K used in the vertex shader loop.
const K = 16;

// Visual scale factor. NOT the physical gravitational constant. Tuned so that
// a node with mass=1 at horizontal distance ~40 produces a well roughly ~1
// unit deep. Increase to make wells more dramatic.
const G_VIS = 1200.0;

// Softening length ε (world units). Prevents divergence at r → 0 and keeps
// the well finite at the node's projected footprint.
const SOFTENING = 40.0;

// Well floor — clamps y to ≥ -MAX_WELL so extreme cases don't nuke the mesh.
const MAX_WELL = 200.0;

// Grid line spacing in world units (fragment shader).
const GRID_SPACING = 30.0;

const vert = /* glsl */ `
  precision highp float;

  // K heavy nodes: xyz + mass packed as a vec4 (xz used for displacement, y
  // ignored because we displace along Y on an XZ-plane).
  uniform vec4  uHeavy[${K}];   // (x, y, z, mass)
  uniform int   uHeavyCount;
  uniform float uIntensity;
  uniform float uTime;
  uniform float uMaxWell;
  uniform float uG;
  uniform float uSoft;

  varying vec3 vWorldPos;
  varying float vDepth;

  // Cheap value-noise for breathing motion.
  float hash21(vec2 p) {
    p = fract(p * vec2(123.34, 456.21));
    p += dot(p, p + 45.32);
    return fract(p.x * p.y);
  }
  float vnoise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    float a = hash21(i);
    float b = hash21(i + vec2(1.0, 0.0));
    float c = hash21(i + vec2(0.0, 1.0));
    float d = hash21(i + vec2(1.0, 1.0));
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(a, b, u.x) + (c - a) * u.y * (1.0 - u.x) + (d - b) * u.x * u.y;
  }

  void main() {
    // The PlaneGeometry lies on its own local XY plane; we rotate it to XZ in
    // JS. Take the *world-space* horizontal footprint for displacement math.
    vec4 wp = modelMatrix * vec4(position, 1.0);
    vec2 pxz = wp.xz;

    // Newtonian potential-like sum. y is negative (nodes pull the sheet down).
    float y = 0.0;
    float soft2 = uSoft * uSoft;
    for (int k = 0; k < ${K}; k++) {
      if (k >= uHeavyCount) break;
      vec4 h = uHeavy[k];
      vec2 dxz = pxz - h.xz;
      float r2 = dot(dxz, dxz) + soft2;
      y -= uIntensity * uG * h.w / r2;
    }
    y = clamp(y, -uMaxWell, 0.0);

    // Subtle "breathing" — plane feels alive, but does not dominate.
    float breathe = sin(uTime * 0.15 + vnoise(pxz * 0.005) * 6.2831) * 0.3;
    y += breathe;

    wp.y += y;
    vWorldPos = wp.xyz;
    vDepth = -y / uMaxWell;   // 0 flat → 1 deepest well

    gl_Position = projectionMatrix * viewMatrix * wp;
  }
`;

const frag = /* glsl */ `
  precision highp float;

  #extension GL_OES_standard_derivatives : enable

  varying vec3 vWorldPos;
  varying float vDepth;

  uniform float uGridSpacing;
  uniform float uSize;
  uniform vec3  uColorA;   // shallow color
  uniform vec3  uColorB;   // deep color

  void main() {
    // Grid lines on world XZ using screen-space derivatives so the line width
    // stays constant in pixels regardless of camera distance.
    vec2 uv   = vWorldPos.xz / uGridSpacing;
    vec2 g    = abs(fract(uv - 0.5) - 0.5) / max(fwidth(uv), vec2(1e-5));
    float line = 1.0 - min(min(g.x, g.y), 1.0);

    // Bold every 10th line — anchors the eye and communicates scale.
    vec2 uvMajor = vWorldPos.xz / (uGridSpacing * 10.0);
    vec2 gM = abs(fract(uvMajor - 0.5) - 0.5) / max(fwidth(uvMajor), vec2(1e-5));
    float lineMajor = 1.0 - min(min(gM.x, gM.y), 1.0);

    // Fade toward the outer border so the mesh doesn't clip abruptly.
    float half_ = uSize * 0.5;
    float ex = 1.0 - smoothstep(half_ * 0.65, half_ * 0.98, abs(vWorldPos.x));
    float ez = 1.0 - smoothstep(half_ * 0.65, half_ * 0.98, abs(vWorldPos.z));
    float edgeFade = ex * ez;

    // Depth shading — warmer where the well is deeper.
    vec3 col = mix(uColorA, uColorB, clamp(vDepth * 1.2, 0.0, 1.0));

    float baseAlpha = 0.22;
    float alpha = (line * baseAlpha + lineMajor * baseAlpha * 0.9) * edgeFade;
    alpha *= (0.55 + 0.65 * vDepth);   // lines glow a bit brighter in wells

    if (alpha < 0.002) discard;

    gl_FragColor = vec4(col * (0.7 + 0.9 * vDepth), alpha);
  }
`;

function palette(hint: "cool" | "warm" | "duo") {
  // Restrained. Low-saturation. Additive.
  if (hint === "cool") return { a: new THREE.Color("#4b7fbf"), b: new THREE.Color("#22d3ee") };
  if (hint === "warm") return { a: new THREE.Color("#b06a7f"), b: new THREE.Color("#ff7a4a") };
  // duo: cyan grid fading into magenta wells
  return { a: new THREE.Color("#3aa8c8"), b: new THREE.Color("#c86adf") };
}

export default function SpacetimeGrid({
  heavyNodes,
  visible,
  intensity = 0.6,
  size = 6000,
  subdivisions = 200,
  paletteHint = "duo",
}: Props) {
  const meshRef = useRef<THREE.Mesh>(null);
  const lastHeavyKey = useRef<string>("");

  // Geometry: PlaneGeometry rotated onto the XZ world plane (Y = flat).
  const geometry = useMemo(() => {
    const g = new THREE.PlaneGeometry(size, size, subdivisions, subdivisions);
    g.rotateX(-Math.PI / 2);
    return g;
  }, [size, subdivisions]);

  const uniforms = useMemo(() => {
    const arr = new Array(K).fill(0).map(() => new THREE.Vector4(0, 0, 0, 0));
    const { a, b } = palette(paletteHint);
    return {
      uHeavy: { value: arr },
      uHeavyCount: { value: 0 },
      uIntensity: { value: intensity },
      uTime: { value: 0 },
      uMaxWell: { value: MAX_WELL },
      uG: { value: G_VIS },
      uSoft: { value: SOFTENING },
      uGridSpacing: { value: GRID_SPACING },
      uSize: { value: size },
      uColorA: { value: new THREE.Vector3(a.r, a.g, a.b) },
      uColorB: { value: new THREE.Vector3(b.r, b.g, b.b) },
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const material = useMemo(() => {
    const m = new THREE.ShaderMaterial({
      vertexShader: vert,
      fragmentShader: frag,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      side: THREE.DoubleSide,
      uniforms,
      extensions: { derivatives: true } as any,
    });
    return m;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uniforms]);

  // Push palette updates when the hint changes (no re-alloc).
  useEffect(() => {
    const { a, b } = palette(paletteHint);
    (uniforms.uColorA.value as THREE.Vector3).set(a.r, a.g, a.b);
    (uniforms.uColorB.value as THREE.Vector3).set(b.r, b.g, b.b);
  }, [paletteHint, uniforms]);

  // Intensity + size uniform sync (no re-alloc).
  useEffect(() => { uniforms.uIntensity.value = intensity; }, [intensity, uniforms]);
  useEffect(() => { uniforms.uSize.value = size; }, [size, uniforms]);

  // Heavy-node uniform update — only when they actually change.
  useEffect(() => {
    if (!visible) return;
    const arr = uniforms.uHeavy.value as THREE.Vector4[];
    const count = Math.min(heavyNodes.length, K);
    // Build a signature so we don't touch uniforms if positions/masses match.
    let sig = String(count);
    for (let i = 0; i < count; i++) {
      const n = heavyNodes[i];
      sig += `|${n.position[0].toFixed(2)},${n.position[1].toFixed(2)},${n.position[2].toFixed(2)},${n.mass.toFixed(3)}`;
    }
    if (sig === lastHeavyKey.current) return;
    lastHeavyKey.current = sig;

    for (let i = 0; i < count; i++) {
      const n = heavyNodes[i];
      arr[i].set(n.position[0], n.position[1], n.position[2], Math.max(0, n.mass));
    }
    for (let i = count; i < K; i++) arr[i].set(0, 0, 0, 0);
    uniforms.uHeavyCount.value = count;
  }, [heavyNodes, visible, uniforms]);

  // Time-only per-frame write. Zero allocations.
  useFrame(({ clock }) => {
    if (!visible) return;
    uniforms.uTime.value = clock.getElapsedTime();
  });

  if (!visible) return null;

  return (
    <mesh
      ref={meshRef}
      geometry={geometry}
      material={material}
      frustumCulled={false}
      renderOrder={-2}
    />
  );
}
