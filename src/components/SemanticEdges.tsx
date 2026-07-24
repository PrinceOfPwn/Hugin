import { useFrame } from "@react-three/fiber";
import { useMemo } from "react";
import * as THREE from "three";

export type EdgeType =
  | "enables" | "counters" | "detects" | "chains_to" | "requires"
  | "implements" | "derived_from" | "alternative_to" | "related"
  | "concept_link" | "reference" | "enhances";

export type SemanticEdge = {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
};

interface Props {
  edges: SemanticEdge[];
  positions: Map<string, THREE.Vector3>;
  selectedId: string | null;
  visibleSet: Set<string> | null;
  hoveredId?: string | null;
}

const TYPE_ORDER: EdgeType[] = [
  "enables", "counters", "detects", "chains_to", "requires",
  "implements", "derived_from", "alternative_to", "related",
  "concept_link", "reference", "enhances",
];

const TYPE_INDEX: Record<EdgeType, number> = TYPE_ORDER.reduce((a, t, i) => (a[t] = i, a), {} as any);

const vert = /* glsl */`
  attribute float aT;           // 0 at source, 1 at target
  attribute float aTypeIdx;     // 0..11
  attribute float aHash;        // 0..1 stable per edge
  attribute float aFlag;        // 0=idle 1=selected 2=hovered
  varying float vT;
  varying float vType;
  varying float vHash;
  varying float vFlag;
  void main() {
    vT = aT; vType = aTypeIdx; vHash = aHash; vFlag = aFlag;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

// 12 type styles: (color.rgb, dashDensity, pulseSpeed, brightness, waveMode)
// waveMode: 0=flow forward, 1=incoming (backwards), 2=scanning (bounce), 3=static, 4=parallel double
const frag = /* glsl */`
  precision highp float;
  uniform float uTime;
  varying float vT;
  varying float vType;
  varying float vHash;
  varying float vFlag;

  // color table
  vec3 typeColor(float t) {
    if (t < 0.5) return vec3(0.00, 0.94, 1.00);   // enables — cyan
    if (t < 1.5) return vec3(1.00, 0.20, 0.30);   // counters — hot red
    if (t < 2.5) return vec3(0.22, 1.00, 0.42);   // detects — neon green
    if (t < 3.5) return vec3(1.00, 0.72, 0.06);   // chains_to — amber gold
    if (t < 4.5) return vec3(0.88, 0.24, 0.98);   // requires — magenta
    if (t < 5.5) return vec3(0.95, 0.95, 1.00);   // implements — white
    if (t < 6.5) return vec3(0.00, 0.90, 0.75);   // derived_from — teal
    if (t < 7.5) return vec3(0.62, 0.31, 0.96);   // alternative_to — violet
    if (t < 8.5) return vec3(0.55, 0.62, 0.75);   // related — pale steel
    if (t < 9.5) return vec3(0.00, 0.70, 0.90);   // concept_link — sky
    if (t <10.5) return vec3(0.42, 0.46, 0.55);   // reference — muted gray
    return           vec3(1.00, 0.86, 0.30);       // enhances — hot gold
  }

  // brightness / base opacity per type
  float typeBrightness(float t) {
    if (t < 0.5) return 1.40;   // enables — strong
    if (t < 1.5) return 1.80;   // counters — very strong
    if (t < 2.5) return 1.50;   // detects — strong
    if (t < 3.5) return 1.60;   // chains_to — strong
    if (t < 4.5) return 1.30;   // requires — medium-strong
    if (t < 5.5) return 1.10;   // implements — medium
    if (t < 6.5) return 0.90;   // derived_from — medium
    if (t < 7.5) return 1.00;   // alternative_to — medium
    if (t < 8.5) return 0.45;   // related — faint
    if (t < 9.5) return 0.60;   // concept_link — faint-medium
    if (t <10.5) return 0.35;   // reference — very faint
    return           1.30;      // enhances — strong
  }

  // wave mode per type
  int typeWaveMode(float t) {
    if (t < 0.5) return 0;   // enables — flow forward
    if (t < 1.5) return 1;   // counters — incoming toward target
    if (t < 2.5) return 2;   // detects — scanning bounce
    if (t < 3.5) return 0;   // chains_to — flow forward (chain)
    if (t < 4.5) return 1;   // requires — incoming (dependency)
    if (t < 5.5) return 3;   // implements — solid pulse
    if (t < 6.5) return 3;   // derived_from — dashed static
    if (t < 7.5) return 4;   // alternative_to — parallel twin
    if (t < 8.5) return 3;   // related — thin dashed
    if (t < 9.5) return 0;   // concept_link — soft flow
    if (t <10.5) return 3;   // reference — static faint
    return           0;      // enhances — flow with glow
  }

  void main() {
    vec3 col = typeColor(vType);
    float bright = typeBrightness(vType);
    int mode = typeWaveMode(vType);

    float pulseSpeed = 0.25 + vHash * 0.3;
    if (vFlag > 0.5) { pulseSpeed *= 2.0; bright *= 1.6; }

    float baseGlow = 0.08 * bright;
    float pulse = 0.0;

    if (mode == 0) {
      // flow source->target
      float t_scaled = vT * (2.0 + floor(vHash * 3.0)) - uTime * pulseSpeed;
      float t_norm = fract(t_scaled);
      pulse = smoothstep(0.5, 0.42, abs(t_norm - 0.5));
    } else if (mode == 1) {
      // incoming target->source
      float t_scaled = (1.0 - vT) * (2.0 + floor(vHash * 3.0)) - uTime * pulseSpeed;
      float t_norm = fract(t_scaled);
      pulse = smoothstep(0.5, 0.42, abs(t_norm - 0.5));
    } else if (mode == 2) {
      // scanning bounce
      float phase = mod(uTime * pulseSpeed * 0.6 + vHash, 2.0);
      float head = phase < 1.0 ? phase : (2.0 - phase);
      pulse = smoothstep(0.06, 0.0, abs(vT - head));
    } else if (mode == 3) {
      // static dashed
      float dash = fract(vT * (6.0 + floor(vHash * 4.0)));
      pulse = smoothstep(0.5, 0.35, abs(dash - 0.5)) * 0.35;
    } else {
      // parallel twin flow
      float t_scaled = vT * 3.0 - uTime * pulseSpeed;
      float a = smoothstep(0.5, 0.42, abs(fract(t_scaled) - 0.5));
      float b = smoothstep(0.5, 0.42, abs(fract(t_scaled + 0.25) - 0.5));
      pulse = max(a, b);
    }

    float sel = vFlag > 0.5 ? 1.4 : 1.0;
    vec3 finalColor = col * baseGlow + col * pulse * 2.6 * sel * bright;
    float alpha = clamp(baseGlow + pulse * bright * sel, 0.0, 1.0);
    gl_FragColor = vec4(finalColor, alpha);
  }
`;

function hashId(id: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < id.length; i++) { h ^= id.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) / 4294967295;
}

export default function SemanticEdges({ edges, positions, selectedId, visibleSet, hoveredId }: Props) {
  const geometry = useMemo(() => {
    const valid = edges.filter(e =>
      positions.has(e.source) && positions.has(e.target) &&
      (!visibleSet || (visibleSet.has(e.source) && visibleSet.has(e.target)))
    );
    const n = valid.length;
    const pos = new Float32Array(n * 6);
    const t = new Float32Array(n * 2);
    const type = new Float32Array(n * 2);
    const hash = new Float32Array(n * 2);
    const flag = new Float32Array(n * 2);

    for (let i = 0; i < n; i++) {
      const e = valid[i];
      const s = positions.get(e.source)!;
      const g = positions.get(e.target)!;
      const b6 = i * 6, b2 = i * 2;
      pos[b6] = s.x; pos[b6+1] = s.y; pos[b6+2] = s.z;
      pos[b6+3] = g.x; pos[b6+4] = g.y; pos[b6+5] = g.z;
      t[b2] = 0; t[b2+1] = 1;
      const ti = TYPE_INDEX[e.type] ?? 8;
      type[b2] = ti; type[b2+1] = ti;
      const h = hashId(e.id);
      hash[b2] = h; hash[b2+1] = h;
      const f = (selectedId && (e.source === selectedId || e.target === selectedId)) ? 1
              : (hoveredId && (e.source === hoveredId || e.target === hoveredId)) ? 0.6 : 0;
      flag[b2] = f; flag[b2+1] = f;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    geo.setAttribute("aT", new THREE.BufferAttribute(t, 1));
    geo.setAttribute("aTypeIdx", new THREE.BufferAttribute(type, 1));
    geo.setAttribute("aHash", new THREE.BufferAttribute(hash, 1));
    geo.setAttribute("aFlag", new THREE.BufferAttribute(flag, 1));
    return geo;
  }, [edges, positions, selectedId, hoveredId, visibleSet]);

  const material = useMemo(() => new THREE.ShaderMaterial({
    vertexShader: vert,
    fragmentShader: frag,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: { uTime: { value: 0 } },
  }), []);

  useFrame((state) => { material.uniforms.uTime.value = state.clock.elapsedTime; });

  return <lineSegments geometry={geometry} material={material} />;
}
