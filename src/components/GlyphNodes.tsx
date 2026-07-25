import { useLayoutEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import type { ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";

export type NodeKind =
  | "technique" | "chain" | "detection" | "concept"
  | "lgtm_note" | "playbook" | "source" | "source-extract"
  | "documentation" | "reference" | "pattern";

export type GlyphNodeData = {
  id: string;
  position: THREE.Vector3;
  color: string;
  size: number;
  kind: NodeKind;
  tier?: "S" | "A" | "B" | "C";  // techniques only
};

interface Props {
  nodes: GlyphNodeData[];
  hoveredId: string | null;
  selectedId: string | null;
  visibleSet: Set<string> | null;
  onHover: (id: string | null) => void;
  onClick: (id: string) => void;
}

const KIND_INDEX: Record<NodeKind, number> = {
  technique: 0, chain: 1, detection: 2, concept: 3,
  lgtm_note: 4, playbook: 5, source: 6, "source-extract": 6,
  documentation: 7, reference: 8, pattern: 8,
};

const vert = /* glsl */`
  uniform float uTime;
  attribute vec3 aColor;
  attribute float aSize;
  attribute float aPhase;
  attribute float aFlags;
  attribute float aKind;
  attribute float aTier;
  varying vec2 vUv;
  varying vec3 vColor;
  varying float vFlags;
  varying float vKind;
  varying float vTier;
  varying float vPhase;

  void main() {
    vUv = uv - 0.5;
    vColor = aColor;
    vFlags = aFlags;
    vKind = aKind;
    vTier = aTier;
    vPhase = aPhase;

    float f = aFlags;
    bool isVisible = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isHovered = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isSelected = mod(f, 2.0) > 0.5;

    if (!isVisible) { gl_Position = vec4(0.0, 0.0, -10000.0, 1.0); return; }

    vec3 instPos = instanceMatrix[3].xyz;
    vec3 camR = viewMatrix[0].xyz;
    vec3 camU = viewMatrix[1].xyz;

    // Breathing — stronger for techniques, subtler for concepts
    float breathAmp = aKind < 0.5 ? 0.22 : (aKind < 3.5 ? 0.15 : 0.08);
    float breath = sin(uTime * 0.6 + aPhase) * breathAmp + 1.0;

    // Tier boosts size for techniques (S=1.5x, A=1.25x, B=1.0x, C=0.8x)
    float tierBoost = 1.0;
    if (aKind < 0.5) tierBoost = 1.6 - aTier * 0.2;  // aTier 0..3

    float size = aSize * breath * tierBoost;
    if (isHovered) size *= 1.9;
    if (isSelected) size *= 1.5 + sin(uTime * 4.0) * 0.15;

    // Chains get elongated (aspect ratio)
    vec2 stretch = vec2(1.0);
    if (aKind >= 0.5 && aKind < 1.5) {
      // rotate elongation slowly for chain feel
      float ang = uTime * 0.4 + aPhase;
      stretch = vec2(1.7, 0.55);
      vec2 uv = vUv;
      float c = cos(ang), s = sin(ang);
      uv = vec2(c*uv.x - s*uv.y, s*uv.x + c*uv.y);
      vec3 vertOff = (camR * uv.x * stretch.x + camU * uv.y * stretch.y) * size;
      gl_Position = projectionMatrix * viewMatrix * vec4(instPos + vertOff, 1.0);
      return;
    }

    vec3 vertOff = (camR * vUv.x + camU * vUv.y) * size;
    gl_Position = projectionMatrix * viewMatrix * vec4(instPos + vertOff, 1.0);
  }
`;

const frag = /* glsl */`
  precision highp float;
  uniform float uTime;
  varying vec2 vUv;
  varying vec3 vColor;
  varying float vFlags;
  varying float vKind;
  varying float vTier;
  varying float vPhase;

  float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
  float noise(vec2 p) {
    vec2 i = floor(p), f = fract(p);
    f = f*f*(3.0-2.0*f);
    return mix(mix(hash(i), hash(i+vec2(1,0)), f.x),
               mix(hash(i+vec2(0,1)), hash(i+vec2(1,1)), f.x), f.y);
  }

  // signed distance to regular n-gon
  float sdPolygon(vec2 p, float r, float n) {
    float ang = atan(p.y, p.x);
    float slice = 6.2831853 / n;
    float a = mod(ang, slice) - slice * 0.5;
    return cos(a) * length(p) - r;
  }

  void main() {
    float f = vFlags;
    bool isVisible = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isHovered = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isSelected = mod(f, 2.0) > 0.5;
    if (!isVisible) discard;

    vec2 uv = vUv * 2.0;   // -1..1
    float dist = length(uv);

    // Base glyph mask per kind
    float core = 0.0;
    float ring = 0.0;
    float corona = 0.0;

    int k = int(vKind + 0.5);

    if (k == 0) {
      // TECHNIQUE — bright pulsating star with sharp corona
      core = smoothstep(0.18, 0.0, dist);
      ring = smoothstep(0.42, 0.18, dist);
      corona = exp(-dist * 2.3);
      // 4-pointed star cross
      float cross = max(smoothstep(0.02, 0.0, abs(uv.x) * 0.5) * smoothstep(0.6, 0.0, abs(uv.y)),
                        smoothstep(0.02, 0.0, abs(uv.y) * 0.5) * smoothstep(0.6, 0.0, abs(uv.x)));
      corona += cross * 0.6;
    } else if (k == 1) {
      // CHAIN — elongated meteor (uv already stretched by vertex)
      core = smoothstep(0.15, 0.0, dist);
      ring = smoothstep(0.5, 0.15, dist);
      corona = exp(-dist * 1.8) * 0.8;
    } else if (k == 2) {
      // DETECTION — hexagonal shield
      float hex = sdPolygon(uv, 0.55, 6.0);
      float hexRing = smoothstep(0.0, -0.06, hex) * smoothstep(-0.18, -0.12, hex);
      float hexFill = smoothstep(0.0, -0.02, hex);
      core = hexFill * 0.6;
      ring = hexRing * 1.2;
      corona = smoothstep(0.15, -0.05, hex) * 0.5;
    } else if (k == 3) {
      // CONCEPT — small soft orb
      core = smoothstep(0.14, 0.0, dist);
      ring = smoothstep(0.32, 0.14, dist);
      corona = exp(-dist * 3.2) * 0.6;
    } else if (k == 4) {
      // LGTM_NOTE — flickering wisp (vertical stretched)
      vec2 wisp = vec2(uv.x * 2.0, uv.y * 0.7);
      float wdist = length(wisp);
      float flicker = 0.5 + 0.5 * sin(uTime * 3.0 + vPhase * 6.0);
      core = smoothstep(0.25, 0.0, wdist) * flicker;
      corona = exp(-wdist * 2.5) * 0.4 * flicker;
    } else if (k == 5) {
      // PLAYBOOK — square/tile
      float sq = max(abs(uv.x), abs(uv.y));
      core = smoothstep(0.25, 0.0, sq);
      ring = smoothstep(0.55, 0.4, sq);
      corona = exp(-sq * 1.8) * 0.5;
    } else if (k == 6) {
      // SOURCE / EXTRACT — diamond glyph
      float diam = abs(uv.x) + abs(uv.y);
      core = smoothstep(0.25, 0.0, diam);
      ring = smoothstep(0.6, 0.35, diam);
      corona = smoothstep(0.9, 0.5, diam) * 0.4;
    } else if (k == 7) {
      // DOCUMENTATION — triangle
      float tri = sdPolygon(uv, 0.5, 3.0);
      core = smoothstep(0.0, -0.15, tri);
      ring = smoothstep(-0.08, -0.14, tri);
      corona = smoothstep(0.2, -0.05, tri) * 0.5;
    } else {
      // REFERENCE / PATTERN — subtle dot
      core = smoothstep(0.12, 0.0, dist);
      corona = exp(-dist * 4.0) * 0.35;
    }

    // Halo noise + sparkle for star-class kinds
    if (k <= 3 || k == 5) {
      float n = noise(uv * 5.0 + vec2(uTime * 0.25, uTime * 0.18));
      corona *= 0.75 + n * 0.45;
      float sparkle = noise(uv * 9.0 + uTime * 1.6) * smoothstep(0.9, 0.4, dist);
      corona += sparkle * 0.18;
    }

    // HDR colors sized for bloom
    vec3 coreCol = vec3(1.0, 0.98, 0.9) * 8.0;
    vec3 midCol  = vColor * 4.0;
    vec3 outCol  = vColor * 1.6;

    vec3 color = coreCol * core + midCol * ring + outCol * corona;

    if (isHovered) color += coreCol * smoothstep(0.35, 0.0, dist) * 0.7;
    if (isSelected) {
      float t = mod(uTime * 0.9, 1.0);
      float rd = t * 1.3 + 0.2;
      float rp = smoothstep(0.05, 0.0, abs(dist - rd)) * (1.0 - t);
      color += outCol * rp * 4.5;
    }

    float alpha = clamp(max(max(color.r, color.g), color.b), 0.0, 1.0);
    gl_FragColor = vec4(color, alpha);
  }
`;

export default function GlyphNodes({ nodes, hoveredId, selectedId, visibleSet, onHover, onClick }: Props) {
  const meshRef = useRef<THREE.InstancedMesh>(null);

  const [geometry, material] = useMemo(() => {
    const geo = new THREE.PlaneGeometry(1, 1);
    const count = nodes.length;
    const aColor = new Float32Array(count * 3);
    const aSize = new Float32Array(count);
    const aPhase = new Float32Array(count);
    const aFlags = new Float32Array(count);
    const aKind = new Float32Array(count);
    const aTier = new Float32Array(count);

    const TIER = { S: 0, A: 1, B: 2, C: 3 } as const;

    for (let i = 0; i < count; i++) {
      const n = nodes[i];
      const c = new THREE.Color(n.color);
      aColor[i * 3] = c.r; aColor[i * 3 + 1] = c.g; aColor[i * 3 + 2] = c.b;
      aSize[i] = n.size;
      aPhase[i] = Math.random() * Math.PI * 2;
      aFlags[i] = 1;
      aKind[i] = KIND_INDEX[n.kind] ?? 8;
      aTier[i] = n.tier ? TIER[n.tier] : 2;
    }

    geo.setAttribute("aColor", new THREE.InstancedBufferAttribute(aColor, 3));
    geo.setAttribute("aSize", new THREE.InstancedBufferAttribute(aSize, 1));
    geo.setAttribute("aPhase", new THREE.InstancedBufferAttribute(aPhase, 1));
    geo.setAttribute("aFlags", new THREE.InstancedBufferAttribute(aFlags, 1));
    geo.setAttribute("aKind", new THREE.InstancedBufferAttribute(aKind, 1));
    geo.setAttribute("aTier", new THREE.InstancedBufferAttribute(aTier, 1));

    const mat = new THREE.ShaderMaterial({
      uniforms: { uTime: { value: 0 } },
      vertexShader: vert,
      fragmentShader: frag,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
    return [geo, mat];
  }, [nodes]);

  // Custom raycast: the visual is a camera-billboarded glyph, but the base
  // PlaneGeometry(1,1) is fixed in XY world — edge-on to most camera angles.
  // Instead of relying on the base geometry, treat each instance as a sphere
  // in world space and hit-test against that.
  const raycastCallback = useMemo(() => {
    return function customRaycast(this: THREE.InstancedMesh, raycaster: THREE.Raycaster, intersects: THREE.Intersection[]) {
      const m = new THREE.Matrix4();
      const pos = new THREE.Vector3();
      const sphere = new THREE.Sphere();
      const hit = new THREE.Vector3();
      for (let i = 0; i < this.count; i++) {
        this.getMatrixAt(i, m);
        pos.setFromMatrixPosition(m);
        // Scale from matrix is our per-instance hit radius (set below in useLayoutEffect).
        const sx = Math.hypot(m.elements[0], m.elements[1], m.elements[2]);
        if (sx <= 0) continue;
        sphere.set(pos, sx);
        // Ray.intersectSphere returns the first entry point (or null if miss);
        // gives us the correct distance for ordering nearest-instance-under-ray.
        if (!raycaster.ray.intersectSphere(sphere, hit)) continue;
        intersects.push({
          distance: raycaster.ray.origin.distanceTo(hit),
          point: hit.clone(),
          object: this,
          instanceId: i,
        } as THREE.Intersection);
      }
    };
  }, []);

  useLayoutEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const dummy = new THREE.Object3D();
    for (let i = 0; i < nodes.length; i++) {
      dummy.position.copy(nodes[i].position);
      // Encode hit radius in the matrix scale. The vertex shader ONLY reads
      // instanceMatrix[3].xyz (translation) so this scale is invisible visually,
      // but the raycast override above uses it as the hit-sphere radius.
      const hitR = Math.max(3, nodes[i].size * 0.85);
      dummy.scale.setScalar(hitR);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
    }
    mesh.instanceMatrix.needsUpdate = true;
    mesh.computeBoundingSphere();
    mesh.frustumCulled = false;
    // Install the custom raycast — must happen after ref exists.
    (mesh as any).raycast = raycastCallback;
  }, [nodes, raycastCallback]);

  useFrame((state) => {
    if (!meshRef.current) return;
    (material.uniforms.uTime.value as number) = state.clock.elapsedTime;

    const attr = meshRef.current.geometry.attributes.aFlags as THREE.InstancedBufferAttribute;
    const arr = attr.array as Float32Array;
    let dirty = false;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      let f = 0;
      if (!visibleSet || visibleSet.has(n.id)) f |= 1;
      if (hoveredId === n.id) f |= 2;
      if (selectedId === n.id) f |= 4;
      if (arr[i] !== f) { arr[i] = f; dirty = true; }
    }
    if (dirty) attr.needsUpdate = true;
  });

  const handleMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    if (e.instanceId == null) return;
    onHover(nodes[e.instanceId].id);
  };
  const handleOut = (e: ThreeEvent<PointerEvent>) => { e.stopPropagation(); onHover(null); };
  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    if (e.instanceId == null) return;
    onClick(nodes[e.instanceId].id);
  };

  if (nodes.length === 0) return null;

  return (
    <instancedMesh
      ref={meshRef}
      args={[geometry, material, nodes.length]}
      frustumCulled={false}
      onPointerMove={handleMove}
      onPointerOut={handleOut}
      onClick={handleClick}
    />
  );
}
