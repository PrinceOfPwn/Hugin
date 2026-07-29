// ═════════════════════════════════════════════════════════════════════════════
//  GravityPulse — an expanding, fading ring on the XZ world-plane at an
//  arbitrary origin. Meant to fire when a heavy node is released back into
//  spacetime, communicating that the fabric of the mesh just recovered from
//  a disturbance.
//
//  Physically it's a hand-wave analog to a gravitational wave's far-field
//  amplitude: A(r,t) ∝ 1/r · f(t − r/c). We use a hard ring at r = c·(t−t0)
//  with soft edges from smoothstep, plus a global cosine fade over the pulse
//  lifetime.
//
//  Zero allocations per frame — the shader just reads uTime & uT0.
// ═════════════════════════════════════════════════════════════════════════════

import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  origin: [number, number, number] | null;
  triggerId?: string | number;
  color?: string;
  speed?: number;
  duration?: number;
}

const vert = /* glsl */ `
  varying vec2 vLocal;
  void main() {
    vLocal = position.xz;   // (already rotated to lie on XZ)
    gl_Position = projectionMatrix * viewMatrix * modelMatrix * vec4(position, 1.0);
  }
`;

const frag = /* glsl */ `
  precision highp float;
  varying vec2 vLocal;

  uniform float uTime;
  uniform float uT0;
  uniform float uSpeed;
  uniform float uDuration;
  uniform vec3  uColor;

  void main() {
    float t = uTime - uT0;
    if (t < 0.0 || t > uDuration) discard;

    // Ring radius travels at c = uSpeed. Width w in world units — thin.
    float r    = length(vLocal);
    float edge = t * uSpeed;
    float w    = 6.0 + t * 4.0;   // ring widens slightly as it travels

    // Hard band: smoothstep in both directions gives a soft-edged ring.
    float ring = smoothstep(edge - w, edge, r) * smoothstep(edge + w, edge, r);

    // Global lifetime fade — quartic ease-out.
    float lifeT = t / uDuration;
    float fade  = pow(1.0 - lifeT, 2.0);

    // Radial attenuation so the pulse dims as it expands, mimicking the
    // 1/r falloff of a spherical wave projected onto our sheet.
    float attn = 1.0 / (1.0 + edge * 0.005);

    float a = ring * fade * attn * 0.85;
    if (a < 0.002) discard;
    gl_FragColor = vec4(uColor, a);
  }
`;

export default function GravityPulse({
  origin,
  triggerId,
  color = "#9d7cf4",
  speed = 250,
  duration = 1.8,
}: Props) {
  const meshRef = useRef<THREE.Mesh>(null);
  const activeUntil = useRef<number>(-1);
  const lastTriggerRef = useRef<string | number | undefined>(undefined);

  // Big enough quad that the ring never leaves it before its lifetime ends.
  const quadSize = useMemo(() => Math.max(400, speed * duration * 2 + 100), [speed, duration]);

  const geometry = useMemo(() => {
    const g = new THREE.PlaneGeometry(quadSize, quadSize, 1, 1);
    g.rotateX(-Math.PI / 2);
    return g;
  }, [quadSize]);

  const uniforms = useMemo(() => {
    const c = new THREE.Color(color);
    return {
      uTime:     { value: 0 },
      uT0:       { value: -1 },
      uSpeed:    { value: speed },
      uDuration: { value: duration },
      uColor:    { value: new THREE.Vector3(c.r, c.g, c.b) },
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const material = useMemo(() => new THREE.ShaderMaterial({
    vertexShader: vert,
    fragmentShader: frag,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    side: THREE.DoubleSide,
    uniforms,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [uniforms]);

  // Sync scalar uniforms (no re-alloc).
  useEffect(() => { uniforms.uSpeed.value = speed; }, [speed, uniforms]);
  useEffect(() => { uniforms.uDuration.value = duration; }, [duration, uniforms]);
  useEffect(() => {
    const c = new THREE.Color(color);
    (uniforms.uColor.value as THREE.Vector3).set(c.r, c.g, c.b);
  }, [color, uniforms]);

  // Fire a pulse when triggerId changes and an origin is set.
  useEffect(() => {
    if (triggerId === undefined || triggerId === lastTriggerRef.current) return;
    lastTriggerRef.current = triggerId;
    if (!origin) return;

    // Move the mesh to the pulse origin. Uniform t0 = current elapsed time.
    if (meshRef.current) {
      meshRef.current.position.set(origin[0], origin[1] + 0.1, origin[2]);
    }
    // t0 will be initialized on the next useFrame via `armed` flag below.
    (uniforms as any)._armed = true;
    activeUntil.current = performance.now() / 1000 + duration + 0.05;
  }, [triggerId, origin, duration, uniforms]);

  useFrame(({ clock }) => {
    if (activeUntil.current < 0) return;

    const t = clock.getElapsedTime();
    uniforms.uTime.value = t;

    // First frame after arming — capture t0 so the ring starts from r=0.
    if ((uniforms as any)._armed) {
      uniforms.uT0.value = t;
      (uniforms as any)._armed = false;
    }

    if (performance.now() / 1000 > activeUntil.current) {
      activeUntil.current = -1;
      uniforms.uT0.value = -1;
    }
  });

  if (!origin) return null;
  return (
    <mesh
      ref={meshRef}
      geometry={geometry}
      material={material}
      frustumCulled={false}
      renderOrder={-1}
    />
  );
}
