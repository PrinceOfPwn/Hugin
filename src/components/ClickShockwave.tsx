import { useEffect, useMemo, useRef, useState } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  active: boolean;
  origin: THREE.Vector3 | null;
  originId: string | null;
  originColor: string;
  adjacency: Map<string, string[]>;
  onFadeComplete: () => void;
}

const RING_DURATION = 0.9;
const HOP_DELAY = 0.08;
const FLASH_DURATION = 0.2;
const MAX_HOPS = 12;

const ringVert = /* glsl */`
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const ringFrag = /* glsl */`
  uniform float uOpacity;
  uniform vec3 uColor;
  uniform float uTime;
  varying vec2 vUv;

  float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }

  void main() {
    vec2 c = vUv - 0.5;
    float r = length(c) * 2.0;
    float band = smoothstep(0.85, 0.99, r) - smoothstep(0.99, 1.05, r);
    float angle = atan(c.y, c.x);
    float noise = hash(vec2(floor(angle * 12.0), floor(uTime * 20.0))) * 0.4 + 0.6;
    vec3 col = uColor * (3.0 + noise * 2.0);
    float alpha = band * uOpacity * noise;
    gl_FragColor = vec4(col, alpha);
  }
`;

function computeBfsDepths(originId: string, adj: Map<string, string[]>): Map<string, number> {
  const depths = new Map<string, number>();
  depths.set(originId, 0);
  const queue: string[] = [originId];
  while (queue.length > 0) {
    const id = queue.shift()!;
    const d = depths.get(id)!;
    if (d >= MAX_HOPS) continue;
    for (const nb of adj.get(id) ?? []) {
      if (!depths.has(nb)) {
        depths.set(nb, d + 1);
        queue.push(nb);
      }
    }
  }
  return depths;
}

const flashStore = { depths: null as Map<string, number> | null, startTime: 0 };

export function useEdgeFlashState(
  originId: string | null,
  adjacency: Map<string, string[]>,
  active: boolean,
): Map<string, number> {
  const [, setTick] = useState(0);
  const clockRef = useRef(0);

  useEffect(() => {
    if (active && originId) {
      flashStore.depths = computeBfsDepths(originId, adjacency);
      flashStore.startTime = clockRef.current;
    }
  }, [active, originId, adjacency]);

  useFrame((state) => {
    clockRef.current = state.clock.elapsedTime;
    if (flashStore.depths) setTick(t => (t + 1) % 1024);
  });

  const brightness = useMemo(() => {
    const m = new Map<string, number>();
    if (!flashStore.depths) return m;
    const elapsed = clockRef.current - flashStore.startTime;
    for (const [id, depth] of flashStore.depths) {
      const start = depth * HOP_DELAY;
      const t = elapsed - start;
      if (t >= 0 && t <= FLASH_DURATION) {
        const local = t / FLASH_DURATION;
        m.set(id, Math.sin(local * Math.PI));
      }
    }
    if (elapsed > MAX_HOPS * HOP_DELAY + FLASH_DURATION) flashStore.depths = null;
    return m;
  }, [flashStore.depths, clockRef.current]);

  return brightness;
}

export function ClickShockwave({ active, origin, originColor, onFadeComplete }: Props) {
  const meshRef = useRef<THREE.Mesh>(null);
  const material = useMemo(() => new THREE.ShaderMaterial({
    vertexShader: ringVert,
    fragmentShader: ringFrag,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: {
      uOpacity: { value: 0 },
      uColor: { value: new THREE.Color(originColor) },
      uTime: { value: 0 },
    },
  }), []);

  const startTime = useRef<number | null>(null);
  const { camera } = useThree();
  const completedRef = useRef(false);

  useEffect(() => {
    if (active && origin) {
      startTime.current = null;
      completedRef.current = false;
      material.uniforms.uColor.value.set(originColor);
      if (meshRef.current) meshRef.current.position.copy(origin);
    }
  }, [active, origin, originColor, material]);

  useFrame((state) => {
    material.uniforms.uTime.value = state.clock.elapsedTime;
    if (!active || !origin || !meshRef.current) return;

    if (startTime.current === null) startTime.current = state.clock.elapsedTime;
    const elapsed = state.clock.elapsedTime - startTime.current;
    const t = Math.min(elapsed / RING_DURATION, 1);
    const ease = 1 - Math.pow(1 - t, 3);

    const scale = 1 + ease * 59;
    meshRef.current.scale.setScalar(scale);
    meshRef.current.lookAt(camera.position);

    material.uniforms.uOpacity.value = Math.pow(1 - t, 1.5);

    const totalSettle = Math.max(RING_DURATION, MAX_HOPS * HOP_DELAY + FLASH_DURATION);
    if (elapsed > totalSettle && !completedRef.current) {
      completedRef.current = true;
      onFadeComplete();
    }
  });

  if (!active || !origin) return null;

  return (
    <mesh ref={meshRef} material={material}>
      <ringGeometry args={[0.6, 1.0, 64]} />
    </mesh>
  );
}

export default ClickShockwave;
