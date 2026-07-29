import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export type HeavyNode = {
  id: string;
  mass: number;
  position: THREE.Vector3;
  color?: string;
};

interface Props {
  heavyNodes: HeavyNode[];
  /** how large the halo extends around each heavy node (world units) */
  radiusScale?: number;
  intensity?: number;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SpacetimeWarp — additive-blended radial halos parented to the heaviest
//  nodes in the scene. Cheap: one billboard quad per node, no post-processing
//  pass, no per-frame allocations. The halo is a soft radial gradient that
//  fakes gravitational lensing / "warp" atmospherics.
// ═════════════════════════════════════════════════════════════════════════════

const vert = /* glsl */`
  varying vec2 vUv;
  void main() {
    vUv = uv;
    // Billboard: kill rotation from the modelView matrix, keep translation.
    vec4 mvPos = modelViewMatrix * vec4(0.0, 0.0, 0.0, 1.0);
    mvPos.xy += position.xy;
    gl_Position = projectionMatrix * mvPos;
  }
`;

const frag = /* glsl */`
  precision highp float;
  varying vec2 vUv;
  uniform vec3 uColor;
  uniform float uIntensity;

  void main() {
    vec2 p = vUv - 0.5;
    float d = length(p) * 2.0;   // 0 at center, 1 at edge
    if (d > 1.0) discard;
    // Inverse-square-ish falloff; a hint of a bright core to sell mass.
    float halo = pow(1.0 - d, 2.5);
    float core = smoothstep(0.35, 0.0, d) * 0.4;
    float a = (halo * 0.55 + core) * uIntensity;
    gl_FragColor = vec4(uColor, a);
  }
`;

function HaloSprite({ node, radius, intensity }: {
  node: HeavyNode;
  radius: number;
  intensity: number;
}) {
  const meshRef = useRef<THREE.Mesh>(null);

  const material = useMemo(() => {
    const c = new THREE.Color(node.color || "#7fbfff");
    return new THREE.ShaderMaterial({
      vertexShader: vert,
      fragmentShader: frag,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        uColor: { value: new THREE.Vector3(c.r, c.g, c.b) },
        uIntensity: { value: intensity },
      },
    });
  }, [node.color, intensity]);

  const geometry = useMemo(() => new THREE.PlaneGeometry(radius * 2, radius * 2), [radius]);

  useFrame(({ camera }) => {
    if (!meshRef.current) return;
    // Cheap billboarding — face the camera every frame.
    meshRef.current.quaternion.copy(camera.quaternion);
  });

  return (
    <mesh
      ref={meshRef}
      geometry={geometry}
      material={material}
      position={[node.position.x, node.position.y, node.position.z]}
      renderOrder={-1}
    />
  );
}

export default function SpacetimeWarp({
  heavyNodes,
  radiusScale = 22,
  intensity = 0.35,
}: Props) {
  // Radius scales with mass so heavier stars carry visibly larger halos.
  return (
    <group>
      {heavyNodes.map((n) => (
        <HaloSprite
          key={n.id}
          node={n}
          radius={radiusScale * Math.max(1, n.mass)}
          intensity={intensity}
        />
      ))}
    </group>
  );
}
