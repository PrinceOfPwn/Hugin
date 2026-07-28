import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export type NebulaGalaxy = {
  id: string;
  color: string;
  centroid: { x: number; y: number; z: number };
  totalMass: number;
};

interface Props {
  galaxies: NebulaGalaxy[];
  intensity?: number;
}

// ═════════════════════════════════════════════════════════════════════════════
//  NebulaField — one soft, additive, camera-facing quad per galaxy. The quad
//  samples a radial gradient in the fragment shader (no texture upload, no
//  data-URL, one draw call per galaxy). Alpha ≈0.15, blending additive, size
//  scales with log(totalMass). Cheap; each frame just copies the camera
//  quaternion into each mesh.
// ═════════════════════════════════════════════════════════════════════════════

const vert = /* glsl */`
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const frag = /* glsl */`
  precision highp float;
  varying vec2 vUv;
  uniform vec3 uColor;
  uniform float uIntensity;

  void main() {
    vec2 p = vUv - 0.5;
    float d = length(p) * 2.0;
    if (d > 1.0) discard;
    // Soft radial gradient: bright core, long tail.
    float halo = pow(1.0 - d, 2.2);
    float core = smoothstep(0.4, 0.0, d) * 0.55;
    float a = (halo * 0.55 + core) * uIntensity;
    gl_FragColor = vec4(uColor, a);
  }
`;

function NebulaSprite({ galaxy, intensity }: { galaxy: NebulaGalaxy; intensity: number }) {
  const meshRef = useRef<THREE.Mesh>(null);

  const size = 500 + 200 * Math.log(Math.max(1, galaxy.totalMass));

  const material = useMemo(() => {
    const c = new THREE.Color(galaxy.color);
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
  }, [galaxy.color, intensity]);

  const geometry = useMemo(() => new THREE.PlaneGeometry(size, size), [size]);

  useFrame(({ camera }) => {
    if (!meshRef.current) return;
    meshRef.current.quaternion.copy(camera.quaternion);
  });

  return (
    <mesh
      ref={meshRef}
      geometry={geometry}
      material={material}
      position={[galaxy.centroid.x, galaxy.centroid.y, galaxy.centroid.z]}
      renderOrder={-2}
    />
  );
}

export default function NebulaField({ galaxies, intensity = 0.15 }: Props) {
  return (
    <group>
      {galaxies.map((g) => (
        <NebulaSprite key={g.id} galaxy={g} intensity={intensity} />
      ))}
    </group>
  );
}
