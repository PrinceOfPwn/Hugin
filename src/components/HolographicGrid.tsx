import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  y?: number;
  size?: number;
  divisions?: number;
  color?: string;
  pulseSpeed?: number;
}

const vert = /* glsl */`
  varying vec2 vUv;
  varying vec3 vWorldPos;
  void main() {
    vUv = uv;
    vec4 wp = modelMatrix * vec4(position, 1.0);
    vWorldPos = wp.xyz;
    gl_Position = projectionMatrix * viewMatrix * wp;
  }
`;

const frag = /* glsl */`
  uniform float uTime;
  uniform vec3 uColor;
  uniform float uSize;
  uniform float uDivisions;
  uniform float uPulseSpeed;
  varying vec2 vUv;
  varying vec3 vWorldPos;

  float gridLine(float coord, float freq, float thickness) {
    float g = abs(fract(coord * freq - 0.5) - 0.5) / fwidth(coord * freq);
    return 1.0 - min(g / thickness, 1.0);
  }

  void main() {
    float cellFreq = uDivisions / uSize;
    float minor = max(gridLine(vWorldPos.x, cellFreq, 1.2),
                      gridLine(vWorldPos.z, cellFreq, 1.2));
    float major = max(gridLine(vWorldPos.x, cellFreq / 10.0, 1.6),
                      gridLine(vWorldPos.z, cellFreq / 10.0, 1.6));

    float dist = length(vWorldPos.xz);
    float pulse = sin(dist * 0.02 - uTime * uPulseSpeed) * 0.5 + 0.5;
    pulse = pow(pulse, 3.0);

    float fade = smoothstep(uSize * 0.5, 0.0, dist);

    float minorA = minor * 0.15 * (1.0 + pulse * 0.6);
    float majorA = major * 0.5 * (1.0 + pulse * 0.9);
    float a = (minorA + majorA) * fade;

    if (a < 0.01) discard;
    vec3 col = uColor * (1.0 + pulse * 2.0);
    gl_FragColor = vec4(col, a);
  }
`;

function HolographicGrid({
  y = -400,
  size = 3000,
  divisions = 300,
  color = "#00f0ff",
  pulseSpeed = 0.8,
}: Props) {
  const matRef = useRef<THREE.ShaderMaterial>(null);
  const material = useMemo(() => new THREE.ShaderMaterial({
    vertexShader: vert,
    fragmentShader: frag,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    side: THREE.DoubleSide,
    uniforms: {
      uTime: { value: 0 },
      uColor: { value: new THREE.Color(color) },
      uSize: { value: size },
      uDivisions: { value: divisions },
      uPulseSpeed: { value: pulseSpeed },
    },
  }), [color, size, divisions, pulseSpeed]);

  useFrame((state) => {
    material.uniforms.uTime.value = state.clock.elapsedTime;
  });

  return (
    <mesh position={[0, y, 0]} rotation={[-Math.PI / 2, 0, 0]} material={material}>
      <planeGeometry args={[size, size, 1, 1]} />
    </mesh>
  );
}

export default HolographicGrid;
