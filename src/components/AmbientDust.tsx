import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  count?: number;
  radius?: number;
  color?: string;
  opacity?: number;
  size?: number;
}

function AmbientDust({
  count = 15000,
  radius = 1500,
  color = "#e8f4ff",
  opacity = 0.22,
  size = 0.7,
}: Props) {
  const ref = useRef<THREE.Points>(null);

  const [geometry, material] = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const alphaVar = new Float32Array(count);

    for (let i = 0; i < count; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = 2 * Math.PI * u;
      const phi = Math.acos(2 * v - 1);
      const r = radius * Math.cbrt(Math.random());
      pos[i * 3]     = r * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      pos[i * 3 + 2] = r * Math.cos(phi);
      alphaVar[i] = 0.5 + Math.random() * 0.5;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    geo.setAttribute("aAlpha", new THREE.BufferAttribute(alphaVar, 1));

    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        uColor:   { value: new THREE.Color(color) },
        uOpacity: { value: opacity },
        uSize:    { value: size },
        uTime:    { value: 0 },
      },
      vertexShader: /* glsl */`
        attribute float aAlpha;
        uniform float uSize;
        uniform float uTime;
        varying float vAlpha;
        void main() {
          vAlpha = aAlpha * (0.7 + 0.3 * sin(uTime * 0.4 + aAlpha * 40.0));
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_Position = projectionMatrix * mv;
          gl_PointSize = uSize * (300.0 / -mv.z);
        }
      `,
      fragmentShader: /* glsl */`
        uniform vec3 uColor;
        uniform float uOpacity;
        varying float vAlpha;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float a = smoothstep(0.5, 0.0, d) * uOpacity * vAlpha;
          gl_FragColor = vec4(uColor, a);
        }
      `,
    });
    return [geo, mat];
  }, [count, radius, color, opacity, size]);

  useFrame((state) => {
    (material.uniforms.uTime.value as number) = state.clock.elapsedTime;
    if (ref.current) {
      ref.current.rotation.y = state.clock.elapsedTime * 0.005;
      ref.current.rotation.x = state.clock.elapsedTime * 0.002;
    }
  });

  return <points ref={ref} geometry={geometry} material={material} />;
}

export default AmbientDust;
