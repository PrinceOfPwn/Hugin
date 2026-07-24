import React, { useLayoutEffect, useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import type { ThreeEvent } from '@react-three/fiber';
import * as THREE from 'three';

type NodeData = {
  id: string;
  position: THREE.Vector3;
  color: string;
  size: number;
};

interface Props {
  nodes: NodeData[];
  hoveredId: string | null;
  selectedId: string | null;
  visibleSet: Set<string> | null;
  onHover: (id: string | null) => void;
  onClick: (id: string) => void;
}

const vertexShader = /* glsl */ `
  uniform float uTime;

  attribute vec3 aColor;
  attribute float aSize;
  attribute float aPhase;
  attribute float aFlags;

  varying vec2 vUv;
  varying vec3 vColor;
  varying float vFlags;

  void main() {
    vUv = uv - 0.5;
    vColor = aColor;
    vFlags = aFlags;

    float f = aFlags;
    bool isVisible = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isHovered = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isSelected = mod(f, 2.0) > 0.5;

    if (!isVisible) {
      gl_Position = vec4(0.0, 0.0, -10000.0, 1.0);
      return;
    }

    vec3 instancePosition = instanceMatrix[3].xyz;

    // Extract camera right and up vectors from viewMatrix
    vec3 cameraRight = viewMatrix[0].xyz;
    vec3 cameraUp = viewMatrix[1].xyz;

    // Breathing scale
    float breath = sin(uTime * 0.6 + aPhase) * 0.15 + 1.0;
    float currentSize = aSize * breath;

    if (isHovered) {
      currentSize *= 1.8;
    }

    // Billboard offset
    vec3 vertexOffset = (cameraRight * vUv.x + cameraUp * vUv.y) * currentSize;
    vec3 worldPosition = instancePosition + vertexOffset;

    vec4 mvPosition = viewMatrix * vec4(worldPosition, 1.0);
    gl_Position = projectionMatrix * mvPosition;
  }
`;

const fragmentShader = /* glsl */ `
  precision highp float;

  uniform float uTime;

  varying vec2 vUv;
  varying vec3 vColor;
  varying float vFlags;

  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
  }

  float noise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    float a = hash(i);
    float b = hash(i + vec2(1.0, 0.0));
    float c = hash(i + vec2(0.0, 1.0));
    float d = hash(i + vec2(1.0, 1.0));
    return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
  }

  void main() {
    float f = vFlags;
    bool isVisible = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isHovered = mod(f, 2.0) > 0.5; f = floor(f / 2.0);
    bool isSelected = mod(f, 2.0) > 0.5;

    if (!isVisible) discard;

    vec2 uv = vUv * 2.0; // -1 to 1
    float dist = length(uv);

    // Base radial gradients
    float core = smoothstep(0.2, 0.0, dist);
    float ring = smoothstep(0.45, 0.2, dist);
    
    // Corona falloff (wider when hovered)
    float coronaFalloff = isHovered ? 1.5 : 2.5;
    float corona = exp(-dist * coronaFalloff);

    // Animated noise/sparkle on the halo
    float n = noise(uv * 4.0 + vec2(uTime * 0.2, uTime * 0.15));
    corona *= 0.7 + n * 0.5;

    float sparkle = noise(uv * 8.0 + uTime * 2.0) * smoothstep(1.0, 0.4, dist);
    corona += sparkle * 0.2;

    // HDR colors for intense bloom
    vec3 coreColor = vec3(1.0, 0.98, 0.9) * 8.0;
    vec3 midColor = vColor * 4.0;
    vec3 outerColor = vColor * 1.5;

    vec3 color = vec3(0.0);
    color += coreColor * core;
    color += midColor * ring;
    color += outerColor * corona;

    if (isHovered) {
      float hoverCore = smoothstep(0.3, 0.0, dist);
      color += coreColor * hoverCore * 0.5;
    }

    if (isSelected) {
      float t = mod(uTime, 2.0) / 2.0; // 0 to 1 every 2s
      float ringDist = t * 1.2 + 0.2;
      float ringThickness = 0.05;
      float ringPulse = smoothstep(ringThickness, 0.0, abs(dist - ringDist)) * (1.0 - t);
      color += outerColor * ringPulse * 4.0;
    }

    float alpha = clamp(max(max(color.r, color.g), color.b), 0.0, 1.0);
    gl_FragColor = vec4(color, alpha);
  }
`;

export default function StarNodes({ nodes, hoveredId, selectedId, visibleSet, onHover, onClick }: Props) {
  const meshRef = useRef<THREE.InstancedMesh>(null);
  const matRef = useRef<THREE.ShaderMaterial>(null);

  const geometry = useMemo(() => {
    const geo = new THREE.PlaneGeometry(1, 1);
    const count = nodes.length;

    const aColor = new Float32Array(count * 3);
    const aSize = new Float32Array(count);
    const aPhase = new Float32Array(count);
    const aFlags = new Float32Array(count); // 1=visible, 2=hovered, 4=selected

    for (let i = 0; i < count; i++) {
      const node = nodes[i];
      const color = new THREE.Color(node.color);
      aColor[i * 3] = color.r;
      aColor[i * 3 + 1] = color.g;
      aColor[i * 3 + 2] = color.b;
      aSize[i] = node.size;
      aPhase[i] = Math.random() * Math.PI * 2;
      aFlags[i] = 1; // initially visible
    }

    geo.setAttribute('aColor', new THREE.InstancedBufferAttribute(aColor, 3));
    geo.setAttribute('aSize', new THREE.InstancedBufferAttribute(aSize, 1));
    geo.setAttribute('aPhase', new THREE.InstancedBufferAttribute(aPhase, 1));
    geo.setAttribute('aFlags', new THREE.InstancedBufferAttribute(aFlags, 1));

    return geo;
  }, [nodes]);

  const material = useMemo(() => {
    return new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 }
      },
      vertexShader,
      fragmentShader,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
  }, []);

  useLayoutEffect(() => {
    if (!meshRef.current) return;
    const dummy = new THREE.Object3D();
    for (let i = 0; i < nodes.length; i++) {
      dummy.position.copy(nodes[i].position);
      dummy.updateMatrix();
      meshRef.current.setMatrixAt(i, dummy.matrix);
    }
    meshRef.current.instanceMatrix.needsUpdate = true;
  }, [nodes]);

  useFrame((state) => {
    if (!matRef.current || !meshRef.current) return;

    matRef.current.uniforms.uTime.value = state.clock.elapsedTime;

    const flagsAttr = meshRef.current.geometry.attributes.aFlags as THREE.InstancedBufferAttribute;
    const arr = flagsAttr.array as Float32Array;
    let dirty = false;

    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      let flags = 0;
      if (visibleSet ? visibleSet.has(node.id) : true) flags |= 1;
      if (hoveredId === node.id) flags |= 2;
      if (selectedId === node.id) flags |= 4;

      if (arr[i] !== flags) {
        arr[i] = flags;
        dirty = true;
      }
    }
    
    if (dirty) flagsAttr.needsUpdate = true;
  });

  const handlePointerMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    if (e.instanceId === null || e.instanceId === undefined) return;
    onHover(nodes[e.instanceId].id);
  };

  const handlePointerOut = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    onHover(null);
  };

  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    if (e.instanceId === null || e.instanceId === undefined) return;
    onClick(nodes[e.instanceId].id);
  };

  return (
    <instancedMesh
      ref={meshRef}
      args={[geometry, material, nodes.length]}
      onPointerMove={handlePointerMove}
      onPointerOut={handlePointerOut}
      onClick={handleClick}
    >
      <primitive ref={matRef} object={material} attach="material" />
    </instancedMesh>
  );
}
