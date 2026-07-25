import React, { useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

export type EdgeData = {
  id: string;
  source: string;
  target: string;
  type: "curated" | "membership" | "similarity" | "evidence";
};

interface Props {
  edges: EdgeData[];
  positions: Map<string, THREE.Vector3>;
  selectedId: string | null;
  visibleSet: Set<string> | null;
}

const vertexShader = `
  attribute float aT;
  attribute float aEdgeType;
  attribute float aEdgeIdHash;
  attribute float aIsSelected;
  
  varying float vT;
  varying float vEdgeType;
  varying float vEdgeIdHash;
  varying float vIsSelected;
  
  void main() {
    vT = aT;
    vEdgeType = aEdgeType;
    vEdgeIdHash = aEdgeIdHash;
    vIsSelected = aIsSelected;
    
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const fragmentShader = `
  uniform float uTime;
  
  varying float vT;
  varying float vEdgeType;
  varying float vEdgeIdHash;
  varying float vIsSelected;
  
  vec3 getColor(float type) {
    if(type < 0.5) return vec3(0.0, 0.94, 1.0);      // curated #00f0ff
    if(type < 1.5) return vec3(0.878, 0.337, 0.992); // membership #e056fd
    if(type < 2.5) return vec3(0.0, 1.0, 0.4);      // similarity #00ff66
    return vec3(1.0, 0.717, 0.011);                 // evidence #ffb703
  }
  
  void main() {
    vec3 color = getColor(vEdgeType);
    
    // Vary speed subtly per edge
    float speed = 0.15 + vEdgeIdHash * 0.25;
    float numPulses = 2.0 + floor(vEdgeIdHash * 2.0); // 2 to 3 pulses in flight
    
    // Selection effects: brighter, faster, thicker (longer pulse band)
    float selMult = 1.0;
    float baseGlow = 0.05;
    float width = 0.1;
    
    if(vIsSelected > 0.5) {
      speed *= 2.5;
      selMult = 2.0;
      baseGlow = 0.2;
      width = 0.2;
    }
    
    // Calculate moving pulse phase
    // Flowing from source (0) to target (1)
    float t_scaled = vT * numPulses + uTime * speed + vEdgeIdHash * 10.0;
    float t_norm = fract(t_scaled);
    
    // Smoothstep bright band (moving comet)
    float d = abs(t_norm - 0.5);
    
    // Core band
    float pulseCore = smoothstep(width, width * 0.5, d);
    
    // Glow halo
    float pulseGlow = smoothstep(0.5, width, d) * 0.3;
    
    float pulseShape = pulseCore + pulseGlow;
    
    vec3 finalColor = color * baseGlow + color * pulseShape * 2.5 * selMult;
    
    float alpha = baseGlow + pulseShape * selMult;
    
    gl_FragColor = vec4(finalColor, alpha);
  }
`;

function hashId(id: string): number {
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = (hash << 5) - hash + id.charCodeAt(i);
    hash |= 0; 
  }
  return Math.abs(hash % 1000) / 1000.0;
}

const EdgeDataStream: React.FC<Props> = ({ edges, positions, selectedId, visibleSet }) => {
  const geometry = useMemo(() => {
    const validEdges = edges.filter(e => 
      positions.has(e.source) && 
      positions.has(e.target) && 
      (!visibleSet || visibleSet.has(e.id))
    );
    
    const count = validEdges.length;
    const positionsArr = new Float32Array(count * 6);
    const tArr = new Float32Array(count * 2);
    const typeArr = new Float32Array(count * 2);
    const hashArr = new Float32Array(count * 2);
    const selectedArr = new Float32Array(count * 2);
    
    const typeMap: Record<EdgeData['type'], number> = {
      "curated": 0,
      "membership": 1,
      "similarity": 2,
      "evidence": 3
    };
    
    for (let i = 0; i < count; i++) {
      const edge = validEdges[i];
      const src = positions.get(edge.source)!;
      const tgt = positions.get(edge.target)!;
      const isSelected = selectedId === edge.id ? 1.0 : 0.0;
      
      const idx6 = i * 6;
      const idx2 = i * 2;
      
      positionsArr[idx6 + 0] = src.x;
      positionsArr[idx6 + 1] = src.y;
      positionsArr[idx6 + 2] = src.z;
      positionsArr[idx6 + 3] = tgt.x;
      positionsArr[idx6 + 4] = tgt.y;
      positionsArr[idx6 + 5] = tgt.z;
      
      tArr[idx2 + 0] = 0.0;
      tArr[idx2 + 1] = 1.0;
      
      const typeVal = typeMap[edge.type] ?? 0;
      typeArr[idx2 + 0] = typeVal;
      typeArr[idx2 + 1] = typeVal;
      
      const hashVal = hashId(edge.id);
      hashArr[idx2 + 0] = hashVal;
      hashArr[idx2 + 1] = hashVal;
      
      selectedArr[idx2 + 0] = isSelected;
      selectedArr[idx2 + 1] = isSelected;
    }
    
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(positionsArr, 3));
    geo.setAttribute('aT', new THREE.BufferAttribute(tArr, 1));
    geo.setAttribute('aEdgeType', new THREE.BufferAttribute(typeArr, 1));
    geo.setAttribute('aEdgeIdHash', new THREE.BufferAttribute(hashArr, 1));
    geo.setAttribute('aIsSelected', new THREE.BufferAttribute(selectedArr, 1));
    
    return geo;
  }, [edges, positions, selectedId, visibleSet]);
  
  const material = useMemo(() => {
    return new THREE.ShaderMaterial({
      vertexShader,
      fragmentShader,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      uniforms: {
        uTime: { value: 0 }
      }
    });
  }, []);
  
  useFrame((state) => {
    material.uniforms.uTime.value = state.clock.elapsedTime;
  });
  
  return (
    <lineSegments geometry={geometry} material={material} />
  );
};

export default EdgeDataStream;
