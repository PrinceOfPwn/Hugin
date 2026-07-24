import * as THREE from 'three';
import { useFrame, useThree } from '@react-three/fiber';
import { useEffect, useLayoutEffect, useRef } from 'react';

export interface WarpJumpProps {
  from: THREE.Vector3;
  to: THREE.Vector3;
  targetColor: string;
  active: boolean;
  duration?: number;
  onComplete: () => void;
}

// Hook to expose the chromatic aberration amount to a companion post-processing pass
const chromaticAmount = { current: 0 };
export function useChromaticAmount() {
  return chromaticAmount;
}

const easeInQuint = (t: number) => t * t * t * t * t;
const easeOutQuint = (t: number) => 1 - Math.pow(1 - t, 5);

const vertexShader = `
  attribute vec3 aOffset;
  attribute float aSpeed;
  attribute float aScale;
  
  uniform float uTime;
  uniform float uStretch;
  uniform float uIntensity;
  uniform float uOpacity;
  uniform vec3 uColor;
  
  varying vec2 vUv;
  varying float vAlpha;
  
  void main() {
    vUv = uv;
    
    // Base plane is XY. We swap Y and Z to align the plane's length along the camera's forward (Z) axis.
    vec3 pos = vec3(position.x, position.z, position.y);
    
    // Stretch and thin the streak
    pos.z *= uStretch * aScale * uIntensity;
    pos.x *= 0.05;
    
    // Procedural infinite movement
    vec3 instPos = aOffset;
    float speedFactor = (1.0 + uIntensity * 50.0) * aSpeed;
    instPos.z = mod(instPos.z - uTime * speedFactor, 100.0) - 50.0;
    
    vec3 finalPos = pos + instPos;
    
    // Warp tunnel curvature
    vec2 tunnelDir = normalize(finalPos.xy + 0.0001);
    float pull = (1.0 - abs(finalPos.z / 50.0)) * 2.0;
    finalPos.xy -= tunnelDir * pull;
    
    vec4 mvPosition = modelViewMatrix * vec4(finalPos, 1.0);
    gl_Position = projectionMatrix * mvPosition;
    
    float dist = length(mvPosition.xyz);
    vAlpha = smoothstep(60.0, 10.0, dist) * smoothstep(0.0, 2.0, dist);
  }
`;

const fragmentShader = `
  varying vec2 vUv;
  varying float vAlpha;
  
  uniform vec3 uColor;
  uniform float uOpacity;
  
  void main() {
    // Center of the streak is vUv.y = 0.5
    float d = abs(vUv.y - 0.5) * 2.0; 
    float alpha = pow(1.0 - d, 2.0);
    vec3 col = mix(uColor, vec3(1.0), 1.0 - d);
    gl_FragColor = vec4(col, alpha * vAlpha * uOpacity);
  }
`;

const WarpJump: React.FC<WarpJumpProps> = ({
  from,
  to,
  targetColor,
  active,
  duration = 2.4,
  onComplete,
}) => {
  const { camera, clock } = useThree();
  
  const groupRef = useRef<THREE.Group>(null!);
  const meshRef = useRef<THREE.InstancedMesh>(null!);
  const materialRef = useRef<THREE.ShaderMaterial>(null!);
  const flashRef = useRef<THREE.Mesh>(null!);
  const shockRef = useRef<THREE.Mesh>(null!);
  const pulseRef = useRef<THREE.Mesh>(null!);
  
  const startTime = useRef<number>(0);
  const isWarping = useRef<boolean>(false);
  
  const startFrom = useRef<THREE.Vector3>(new THREE.Vector3());
  const startTo = useRef<THREE.Vector3>(new THREE.Vector3());
  const dir = useRef<THREE.Vector3>(new THREE.Vector3());
  const targetPos = useRef<THREE.Vector3>(new THREE.Vector3());

  useEffect(() => {
    if (active) {
      startTime.current = clock.getElapsedTime();
      isWarping.current = true;
      
      startFrom.current.copy(from);
      startTo.current.copy(to);
      
      dir.current.subVectors(to, from);
      if (dir.current.lengthSq() < 0.0001) {
        dir.current.set(0, 0, 1);
      }
      dir.current.normalize();
      
      // Offset camera back by 150 units to view the galaxy upon arrival
      targetPos.current.copy(to).sub(dir.current.clone().multiplyScalar(150));
      
      if (shockRef.current) shockRef.current.visible = false;
      if (pulseRef.current) pulseRef.current.visible = false;
    }
  }, [active, from, to, clock]);

  useEffect(() => {
    if (materialRef.current) {
      materialRef.current.uniforms.uColor.value.set(targetColor);
    }
  }, [targetColor]);

  useLayoutEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    
    const count = 400;
    const offsets = new Float32Array(count * 3);
    const speeds = new Float32Array(count);
    const scales = new Float32Array(count);
    const dummy = new THREE.Object3D();
    
    for (let i = 0; i < count; i++) {
      // Uniform distribution in a cylinder around the Z axis
      const r = 5 + Math.random() * 35;
      const theta = Math.random() * Math.PI * 2;
      offsets[i * 3] = Math.cos(theta) * r;
      offsets[i * 3 + 1] = Math.sin(theta) * r;
      offsets[i * 3 + 2] = (Math.random() - 0.5) * 100;
      
      speeds[i] = 0.5 + Math.random() * 1.5;
      scales[i] = 0.5 + Math.random() * 1.5;
      
      // Set instance matrix to identity
      dummy.position.set(0, 0, 0);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
    }
    
    mesh.geometry.setAttribute('aOffset', new THREE.InstancedBufferAttribute(offsets, 3));
    mesh.geometry.setAttribute('aSpeed', new THREE.InstancedBufferAttribute(speeds, 1));
    mesh.geometry.setAttribute('aScale', new THREE.InstancedBufferAttribute(scales, 1));
    mesh.instanceMatrix.needsUpdate = true;
  }, []);

  useFrame(() => {
    if (!isWarping.current) return;
    
    const elapsed = clock.getElapsedTime() - startTime.current;
    const T = duration;
    const t = Math.min(elapsed / T, 1.0);
    
    let fov = 75;
    let chroma = 0;
    let stretch = 0;
    let streakOpacity = 1.0;
    let flashIntensity = 0;
    let camProgress = 0;
    let roll = 0;
    
    // Phase 1: Charge-up (0 - 0.166)
    if (t < 0.166) {
      const lt = t / 0.166;
      const e = easeInQuint(lt);
      fov = THREE.MathUtils.lerp(75, 60, e);
      chroma = 0.4 * e;
      stretch = 2.0 * e;
      camProgress = 0.01 * e;
      streakOpacity = 1.0;
      
      if (pulseRef.current) {
        pulseRef.current.visible = true;
        pulseRef.current.position.copy(startTo.current);
        pulseRef.current.lookAt(camera.position);
        const s = THREE.MathUtils.lerp(40, 1, e);
        pulseRef.current.scale.setScalar(s);
        (pulseRef.current.material as THREE.Material).opacity = 1.0 - lt;
      }
    } else {
      if (pulseRef.current) pulseRef.current.visible = false;
      
      // Phase 2: Warp streaks (0.166 - 0.666)
      if (t < 0.666) {
        const lt = (t - 0.166) / 0.5;
        fov = THREE.MathUtils.lerp(60, 65, lt);
        chroma = THREE.MathUtils.lerp(0.4, 0.8, lt);
        stretch = THREE.MathUtils.lerp(2.0, 30.0, lt);
        camProgress = 0.01 + 0.8 * lt;
        streakOpacity = 1.0;
        roll = Math.sin(elapsed * 30) * 0.05;
      } 
      // Phase 3: Deceleration (0.666 - 0.875)
      else if (t < 0.875) {
        const lt = (t - 0.666) / 0.209;
        const e = easeOutQuint(lt);
        fov = THREE.MathUtils.lerp(65, 90, e);
        chroma = THREE.MathUtils.lerp(0.8, 0.2, e);
        stretch = THREE.MathUtils.lerp(30.0, 0.0, e);
        camProgress = 0.81 + 0.19 * e;
        streakOpacity = 1.0 - 0.5 * e;
        flashIntensity = Math.sin(lt * Math.PI);
        roll = Math.sin(elapsed * 30) * 0.05 * (1 - lt);
      } 
      // Phase 4: Arrival (0.875 - 1.0)
      else {
        const lt = (t - 0.875) / 0.125;
        fov = THREE.MathUtils.lerp(90, 75, lt);
        chroma = THREE.MathUtils.lerp(0.2, 0.0, lt);
        stretch = 0.0;
        camProgress = 1.0;
        streakOpacity = 0.5 - 0.5 * lt;
        
        if (shockRef.current) {
          shockRef.current.visible = true;
          shockRef.current.position.copy(startTo.current);
          shockRef.current.lookAt(camera.position);
          shockRef.current.scale.setScalar(1 + lt * 40);
          (shockRef.current.material as THREE.Material).opacity = 1.0 - lt;
        }
      }
    }
    
    // Camera Choreography
    camera.position.lerpVectors(startFrom.current, targetPos.current, camProgress);
    camera.lookAt(startTo.current);
    (camera as THREE.PerspectiveCamera).fov = fov;
    camera.updateProjectionMatrix();
    camera.rotateZ(roll);
    
    // Sync group to camera to keep streaks relative
    if (groupRef.current) {
      groupRef.current.position.copy(camera.position);
      groupRef.current.quaternion.copy(camera.quaternion);
    }
    
    // Update Streak Material
    if (materialRef.current) {
      materialRef.current.uniforms.uTime.value = elapsed;
      materialRef.current.uniforms.uStretch.value = stretch;
      materialRef.current.uniforms.uIntensity.value = stretch; // Link intensity to stretch
      materialRef.current.uniforms.uOpacity.value = Math.max(0, streakOpacity);
      materialRef.current.uniforms.uColor.value.set(targetColor);
    }
    
    // Update Flash
    if (flashRef.current) {
      (flashRef.current.material as THREE.Material).opacity = flashIntensity;
    }
    
    // Update Chromatic Aberration
    chromaticAmount.current = chroma;
    
    if (t >= 1.0) {
      isWarping.current = false;
      chromaticAmount.current = 0;
      if (onComplete) onComplete();
    }
  });

  return (
    <>
      <group ref={groupRef}>
        <instancedMesh 
          ref={meshRef} 
          args={[undefined, undefined, 400]} 
          frustumCulled={false}
        >
          <planeGeometry args={[1, 1]} />
          <shaderMaterial
            ref={materialRef}
            transparent
            depthWrite={false}
            blending={THREE.AdditiveBlending}
            vertexShader={vertexShader}
            fragmentShader={fragmentShader}
            uniforms={{
              uTime: { value: 0 },
              uStretch: { value: 0 },
              uIntensity: { value: 0 },
              uOpacity: { value: 0 },
              uColor: { value: new THREE.Color(targetColor) }
            }}
          />
        </instancedMesh>
        
        {/* Screen Flash */}
        <mesh ref={flashRef} position={[0, 0, -5]}>
          <planeGeometry args={[2, 2]} />
          <meshBasicMaterial 
            color="white" 
            transparent 
            opacity={0} 
            depthWrite={false} 
            blending={THREE.AdditiveBlending} 
          />
        </mesh>
      </group>
      
      {/* Target Pulse Ring (Phase 1) */}
      <mesh ref={pulseRef} visible={false}>
        <ringGeometry args={[0.8, 1, 64]} />
        <meshBasicMaterial 
          color="white" 
          transparent 
          opacity={0} 
          depthWrite={false} 
          side={THREE.DoubleSide} 
          blending={THREE.AdditiveBlending} 
        />
      </mesh>
      
      {/* Arrival Shockwave (Phase 4) */}
      <mesh ref={shockRef} visible={false}>
        <ringGeometry args={[0.8, 1, 64]} />
        <meshBasicMaterial 
          color={targetColor} 
          transparent 
          opacity={0} 
          depthWrite={false} 
          side={THREE.DoubleSide} 
          blending={THREE.AdditiveBlending} 
        />
      </mesh>
    </>
  );
};

export default WarpJump;
