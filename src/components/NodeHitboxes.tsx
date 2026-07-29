import { useLayoutEffect, useMemo, useRef } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";
import { keplerPositionInto } from "../lib/kepler";
import type { OrbitDescriptor } from "./NodeCloud";

export type HitboxNode = {
  id: string;
  position: THREE.Vector3;
  size: number;
};

interface Props {
  nodes: HitboxNode[];
  // Orbit descriptors — used so satellite hitboxes track their Kepler
  // positions in lock-step with NodeCloud. Same shape/indexing.
  orbits?: OrbitDescriptor[];
  onHover: (id: string | null, screen?: { x: number; y: number }) => void;
  onSelect: (id: string) => void;
  onDoubleClick?: (id: string) => void;
}

// ═════════════════════════════════════════════════════════════════════════════
//  NodeHitboxes — invisible instanced spheres, one per node, sized generously
//  so clicks land easily even for tiny nodes. Renders nothing visible; it
//  only exists so that R3F's raycaster has real geometry to intersect.
//
//  We mirror NodeCloud's Kepler solve so orbiting satellites' hitboxes track
//  their visual position. All buffers are pre-allocated; useFrame does zero
//  allocations.
// ═════════════════════════════════════════════════════════════════════════════

const HITBOX_SCALE = 2.5;

export default function NodeHitboxes({
  nodes, orbits, onHover, onSelect, onDoubleClick,
}: Props) {
  const meshRef = useRef<THREE.InstancedMesh>(null);

  // Static, per-instance backing arrays (positions live here as source-of-
  // truth; satellite positions get overwritten each frame).
  const posBuf = useMemo(() => {
    const buf = new Float32Array(nodes.length * 3);
    for (let i = 0; i < nodes.length; i++) {
      buf[i * 3]     = nodes[i].position.x;
      buf[i * 3 + 1] = nodes[i].position.y;
      buf[i * 3 + 2] = nodes[i].position.z;
    }
    return buf;
  }, [nodes]);

  const sizes = useMemo(() => {
    const buf = new Float32Array(nodes.length);
    for (let i = 0; i < nodes.length; i++) buf[i] = nodes[i].size * HITBOX_SCALE;
    return buf;
  }, [nodes]);

  const scratchMatrix = useMemo(() => new THREE.Matrix4(), []);
  const scratchScale = useMemo(() => new THREE.Vector3(), []);
  const scratchPos = useMemo(() => new THREE.Vector3(), []);
  const scratchQuat = useMemo(() => new THREE.Quaternion(), []);
  const scratchKepler = useMemo(() => new Float32Array(3), []);

  // Bake initial instance matrices.
  useLayoutEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    for (let i = 0; i < nodes.length; i++) {
      scratchPos.set(posBuf[i * 3], posBuf[i * 3 + 1], posBuf[i * 3 + 2]);
      scratchScale.setScalar(sizes[i]);
      scratchMatrix.compose(scratchPos, scratchQuat, scratchScale);
      mesh.setMatrixAt(i, scratchMatrix);
    }
    mesh.count = nodes.length;
    mesh.instanceMatrix.needsUpdate = true;
    mesh.frustumCulled = false;
  }, [nodes, posBuf, sizes, scratchMatrix, scratchPos, scratchQuat, scratchScale]);

  // Per-frame update — mirror NodeCloud's Kepler solve for satellites.
  useFrame(({ clock }) => {
    if (!orbits || orbits.length === 0) return;
    const mesh = meshRef.current;
    if (!mesh) return;
    const t = clock.getElapsedTime();
    for (let k = 0; k < orbits.length; k++) {
      const o = orbits[k];
      const pi3 = o.parentIndex * 3;
      const px = posBuf[pi3], py = posBuf[pi3 + 1], pz = posBuf[pi3 + 2];
      keplerPositionInto(scratchKepler, o.elements, px, py, pz, t, o.spinRot);
      const i3 = o.nodeIndex * 3;
      posBuf[i3]     = scratchKepler[0];
      posBuf[i3 + 1] = scratchKepler[1];
      posBuf[i3 + 2] = scratchKepler[2];
      scratchPos.set(scratchKepler[0], scratchKepler[1], scratchKepler[2]);
      scratchScale.setScalar(sizes[o.nodeIndex]);
      scratchMatrix.compose(scratchPos, scratchQuat, scratchScale);
      mesh.setMatrixAt(o.nodeIndex, scratchMatrix);
    }
    mesh.instanceMatrix.needsUpdate = true;
  });

  const handleMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    const idx = e.instanceId;
    if (idx == null) return;
    const id = nodes[idx]?.id ?? null;
    onHover(id, {
      x: (e as any).clientX ?? e.nativeEvent?.clientX ?? 0,
      y: (e as any).clientY ?? e.nativeEvent?.clientY ?? 0,
    });
  };
  const handleOut = () => onHover(null);
  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    const idx = e.instanceId;
    if (idx == null) return;
    const id = nodes[idx]?.id;
    if (id) onSelect(id);
  };
  const handleDbl = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    const idx = e.instanceId;
    if (idx == null) return;
    const id = nodes[idx]?.id;
    if (id) onDoubleClick?.(id);
  };

  if (nodes.length === 0) return null;

  return (
    <instancedMesh
      key={nodes.length /* force fresh instanceMatrix buffer when count changes */}
      ref={meshRef}
      args={[undefined as any, undefined as any, nodes.length]}
      renderOrder={-1000}
      onPointerMove={handleMove}
      onPointerOut={handleOut}
      onClick={handleClick}
      onDoubleClick={handleDbl}
    >
      <sphereGeometry args={[1, 8, 6]} />
      <meshBasicMaterial
        transparent
        opacity={0}
        depthWrite={false}
        depthTest={false}
        colorWrite={false}
      />
    </instancedMesh>
  );
}
