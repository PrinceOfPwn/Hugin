import { useEffect, useLayoutEffect, useMemo, useRef } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";
import {
  buildSpinRotation,
  keplerPositionInto,
  type OrbitalElements,
} from "../lib/kepler";

export type NodeDatum = {
  id: string;
  position: THREE.Vector3;
  color: string;
  size: number;          // base size (world units) — actual point size is size * (320/-mv.z)
  kind: string;
  galaxyId: string;
  isAttractor?: boolean;
};

// New Kepler-based orbit descriptor. Client precomputes the 9-element rotation
// matrix once per instance so useFrame can just call keplerPositionInto.
export type OrbitDescriptor = {
  nodeIndex: number;
  parentIndex: number;
  elements: OrbitalElements;
  spinRot: Float32Array;   // 9-element rotation matrix (galaxy spin axis)
};

interface Props {
  nodes: NodeDatum[];
  orbits?: OrbitDescriptor[];
  hoveredId: string | null;
  selectedId: string | null;
  dimmedSet: Set<string> | null;     // when non-null, nodes NOT in set render dim
  onHover?: (id: string | null, screen?: { x: number; y: number }) => void;
  onClick?: (id: string) => void;
  // Gravity Lab positions. The physics worker owns a contiguous array in
  // graph-data order; positionIndices maps this visible subset onto it.
  livePositions?: Float32Array | null;
  positionIndices?: Int32Array | null;
  // When false, the Points object refuses to raycast. Use this when an
  // external hitbox layer is present so we don't get double-fired events.
  interactive?: boolean;
}

// ═════════════════════════════════════════════════════════════════════════════
//  NodeCloud — one THREE.Points draw call for every entity. Vertex shader
//  applies distance-based LOD; fragment shader draws a soft glowing disc.
//  Satellite positions are updated per frame via a shared Kepler solver so
//  the whole universe is in motion.
// ═════════════════════════════════════════════════════════════════════════════

const vert = /* glsl */`
  attribute float aBaseSize;
  attribute float aState;   // 0=idle, 1=hovered, 2=selected, 3=dim
  attribute vec3 aColor;
  varying vec3 vColor;
  varying float vState;
  varying float vLodAlpha;

  const float NEAR_DIST = 250.0;
  const float FAR_DIST  = 1500.0;

  void main() {
    vColor = aColor;
    vState = aState;

    vec4 mv = modelViewMatrix * vec4(position, 1.0);

    // Distance-based LOD: near = full size + alpha, far = smaller + faded.
    float dist = -mv.z;
    float lodT = clamp((dist - NEAR_DIST) / (FAR_DIST - NEAR_DIST), 0.0, 1.0);
    float lodSize  = mix(1.0, 0.45, lodT);
    vLodAlpha      = mix(1.0, 0.5, lodT);

    // Screen-space projection: 320.0 divisor tuned for the default fov=55.
    float scale = aBaseSize * (320.0 / dist) * lodSize;

    // Boost hovered/selected
    if (vState > 1.5 && vState < 2.5) scale *= 1.9;         // selected
    else if (vState > 0.5 && vState < 1.5) scale *= 1.5;    // hovered
    else if (vState > 2.5) scale *= 0.65;                    // dimmed

    gl_PointSize = max(3.0, scale);
    gl_Position = projectionMatrix * mv;
  }
`;

const frag = /* glsl */`
  precision highp float;
  varying vec3 vColor;
  varying float vState;
  varying float vLodAlpha;

  void main() {
    vec2 uv = gl_PointCoord - 0.5;
    float d = length(uv);
    if (d > 0.5) discard;

    float core = smoothstep(0.5, 0.0, d);
    float ring = smoothstep(0.5, 0.35, d) * smoothstep(0.15, 0.35, d);

    vec3 col;
    if (vState > 1.5 && vState < 2.5) {
      // selected — white-hot core, colored halo
      col = mix(vColor, vec3(1.0), 0.7) * core + vColor * ring * 1.8;
    } else if (vState > 0.5 && vState < 1.5) {
      // hovered — bright center, colored ring
      col = mix(vColor, vec3(1.0), 0.5) * core * 1.4 + vColor * ring;
    } else if (vState > 2.5) {
      // dimmed — recede into darkness so the beam+selection dominates.
      col = vColor * core * 0.08;
    } else {
      col = vColor * core * 1.15 + vColor * ring * 0.45;
    }

    float alpha = (vState > 2.5 ? core * 0.08 : core * 0.9) * vLodAlpha;
    gl_FragColor = vec4(col, alpha);
  }
`;

export default function NodeCloud({
  nodes, orbits, hoveredId, selectedId, dimmedSet, onHover, onClick,
  livePositions, positionIndices,
  interactive = true,
}: Props) {
  const pointsRef = useRef<THREE.Points>(null);

  const [geometry, material] = useMemo(() => {
    const n = nodes.length;
    const positions = new Float32Array(n * 3);
    const colors = new Float32Array(n * 3);
    const sizes = new Float32Array(n);
    const states = new Float32Array(n);
    const c = new THREE.Color();

    for (let i = 0; i < n; i++) {
      const d = nodes[i];
      positions[i * 3]     = d.position.x;
      positions[i * 3 + 1] = d.position.y;
      positions[i * 3 + 2] = d.position.z;
      c.set(d.color);
      colors[i * 3]     = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
      sizes[i] = d.size;
      states[i] = 0;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("aColor",   new THREE.BufferAttribute(colors, 3));
    geo.setAttribute("aBaseSize", new THREE.BufferAttribute(sizes, 1));
    geo.setAttribute("aState",   new THREE.BufferAttribute(states, 1));

    const mat = new THREE.ShaderMaterial({
      vertexShader: vert,
      fragmentShader: frag,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    return [geo, mat];
  }, [nodes]);

  // Points' built-in raycast is per-vertex distance-to-ray. Widen threshold so
  // clicks are forgiving; needs to be re-registered when nodes change (the
  // geometry ref is new) — but the fn shape is identical, so the effect body
  // is stable.
  useLayoutEffect(() => {
    const pts = pointsRef.current;
    if (!pts) return;
    pts.frustumCulled = false;
    if (!interactive) {
      // No-op raycast: external hitbox layer owns picking.
      (pts as any).raycast = () => {};
      return;
    }
    (pts as any).raycast = function (this: THREE.Points, raycaster: THREE.Raycaster, intersects: THREE.Intersection[]) {
      const threshold = 12;
      const ray = raycaster.ray;
      const pos = this.geometry.getAttribute("position") as THREE.BufferAttribute;
      const inverseMatrix = new THREE.Matrix4().copy(this.matrixWorld).invert();
      const localRay = ray.clone().applyMatrix4(inverseMatrix);
      const localThreshold = threshold / ((this.scale.x + this.scale.y + this.scale.z) / 3);
      const localThresholdSq = localThreshold * localThreshold;
      const p = new THREE.Vector3();
      for (let i = 0; i < pos.count; i++) {
        p.set(pos.getX(i), pos.getY(i), pos.getZ(i));
        const rayPointDistanceSq = localRay.distanceSqToPoint(p);
        if (rayPointDistanceSq < localThresholdSq) {
          const intersectPoint = new THREE.Vector3();
          localRay.closestPointToPoint(p, intersectPoint);
          intersectPoint.applyMatrix4(this.matrixWorld);
          const distance = raycaster.ray.origin.distanceTo(intersectPoint);
          if (distance < raycaster.near || distance > raycaster.far) continue;
          intersects.push({
            distance,
            distanceToRay: Math.sqrt(rayPointDistanceSq),
            point: intersectPoint,
            index: i,
            face: null,
            object: this,
          } as any);
        }
      }
    };
  }, [geometry]);

  // Update state attribute on hover/select/dim changes.
  useEffect(() => {
    const pts = pointsRef.current;
    if (!pts) return;
    const attr = pts.geometry.getAttribute("aState") as THREE.BufferAttribute;
    const arr = attr.array as Float32Array;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      let s = 0;
      if (dimmedSet && !dimmedSet.has(n.id)) s = 3;
      if (n.id === hoveredId) s = 1;
      if (n.id === selectedId) s = 2;
      arr[i] = s;
    }
    attr.needsUpdate = true;
  }, [hoveredId, selectedId, dimmedSet, nodes]);

  // Per-frame Kepler position update for satellites. Zero allocations — a
  // pre-alloc'd 3-float scratch is reused across all satellites.
  const scratch = useMemo(() => new Float32Array(3), []);

  useFrame(({ clock }) => {
    const pts = pointsRef.current;
    if (!pts) return;
    const attr = pts.geometry.getAttribute("position") as THREE.BufferAttribute;
    const arr = attr.array as Float32Array;
    // Worker simulation takes precedence over analytic satellite motion.
    if (livePositions && positionIndices) {
      for (let i = 0; i < nodes.length; i++) {
        const source = positionIndices[i] * 3;
        const target = i * 3;
        arr[target] = livePositions[source]; arr[target + 1] = livePositions[source + 1]; arr[target + 2] = livePositions[source + 2];
      }
      attr.needsUpdate = true;
      return;
    }
    if (!orbits || orbits.length === 0) return;
    const t = clock.getElapsedTime();
    for (let k = 0; k < orbits.length; k++) {
      const o = orbits[k];
      const pi3 = o.parentIndex * 3;
      const px = arr[pi3], py = arr[pi3 + 1], pz = arr[pi3 + 2];
      keplerPositionInto(scratch, o.elements, px, py, pz, t, o.spinRot);
      const i3 = o.nodeIndex * 3;
      arr[i3]     = scratch[0];
      arr[i3 + 1] = scratch[1];
      arr[i3 + 2] = scratch[2];
    }
    attr.needsUpdate = true;
  });

  const handleMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    if (e.index == null) return;
    const id = nodes[e.index]?.id ?? null;
    onHover?.(id, { x: (e as any).clientX ?? e.nativeEvent?.clientX ?? 0, y: (e as any).clientY ?? e.nativeEvent?.clientY ?? 0 });
  };
  const handleOut = () => onHover?.(null);
  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    if (e.index == null) return;
    const id = nodes[e.index]?.id;
    if (id) onClick?.(id);
  };

  if (nodes.length === 0) return null;

  // Skip handler binding entirely when non-interactive so we don't pay for
  // event bubbling on a dead layer.
  const handlers = interactive
    ? { onPointerMove: handleMove, onPointerOut: handleOut, onClick: handleClick }
    : {};

  return (
    <points
      ref={pointsRef}
      geometry={geometry}
      material={material}
      {...handlers}
    />
  );
}

// Re-export the utility so consumers can also derive spin matrices without
// pulling from ../lib/kepler directly.
export { buildSpinRotation };
