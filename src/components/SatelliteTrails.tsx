import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import {
  buildSpinRotation,
  keplerPositionInto,
  type OrbitalElements,
} from "../lib/kepler";

export type TrailOrbit = {
  id: string;
  parentPos: [number, number, number];
  elements: OrbitalElements;
  spinAxis: { x: number; y: number; z: number };
  color: string;
};

interface Props {
  orbits: TrailOrbit[];
  trailLength?: number;   // N frames of tail per satellite
  intensity?: number;     // overall alpha multiplier
}

// ═════════════════════════════════════════════════════════════════════════════
//  SatelliteTrails — one LineSegments per frame, per-vertex color with alpha
//  fading from 1.0 at the head to 0.0 at the tail. Position buffer is a fixed
//  rolling ring buffer (N samples × M satellites × 3 floats). No allocations
//  inside useFrame — everything reused.
//
//  The trail draws segments (i, i+1) for the ring in write order, which means
//  every step we advance the write cursor by 1 and just rewrite one vertex.
//  The line will loop-connect head↔tail across the ring boundary — that
//  single stray segment is hidden by giving it alpha 0 via vertex color.
// ═════════════════════════════════════════════════════════════════════════════

export default function SatelliteTrails({
  orbits,
  trailLength = 24,
  intensity = 0.55,
}: Props) {
  const lineRef = useRef<THREE.LineSegments>(null);

  // Precompute the rotation matrix per orbit — reused every frame.
  const rotations = useMemo(
    () => orbits.map((o) => buildSpinRotation(o.spinAxis)),
    [orbits],
  );
  const colors3 = useMemo(
    () => orbits.map((o) => {
      const c = new THREE.Color(o.color);
      return [c.r, c.g, c.b] as const;
    }),
    [orbits],
  );

  // Segment count per satellite = trailLength - 1 (line segments between
  // consecutive samples). Each segment = 2 vertices. So per-satellite: 2*(N-1).
  const segsPerSat = Math.max(1, trailLength - 1);
  const vertsPerSat = segsPerSat * 2;
  const nSats = orbits.length;

  const { geometry, positions, colors, seeded, writeIndex } = useMemo(() => {
    const total = nSats * vertsPerSat;
    const pos = new Float32Array(total * 3);
    const col = new Float32Array(total * 3);
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(col, 3));
    return {
      geometry: geo,
      positions: pos,
      colors: col,
      seeded: { value: false },
      writeIndex: { value: 0 },
    };
  }, [nSats, vertsPerSat]);

  // Fill colors once — head bright, tail dark; only touched when orbits change.
  useEffect(() => {
    for (let s = 0; s < nSats; s++) {
      const [r, g, b] = colors3[s];
      const base = s * vertsPerSat * 3;
      for (let seg = 0; seg < segsPerSat; seg++) {
        // Head is written most recently. We colour by "age" — the segment at
        // ring index N-1 is the head (bright), index 0 is the tail (dim).
        const t0 = seg / segsPerSat;         // 0..1 (older → newer within ring)
        const t1 = (seg + 1) / segsPerSat;
        const a0 = t0 * intensity;
        const a1 = t1 * intensity;
        const v = base + seg * 6;
        colors[v]     = r * a0; colors[v + 1] = g * a0; colors[v + 2] = b * a0;
        colors[v + 3] = r * a1; colors[v + 4] = g * a1; colors[v + 5] = b * a1;
      }
    }
  }, [colors3, colors, segsPerSat, vertsPerSat, nSats, intensity]);

  // Pre-alloc scratch for kepler positions.
  const scratch = useMemo(() => new Float32Array(3), []);

  useFrame(({ clock }) => {
    if (nSats === 0) return;
    const line = lineRef.current;
    if (!line) return;
    const t = clock.getElapsedTime();

    // Compute current head position for every satellite, then rotate the
    // ring buffer by one sample. To keep this O(nSats) per frame we don't
    // move all N samples — we treat the geometry as a chain of segments and
    // shift each segment by one sample:
    //   segment i's endpoints become segment (i+1)'s endpoints
    // Then write the head into the last segment's tip.
    //
    // Trick: we lay out samples as consecutive pairs (segment i has vertices
    // 2i and 2i+1, where 2i+1 == 2(i+1)+0 in "shared" form). We reuse the
    // buffer as if it were a linear polyline of length N samples per sat and
    // do a manual shift: copy positions[j+1] → positions[j] for j in 0..N-2.

    // We store samples as N samples per satellite, but the buffer is written
    // as line segments (pairs of vertices) sharing endpoints:
    //   sample[i] contributes to vertex (i-1)*2+1 and vertex i*2 (except at ends).
    // Simplest impl: keep a parallel Float32Array of size (nSats * N * 3) as
    // the logical samples, and rebuild the segment buffer from it each frame.
    // For 200 satellites × 24 samples × 3 = 14.4k floats/frame — trivial.

    // Actually we lazily do this once here rather than allocate scratch above.
    // (It's still one memcpy plus one shader write per frame.)

    // If not seeded, evaluate at t for every sample position so the trail
    // starts as a coherent arc rather than popping in.
    if (!seeded.value) {
      seeded.value = true;
      for (let s = 0; s < nSats; s++) {
        const o = orbits[s];
        const R = rotations[s];
        const px = o.parentPos[0], py = o.parentPos[1], pz = o.parentPos[2];
        for (let i = 0; i < trailLength; i++) {
          const tt = t - (trailLength - 1 - i) * (1 / 60);
          keplerPositionInto(scratch, o.elements, px, py, pz, tt, R);
          // Write into segment vertices — sample i is the shared endpoint
          // between segment (i-1) (as its "tip") and segment i (as its base).
          if (i > 0) {
            const v = s * vertsPerSat * 3 + (i - 1) * 6 + 3;
            positions[v]     = scratch[0];
            positions[v + 1] = scratch[1];
            positions[v + 2] = scratch[2];
          }
          if (i < segsPerSat) {
            const v = s * vertsPerSat * 3 + i * 6;
            positions[v]     = scratch[0];
            positions[v + 1] = scratch[1];
            positions[v + 2] = scratch[2];
          }
        }
      }
    } else {
      // Per satellite: shift every segment left by one, then write new head.
      // Buffer layout is [seg0_v0, seg0_v1, seg1_v0, seg1_v1, ...]. Shifting
      // 6 floats to the left slides each segment's contents into the previous
      // segment's slot. The final segment is not covered by that shift, so we
      // update it explicitly: its base becomes the previous tip, its tip
      // becomes the freshly-solved head.
      for (let s = 0; s < nSats; s++) {
        const base = s * vertsPerSat * 3;
        const lastSeg = base + (segsPerSat - 1) * 6;

        // Grab the old head (last segment's tip) before it's overwritten —
        // it becomes the new base of the last segment (continuity).
        const oldHx = positions[lastSeg + 3];
        const oldHy = positions[lastSeg + 4];
        const oldHz = positions[lastSeg + 5];

        // Shift all "prior" segment vertices left by one segment (6 floats).
        for (let j = 0; j < (segsPerSat - 1) * 6; j++) {
          positions[base + j] = positions[base + j + 6];
        }

        // Compute new head at time t.
        const o = orbits[s];
        const R = rotations[s];
        const px = o.parentPos[0], py = o.parentPos[1], pz = o.parentPos[2];
        keplerPositionInto(scratch, o.elements, px, py, pz, t, R);

        // Last segment: base = old head, tip = new head.
        positions[lastSeg]     = oldHx;
        positions[lastSeg + 1] = oldHy;
        positions[lastSeg + 2] = oldHz;
        positions[lastSeg + 3] = scratch[0];
        positions[lastSeg + 4] = scratch[1];
        positions[lastSeg + 5] = scratch[2];
      }
    }

    (geometry.getAttribute("position") as THREE.BufferAttribute).needsUpdate = true;
  });

  // Material: additive vertex-colored lines. depthWrite off so trails don't
  // hide points behind them.
  const material = useMemo(
    () =>
      new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    [],
  );

  if (nSats === 0) return null;
  // eslint-disable-next-line react/no-unknown-property
  return <lineSegments ref={lineRef} geometry={geometry} material={material} frustumCulled={false} />;
}
