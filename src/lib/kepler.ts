// ═════════════════════════════════════════════════════════════════════════════
//  Kepler orbital solver
//
//  Closed-form position from classical orbital elements plus a per-galaxy
//  spin-axis rotation, so satellites in the same galaxy share a preferred
//  orbital plane. Uses a 3-iteration Newton–Raphson step on the Kepler
//  equation E - e·sin(E) = M — sufficient for e ≤ 0.3 with < 1e-6 error.
//
//  Both a returning form and a mutating "into" form are exported. The mutating
//  form is what NodeCloud / SatelliteTrails call every frame; it MUST not
//  allocate.
// ═════════════════════════════════════════════════════════════════════════════

export interface Vec3 { x: number; y: number; z: number }

export interface OrbitalElements {
  a: number;      // semi-major axis
  e: number;      // eccentricity (0..~0.3)
  omega: number;  // argument of periapsis (rad)
  Omega: number;  // longitude of ascending node (rad)
  incl: number;   // inclination (rad)
  M0: number;     // mean anomaly at epoch (rad)
  n: number;      // mean motion (rad/s)
}

/**
 * Build a 9-element row-major rotation matrix that maps the reference z-axis
 * `[0,0,1]` onto `spinAxis` (must be a unit vector). Used to tilt an orbit
 * plane so all satellites in a galaxy share a common preferred plane.
 */
export function buildSpinRotation(spinAxis: Vec3): Float32Array {
  const R = new Float32Array(9);
  // Rodrigues rotation aligning [0,0,1] with spinAxis.
  const zx = 0, zy = 0, zz = 1;
  const vx = spinAxis.x, vy = spinAxis.y, vz = spinAxis.z;
  // cross(z, v)
  const cx = zy * vz - zz * vy;
  const cy = zz * vx - zx * vz;
  const cz = zx * vy - zy * vx;
  const s = Math.sqrt(cx * cx + cy * cy + cz * cz);
  const c = zx * vx + zy * vy + zz * vz; // dot(z, v) = vz

  if (s < 1e-8) {
    // Parallel or antiparallel.
    if (c > 0) {
      R[0] = 1; R[1] = 0; R[2] = 0;
      R[3] = 0; R[4] = 1; R[5] = 0;
      R[6] = 0; R[7] = 0; R[8] = 1;
    } else {
      // 180° flip about x-axis
      R[0] = 1; R[1] = 0; R[2] = 0;
      R[3] = 0; R[4] = -1; R[5] = 0;
      R[6] = 0; R[7] = 0; R[8] = -1;
    }
    return R;
  }

  // Normalize axis
  const invS = 1 / s;
  const kx = cx * invS, ky = cy * invS, kz = cz * invS;
  const t = 1 - c;

  // Rodrigues rotation matrix, row-major
  R[0] = c + kx * kx * t;
  R[1] = kx * ky * t - kz * s;
  R[2] = kx * kz * t + ky * s;
  R[3] = ky * kx * t + kz * s;
  R[4] = c + ky * ky * t;
  R[5] = ky * kz * t - kx * s;
  R[6] = kz * kx * t - ky * s;
  R[7] = kz * ky * t + kx * s;
  R[8] = c + kz * kz * t;
  return R;
}

/**
 * Solve the Kepler equation and write the world-space satellite position into
 * `out[0..2]`. Zero allocations per call.
 *
 * @param out          length-3 array to receive [x, y, z]
 * @param o            orbital elements
 * @param px py pz     parent (attractor) world-space position
 * @param t            current time (seconds since epoch)
 * @param R            9-element rotation matrix from `buildSpinRotation`
 */
export function keplerPositionInto(
  out: Float32Array | number[],
  o: OrbitalElements,
  px: number, py: number, pz: number,
  t: number,
  R: Float32Array | number[],
): void {
  const M = o.M0 + o.n * t;

  // Newton–Raphson, 3 iterations. Empirically converges within 1e-6 for e ≤ 0.3.
  let E = M;
  for (let i = 0; i < 3; i++) {
    E = E - (E - o.e * Math.sin(E) - M) / (1 - o.e * Math.cos(E));
  }

  const cosE = Math.cos(E);
  const sinE = Math.sin(E);
  const xO = o.a * (cosE - o.e);
  const yO = o.a * Math.sqrt(1 - o.e * o.e) * sinE;

  // Rotate in orbital plane by omega (argument of periapsis)
  const cw = Math.cos(o.omega);
  const sw = Math.sin(o.omega);
  const x1 = xO * cw - yO * sw;
  const y1 = xO * sw + yO * cw;
  // z1 = 0

  // Inclination about x-axis
  const ci = Math.cos(o.incl);
  const si = Math.sin(o.incl);
  const x2 = x1;
  const y2 = y1 * ci;
  const z2 = y1 * si;

  // Longitude of ascending node about z-axis
  const cO = Math.cos(o.Omega);
  const sO = Math.sin(o.Omega);
  const x3 = x2 * cO - y2 * sO;
  const y3 = x2 * sO + y2 * cO;
  const z3 = z2;

  // Apply per-galaxy spin rotation
  out[0] = px + R[0] * x3 + R[1] * y3 + R[2] * z3;
  out[1] = py + R[3] * x3 + R[4] * y3 + R[5] * z3;
  out[2] = pz + R[6] * x3 + R[7] * y3 + R[8] * z3;
}

/**
 * Returning form — allocates a Vec3. Only use off the hot path.
 */
export function keplerPosition(
  o: OrbitalElements,
  parentPos: Vec3,
  t: number,
  R: Float32Array | number[],
): Vec3 {
  const out = [0, 0, 0];
  keplerPositionInto(out, o, parentPos.x, parentPos.y, parentPos.z, t, R);
  return { x: out[0], y: out[1], z: out[2] };
}
