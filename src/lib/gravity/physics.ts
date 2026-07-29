/**
 * HUGIN Gravity Lab physics core.
 *
 * Units are deliberately named HUGIN units. They are deterministic numerical
 * simulation units, never astronomical measurements. The renderer may turn
 * them into a visual solar system but callers must label the result simulated.
 */

export type SolverMode = "adaptive" | "all-barnes-hut" | "exact-n2";
export type CollisionOutcome = "flyby" | "capture" | "accretion" | "fragmentation" | "ejection";

export interface GravityBodyInput {
  id: string;
  mass: number;
  radius: number;
  position: readonly [number, number, number];
  velocity?: readonly [number, number, number];
  pinned?: boolean;
}

export interface GravityConfig {
  solver: SolverMode;
  gravitationalConstant: number;
  softening: number;
  theta: number;
  fixedDt: number;
  activeLimit: number;
  collisionScale: number;
  restitution: number;
}

export interface CollisionEvent {
  type: "collision";
  at: number;
  a: string;
  b: string;
  outcome: CollisionOutcome;
  kineticEnergy: number;
  relativeSpeed: number;
  impactParameter: number;
}

export interface PhysicsMetrics {
  simulationTime: number;
  bodyCount: number;
  activeBodies: number;
  solver: SolverMode;
  pairEvaluations: number;
  kineticEnergy: number;
  potentialEnergy: number | null;
  linearMomentum: readonly [number, number, number];
  collisions: CollisionEvent[];
}

export const DEFAULT_GRAVITY_CONFIG: GravityConfig = {
  solver: "adaptive",
  gravitationalConstant: 0.08,
  softening: 18,
  theta: 0.72,
  fixedDt: 1 / 30,
  activeLimit: 256,
  collisionScale: 0.7,
  restitution: 0.42,
};

type OctreeNode = {
  cx: number; cy: number; cz: number; half: number;
  mass: number; comX: number; comY: number; comZ: number;
  body: number;
  children: Array<OctreeNode | null> | null;
};

const childIndex = (x: number, y: number, z: number, n: OctreeNode) =>
  (x >= n.cx ? 1 : 0) | (y >= n.cy ? 2 : 0) | (z >= n.cz ? 4 : 0);

function createNode(cx: number, cy: number, cz: number, half: number): OctreeNode {
  return { cx, cy, cz, half, mass: 0, comX: 0, comY: 0, comZ: 0, body: -1, children: null };
}

/** A fixed-step, velocity-Verlet N-body engine designed to run in a Worker. */
export class GravityEngine {
  readonly ids: string[];
  readonly masses: Float64Array;
  readonly radii: Float64Array;
  readonly pinned: Uint8Array;
  readonly positions: Float64Array;
  readonly velocities: Float64Array;
  private acceleration = new Float64Array(0);
  private nextAcceleration = new Float64Array(0);
  private active = new Uint32Array(0);
  private config: GravityConfig;
  private time = 0;
  private pairEvaluations = 0;
  /** Pair -> last simulation time. Prevents duplicate broad-phase hits, while
   * allowing two bodies to meet again after separating. */
  private collisionPairs = new Map<string, number>();

  constructor(bodies: GravityBodyInput[], config: Partial<GravityConfig> = {}) {
    this.config = { ...DEFAULT_GRAVITY_CONFIG, ...config };
    this.ids = bodies.map((b) => b.id);
    this.masses = new Float64Array(bodies.length);
    this.radii = new Float64Array(bodies.length);
    this.pinned = new Uint8Array(bodies.length);
    this.positions = new Float64Array(bodies.length * 3);
    this.velocities = new Float64Array(bodies.length * 3);
    for (let i = 0; i < bodies.length; i++) {
      const b = bodies[i];
      this.masses[i] = Math.max(0.01, b.mass);
      this.radii[i] = Math.max(0.5, b.radius);
      this.pinned[i] = b.pinned ? 1 : 0;
      const j = i * 3;
      this.positions[j] = b.position[0]; this.positions[j + 1] = b.position[1]; this.positions[j + 2] = b.position[2];
      this.velocities[j] = b.velocity?.[0] ?? 0; this.velocities[j + 1] = b.velocity?.[1] ?? 0; this.velocities[j + 2] = b.velocity?.[2] ?? 0;
    }
    this.acceleration = new Float64Array(this.positions.length);
    this.nextAcceleration = new Float64Array(this.positions.length);
    this.setActiveBodies();
  }

  getConfig() { return { ...this.config }; }
  setConfig(next: Partial<GravityConfig>) { this.config = { ...this.config, ...next }; this.setActiveBodies(); }
  setBodyState(index: number, position: readonly [number, number, number], velocity?: readonly [number, number, number]) {
    const i = index * 3;
    this.positions[i] = position[0]; this.positions[i + 1] = position[1]; this.positions[i + 2] = position[2];
    if (velocity) { this.velocities[i] = velocity[0]; this.velocities[i + 1] = velocity[1]; this.velocities[i + 2] = velocity[2]; }
  }
  indexFor(id: string) { return this.ids.indexOf(id); }

  /** Select the heaviest bodies for the low-cost adaptive neighborhood. */
  setActiveBodies(center?: readonly [number, number, number]) {
    const total = this.ids.length;
    const all = this.config.solver !== "adaptive";
    const take = all ? total : Math.min(total, Math.max(2, this.config.activeLimit));
    const ranked = Array.from({ length: total }, (_, i) => i).sort((a, b) => {
      const ma = this.masses[a], mb = this.masses[b];
      if (!center) return mb - ma;
      const ia = a * 3, ib = b * 3;
      const da = (this.positions[ia] - center[0]) ** 2 + (this.positions[ia + 1] - center[1]) ** 2 + (this.positions[ia + 2] - center[2]) ** 2;
      const db = (this.positions[ib] - center[0]) ** 2 + (this.positions[ib + 1] - center[1]) ** 2 + (this.positions[ib + 2] - center[2]) ** 2;
      return da === db ? mb - ma : da - db;
    });
    this.active = Uint32Array.from(ranked.slice(0, take));
  }

  step(steps = 1): PhysicsMetrics {
    let collisions: CollisionEvent[] = [];
    for (let n = 0; n < steps; n++) collisions = collisions.concat(this.stepOnce());
    return this.metrics(collisions);
  }

  private stepOnce(): CollisionEvent[] {
    const dt = this.config.fixedDt;
    this.acceleration.fill(0);
    this.pairEvaluations = 0;
    if (this.config.solver === "all-barnes-hut") this.computeBarnesHut(this.acceleration);
    else this.computeDirect(this.acceleration);

    for (const idx of this.active) {
      if (this.pinned[idx]) continue;
      const i = idx * 3;
      this.velocities[i] += this.acceleration[i] * dt * 0.5;
      this.velocities[i + 1] += this.acceleration[i + 1] * dt * 0.5;
      this.velocities[i + 2] += this.acceleration[i + 2] * dt * 0.5;
      this.positions[i] += this.velocities[i] * dt;
      this.positions[i + 1] += this.velocities[i + 1] * dt;
      this.positions[i + 2] += this.velocities[i + 2] * dt;
    }

    this.nextAcceleration.fill(0);
    if (this.config.solver === "all-barnes-hut") this.computeBarnesHut(this.nextAcceleration);
    else this.computeDirect(this.nextAcceleration);
    for (const idx of this.active) {
      if (this.pinned[idx]) continue;
      const i = idx * 3;
      this.velocities[i] += this.nextAcceleration[i] * dt * 0.5;
      this.velocities[i + 1] += this.nextAcceleration[i + 1] * dt * 0.5;
      this.velocities[i + 2] += this.nextAcceleration[i + 2] * dt * 0.5;
    }
    this.time += dt;
    return this.resolveCollisions();
  }

  private computeDirect(out: Float64Array) {
    const active = this.active;
    const eps2 = this.config.softening ** 2;
    const G = this.config.gravitationalConstant;
    for (let ai = 0; ai < active.length; ai++) {
      const a = active[ai], ia = a * 3;
      for (let bi = ai + 1; bi < active.length; bi++) {
        const b = active[bi], ib = b * 3;
        const dx = this.positions[ib] - this.positions[ia];
        const dy = this.positions[ib + 1] - this.positions[ia + 1];
        const dz = this.positions[ib + 2] - this.positions[ia + 2];
        const invR3 = 1 / Math.pow(dx * dx + dy * dy + dz * dz + eps2, 1.5);
        const aScale = G * this.masses[b] * invR3;
        const bScale = G * this.masses[a] * invR3;
        out[ia] += dx * aScale; out[ia + 1] += dy * aScale; out[ia + 2] += dz * aScale;
        out[ib] -= dx * bScale; out[ib + 1] -= dy * bScale; out[ib + 2] -= dz * bScale;
        this.pairEvaluations++;
      }
    }
  }

  private rootForActive(): OctreeNode | null {
    if (this.active.length === 0) return null;
    let minX = Infinity, minY = Infinity, minZ = Infinity, maxX = -Infinity, maxY = -Infinity, maxZ = -Infinity;
    for (const index of this.active) {
      const i = index * 3;
      minX = Math.min(minX, this.positions[i]); minY = Math.min(minY, this.positions[i + 1]); minZ = Math.min(minZ, this.positions[i + 2]);
      maxX = Math.max(maxX, this.positions[i]); maxY = Math.max(maxY, this.positions[i + 1]); maxZ = Math.max(maxZ, this.positions[i + 2]);
    }
    const half = Math.max(maxX - minX, maxY - minY, maxZ - minZ, 1) * 0.55 + this.config.softening;
    const root = createNode((minX + maxX) * 0.5, (minY + maxY) * 0.5, (minZ + maxZ) * 0.5, half);
    for (const index of this.active) this.insert(root, index, 0);
    return root;
  }

  private insert(node: OctreeNode, body: number, depth: number) {
    const i = body * 3;
    const oldMass = node.mass;
    const mass = this.masses[body];
    node.mass += mass;
    node.comX = (node.comX * oldMass + this.positions[i] * mass) / node.mass;
    node.comY = (node.comY * oldMass + this.positions[i + 1] * mass) / node.mass;
    node.comZ = (node.comZ * oldMass + this.positions[i + 2] * mass) / node.mass;
    if (node.body === -1 && node.children === null) { node.body = body; return; }
    if (depth > 32 || node.half < 1e-3) return;
    if (node.children === null) {
      node.children = Array.from({ length: 8 }, () => null);
      const existing = node.body; node.body = -1;
      if (existing >= 0) this.insertChild(node, existing, depth + 1);
    }
    this.insertChild(node, body, depth + 1);
  }

  private insertChild(parent: OctreeNode, body: number, depth: number) {
    const i = body * 3;
    const bit = childIndex(this.positions[i], this.positions[i + 1], this.positions[i + 2], parent);
    let child = parent.children![bit];
    if (!child) {
      const q = parent.half * 0.5;
      child = createNode(parent.cx + (bit & 1 ? q : -q), parent.cy + (bit & 2 ? q : -q), parent.cz + (bit & 4 ? q : -q), q);
      parent.children![bit] = child;
    }
    this.insert(child, body, depth);
  }

  private computeBarnesHut(out: Float64Array) {
    const root = this.rootForActive(); if (!root) return;
    for (const body of this.active) this.accelerateFromTree(body, root, out);
  }

  private accelerateFromTree(body: number, node: OctreeNode, out: Float64Array) {
    if (node.mass <= 0 || (node.body === body && node.children === null)) return;
    const i = body * 3;
    const dx = node.comX - this.positions[i], dy = node.comY - this.positions[i + 1], dz = node.comZ - this.positions[i + 2];
    const d2 = dx * dx + dy * dy + dz * dz + this.config.softening ** 2;
    const d = Math.sqrt(d2);
    if (node.children === null || node.half * 2 / d < this.config.theta) {
      const scale = this.config.gravitationalConstant * node.mass / (d2 * d);
      out[i] += dx * scale; out[i + 1] += dy * scale; out[i + 2] += dz * scale; this.pairEvaluations++;
      return;
    }
    for (const child of node.children) if (child) this.accelerateFromTree(body, child, out);
  }

  private resolveCollisions(): CollisionEvent[] {
    const cells = new Map<string, number[]>(); const events: CollisionEvent[] = [];
    const cellSize = Math.max(2, this.config.collisionScale * 10);
    for (const index of this.active) {
      const i = index * 3;
      const key = `${Math.floor(this.positions[i] / cellSize)},${Math.floor(this.positions[i + 1] / cellSize)},${Math.floor(this.positions[i + 2] / cellSize)}`;
      const bucket = cells.get(key); if (bucket) bucket.push(index); else cells.set(key, [index]);
    }
    const visited = new Set<string>();
    const neighborKeys = (x: number, y: number, z: number) => {
      const keys: string[] = [];
      for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) for (let dz = -1; dz <= 1; dz++) keys.push(`${x + dx},${y + dy},${z + dz}`);
      return keys;
    };
    for (const [cell, bucket] of cells) {
      const [x, y, z] = cell.split(",").map(Number);
      const candidates = neighborKeys(x, y, z).flatMap((key) => cells.get(key) ?? []);
      for (const ia of bucket) for (const ib of candidates) {
      if (ia === ib) continue;
      const ordered = ia < ib ? `${ia}:${ib}` : `${ib}:${ia}`;
      if (visited.has(ordered)) continue;
      visited.add(ordered);
      const pa = ia * 3, pb = ib * 3;
      const dx = this.positions[pb] - this.positions[pa], dy = this.positions[pb + 1] - this.positions[pa + 1], dz = this.positions[pb + 2] - this.positions[pa + 2];
      const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1e-6;
      const threshold = (this.radii[ia] + this.radii[ib]) * this.config.collisionScale;
      if (dist > threshold) continue;
      const lastHit = this.collisionPairs.get(ordered);
      if (lastHit !== undefined && this.time - lastHit < Math.max(this.config.fixedDt * 3, 0.12)) continue;
      this.collisionPairs.set(ordered, this.time);
      const nx = dx / dist, ny = dy / dist, nz = dz / dist;
      const rvx = this.velocities[pb] - this.velocities[pa], rvy = this.velocities[pb + 1] - this.velocities[pa + 1], rvz = this.velocities[pb + 2] - this.velocities[pa + 2];
      const relativeSpeed = Math.sqrt(rvx * rvx + rvy * rvy + rvz * rvz);
      const reducedMass = this.masses[ia] * this.masses[ib] / (this.masses[ia] + this.masses[ib]);
      const energy = 0.5 * reducedMass * relativeSpeed ** 2;
      const escapeSpeed = Math.sqrt(2 * this.config.gravitationalConstant * (this.masses[ia] + this.masses[ib]) / Math.max(1, threshold));
      const massRatio = Math.max(this.masses[ia], this.masses[ib]) / Math.max(0.01, Math.min(this.masses[ia], this.masses[ib]));
      const outcome: CollisionOutcome = relativeSpeed < escapeSpeed * 0.42 && massRatio > 3
        ? "accretion"
        : relativeSpeed < escapeSpeed * 0.7 ? "capture"
        : relativeSpeed > escapeSpeed * 2.4 ? "fragmentation"
        : energy > 40 ? "ejection" : "flyby";
      const normalSpeed = rvx * nx + rvy * ny + rvz * nz;
      if (outcome === "accretion") {
        const heavy = this.masses[ia] >= this.masses[ib] ? ia : ib;
        const light = heavy === ia ? ib : ia;
        const ph = heavy * 3, pl = light * 3;
        const totalMass = this.masses[heavy] + this.masses[light];
        if (!this.pinned[heavy]) {
          this.velocities[ph] = (this.velocities[ph] * this.masses[heavy] + this.velocities[pl] * this.masses[light]) / totalMass;
          this.velocities[ph + 1] = (this.velocities[ph + 1] * this.masses[heavy] + this.velocities[pl + 1] * this.masses[light]) / totalMass;
          this.velocities[ph + 2] = (this.velocities[ph + 2] * this.masses[heavy] + this.velocities[pl + 2] * this.masses[light]) / totalMass;
        }
        this.masses[heavy] = totalMass;
        this.radii[heavy] = Math.cbrt(this.radii[heavy] ** 3 + this.radii[light] ** 3);
        this.masses[light] = 0.01; this.radii[light] = 0.1;
        this.positions[pl] = this.positions[ph]; this.positions[pl + 1] = this.positions[ph + 1]; this.positions[pl + 2] = this.positions[ph + 2];
      } else if (normalSpeed < 0 && outcome !== "capture") {
        const impulse = -(1 + this.config.restitution) * normalSpeed / (1 / this.masses[ia] + 1 / this.masses[ib]);
        if (!this.pinned[ia]) { this.velocities[pa] -= impulse * nx / this.masses[ia]; this.velocities[pa + 1] -= impulse * ny / this.masses[ia]; this.velocities[pa + 2] -= impulse * nz / this.masses[ia]; }
        if (!this.pinned[ib]) { this.velocities[pb] += impulse * nx / this.masses[ib]; this.velocities[pb + 1] += impulse * ny / this.masses[ib]; this.velocities[pb + 2] += impulse * nz / this.masses[ib]; }
      }
      events.push({ type: "collision", at: this.time, a: this.ids[ia], b: this.ids[ib], outcome, kineticEnergy: energy, relativeSpeed, impactParameter: dist / Math.max(threshold, 1e-6) });
      }
    }
    for (const [key, at] of this.collisionPairs) if (this.time - at > 10) this.collisionPairs.delete(key);
    return events;
  }

  private metrics(collisions: CollisionEvent[]): PhysicsMetrics {
    let kinetic = 0, potential = 0, px = 0, py = 0, pz = 0;
    for (const index of this.active) { const i = index * 3, m = this.masses[index]; const vx = this.velocities[i], vy = this.velocities[i + 1], vz = this.velocities[i + 2]; kinetic += 0.5 * m * (vx * vx + vy * vy + vz * vz); px += m * vx; py += m * vy; pz += m * vz; }
    for (let ai = 0; ai < this.active.length; ai++) for (let bi = ai + 1; bi < this.active.length; bi++) {
      const a = this.active[ai] * 3, b = this.active[bi] * 3;
      const dx = this.positions[b] - this.positions[a], dy = this.positions[b + 1] - this.positions[a + 1], dz = this.positions[b + 2] - this.positions[a + 2];
      potential -= this.config.gravitationalConstant * this.masses[this.active[ai]] * this.masses[this.active[bi]] / Math.sqrt(dx * dx + dy * dy + dz * dz + this.config.softening ** 2);
    }
    return { simulationTime: this.time, bodyCount: this.ids.length, activeBodies: this.active.length, solver: this.config.solver, pairEvaluations: this.pairEvaluations, kineticEnergy: kinetic, potentialEnergy: potential, linearMomentum: [px, py, pz], collisions };
  }
}

export function benchmarkDirectPairs(bodyCount: number, hz: number) {
  const pairs = bodyCount * (bodyCount - 1) / 2;
  return { bodyCount, pairsPerStep: pairs, requestedHz: hz, pairEvaluationsPerSecond: pairs * hz };
}
