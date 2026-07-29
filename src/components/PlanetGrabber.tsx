// ═════════════════════════════════════════════════════════════════════════════
//  PlanetGrabber — pointer-driven grab/drag of heavy nodes.
//
//  Interaction model:
//    · On pointerdown, we raycast against a set of invisible hitboxes sized
//      per candidate. Only candidates with mass > threshold are grab-able.
//    · While dragging, we intersect the current ray with a plane that is
//      *parallel to the camera view* and passes through the node's initial
//      grab position. This preserves the node's distance from the camera
//      throughout the drag — it feels like you're holding it in your hand
//      rather than sliding it on the floor.
//    · On release, if mode === "spring-back", the node damped-harmonic tweens
//      back to its origin. If mode === "leave-it", it stays where dropped.
//
//  Zero allocations per frame. All Vector3 / Plane / Ray scratch objects are
//  hoisted into refs and reused every tick.
// ═════════════════════════════════════════════════════════════════════════════

import { useEffect, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

export type GrabCandidate = {
  id: string;
  position: [number, number, number];
  size: number;         // radius of the invisible hitbox sphere (world units)
  mass?: number;
};

interface Props {
  hitCandidates: GrabCandidate[];
  enabled: boolean;
  onGrabStart?: (id: string, position: THREE.Vector3) => void;
  onGrabMove?: (id: string, position: THREE.Vector3) => void;
  onGrabEnd?: (id: string, finalPosition: THREE.Vector3, released: boolean) => void;
  onSpringComplete?: (id: string, origin: THREE.Vector3) => void;
  mode?: "spring-back" | "leave-it";
}

const MASS_THRESHOLD = 3.0;   // Only nodes with mass ≥ this are grab-able.

// Damped-harmonic tween: ω=8, ζ=0.6 → underdamped, snappy, tiny overshoot.
const SPRING_OMEGA = 8.0;
const SPRING_ZETA  = 0.6;

// Spring-back timeout — after ~0.8s we treat the tween as complete.
const SPRING_DURATION = 0.85;

export default function PlanetGrabber({
  hitCandidates,
  enabled,
  onGrabStart,
  onGrabMove,
  onGrabEnd,
  onSpringComplete,
  mode = "spring-back",
}: Props) {
  const { camera, gl, pointer, raycaster } = useThree();

  // Grab state, refs (avoids re-renders).
  const grabbedId    = useRef<string | null>(null);
  const springId     = useRef<string | null>(null);   // id of the node currently springing back
  const grabOrigin   = useRef<THREE.Vector3>(new THREE.Vector3());
  const grabCurrent  = useRef<THREE.Vector3>(new THREE.Vector3());
  const grabPlane    = useRef<THREE.Plane>(new THREE.Plane());
  const springStartT = useRef<number>(-1);
  const springStartP = useRef<THREE.Vector3>(new THREE.Vector3());
  const springVel    = useRef<THREE.Vector3>(new THREE.Vector3());

  // Scratch vectors — reused every frame, never allocate in hot path.
  const scratchA = useRef<THREE.Vector3>(new THREE.Vector3());
  const scratchB = useRef<THREE.Vector3>(new THREE.Vector3());
  const scratchN = useRef<THREE.Vector3>(new THREE.Vector3());

  // Fresh candidate list — mutable ref so pointer handlers see latest.
  const candidatesRef = useRef<GrabCandidate[]>(hitCandidates);
  useEffect(() => { candidatesRef.current = hitCandidates; }, [hitCandidates]);

  const enabledRef = useRef(enabled);
  useEffect(() => { enabledRef.current = enabled; }, [enabled]);

  // ── Raycast helpers ────────────────────────────────────────────────────────

  // Find the nearest grab-able candidate under the current pointer.
  function pickCandidate(): GrabCandidate | null {
    const cands = candidatesRef.current;
    if (!cands || cands.length === 0) return null;
    raycaster.setFromCamera(pointer, camera);
    let best: GrabCandidate | null = null;
    let bestT = Infinity;
    const p = scratchA.current;
    const closest = scratchB.current;
    for (let i = 0; i < cands.length; i++) {
      const c = cands[i];
      if ((c.mass ?? 0) < MASS_THRESHOLD) continue;
      p.set(c.position[0], c.position[1], c.position[2]);
      // Distance from ray to sphere center; hit if within c.size world units.
      raycaster.ray.closestPointToPoint(p, closest);
      const dSq = closest.distanceToSquared(p);
      const r = Math.max(4, c.size);
      if (dSq > r * r) continue;
      const t = raycaster.ray.origin.distanceToSquared(closest);
      if (t < bestT) { bestT = t; best = c; }
    }
    return best;
  }

  // Update the drag position by intersecting the ray with the grab plane.
  function updateFromRay(out: THREE.Vector3): boolean {
    raycaster.setFromCamera(pointer, camera);
    const hit = raycaster.ray.intersectPlane(grabPlane.current, out);
    return hit !== null;
  }

  // ── Pointer handlers ───────────────────────────────────────────────────────

  useEffect(() => {
    const dom = gl.domElement;
    if (!dom) return;

    const setCursor = (v: string) => { dom.style.cursor = v; };

    const onPointerDown = (e: PointerEvent) => {
      if (!enabledRef.current) return;
      const c = pickCandidate();
      if (!c) return;
      // Only respond to primary button drags.
      if (e.button !== 0) return;

      grabbedId.current = c.id;
      grabOrigin.current.set(c.position[0], c.position[1], c.position[2]);
      grabCurrent.current.copy(grabOrigin.current);

      // Build a view-plane-parallel plane through the grab origin. Normal =
      // camera forward. Constant = -(normal · origin).
      const n = scratchN.current;
      camera.getWorldDirection(n);          // unit forward vector
      grabPlane.current.setFromNormalAndCoplanarPoint(n, grabOrigin.current);

      springStartT.current = -1;
      setCursor("grabbing");
      try { dom.setPointerCapture(e.pointerId); } catch { /* noop */ }

      onGrabStart?.(c.id, grabOrigin.current);
    };

    const onPointerMove = (_e: PointerEvent) => {
      if (grabbedId.current) {
        if (updateFromRay(grabCurrent.current)) {
          onGrabMove?.(grabbedId.current, grabCurrent.current);
        }
      } else if (enabledRef.current) {
        // Hover feedback — show grab cursor when hovering a heavy node.
        const c = pickCandidate();
        setCursor(c ? "grab" : "");
      }
    };

    const endGrab = (e: PointerEvent, released: boolean) => {
      const id = grabbedId.current;
      if (!id) return;
      grabbedId.current = null;
      setCursor("");
      try { dom.releasePointerCapture(e.pointerId); } catch { /* noop */ }

      // Prime the spring-back tween.
      if (mode === "spring-back") {
        springId.current = id;
        springStartT.current = performance.now() / 1000;
        springStartP.current.copy(grabCurrent.current);
        springVel.current.set(0, 0, 0);
      }
      onGrabEnd?.(id, grabCurrent.current, released);
    };

    const onPointerUp = (e: PointerEvent) => endGrab(e, true);
    const onPointerLeave = (e: PointerEvent) => { if (grabbedId.current) endGrab(e, false); };

    dom.addEventListener("pointerdown", onPointerDown);
    dom.addEventListener("pointermove", onPointerMove);
    dom.addEventListener("pointerup", onPointerUp);
    dom.addEventListener("pointerleave", onPointerLeave);
    dom.addEventListener("pointercancel", onPointerUp);

    return () => {
      dom.removeEventListener("pointerdown", onPointerDown);
      dom.removeEventListener("pointermove", onPointerMove);
      dom.removeEventListener("pointerup", onPointerUp);
      dom.removeEventListener("pointerleave", onPointerLeave);
      dom.removeEventListener("pointercancel", onPointerUp);
      setCursor("");
    };
  }, [gl, camera, pointer, raycaster, mode, onGrabStart, onGrabMove, onGrabEnd]);

  // Spring-back animation. Damped harmonic oscillator toward grabOrigin.
  // Emits onGrabMove each tick with the stashed id so the parent's model
  // animates back in lockstep with the grabber's internal state.
  useFrame((_state, delta) => {
    const t0 = springStartT.current;
    if (t0 < 0) return;
    const id = springId.current;
    if (!id) return;

    const dt = Math.min(delta, 1 / 30);  // clamp long frame steps
    const p = grabCurrent.current;
    const v = springVel.current;
    const target = grabOrigin.current;

    // Damped harmonic: a = -ω² (p - target) - 2ζω v
    const dx = p.x - target.x, dy = p.y - target.y, dz = p.z - target.z;
    const w2 = SPRING_OMEGA * SPRING_OMEGA;
    const dCoef = 2 * SPRING_ZETA * SPRING_OMEGA;
    const ax = -w2 * dx - dCoef * v.x;
    const ay = -w2 * dy - dCoef * v.y;
    const az = -w2 * dz - dCoef * v.z;
    v.x += ax * dt; v.y += ay * dt; v.z += az * dt;
    p.x += v.x * dt; p.y += v.y * dt; p.z += v.z * dt;

    onGrabMove?.(id, p);

    const elapsed = performance.now() / 1000 - t0;
    if (elapsed > SPRING_DURATION) {
      p.copy(target);
      v.set(0, 0, 0);
      onGrabMove?.(id, p);
      springStartT.current = -1;
      springId.current = null;
      onSpringComplete?.(id, target);
    }
  });

  return null;
}
