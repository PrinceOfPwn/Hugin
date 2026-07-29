import { useEffect, useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

export type HitCandidate = { id: string; position: THREE.Vector3; size: number };

interface Props {
  // Bounding box of the universe — used for warp-in framing.
  bounds: {
    center: [number, number, number];
    size: number;
  };
  autoOrbit?: boolean;
  fitSignal?: number;
  // Optional external focus target. When set, the camera tweens to look at
  // this point from `distance` away (cubic-in-out over ~1.2s).
  focus?: { position: THREE.Vector3; distance?: number } | null;
  onFocusChange?: (target: THREE.Vector3) => void;
  onDoubleClickNode?: (nodeId: string) => void;
  hitCandidates?: HitCandidate[];
}

// ═════════════════════════════════════════════════════════════════════════════
//  CinematicCamera — Google-Earth-ish flight.
//
//  Layers of behavior (top overrides lower):
//    1. Warp-in: on mount, animates from far along +Z into a fit-bounds
//       framing over ~2.5s (ease-out cubic).
//    2. Fly-to tween: on `focus` change or double-click node, cubic-in-out
//       tween of target + spherical over ~1.2s.
//    3. Momentum: after a rotation drag, spherical angles keep updating with
//       exponentially-decaying velocity (0.94/frame).
//    4. Manual: pointer-drag rotate (or shift/right-drag pan), wheel to
//       zoom-toward-cursor, keyboard WASD-QE moves focus.
//    5. Auto-orbit: after 4s of idle (no drag, no momentum, no tween), slow
//       precession around the current target.
// ═════════════════════════════════════════════════════════════════════════════

const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));
const easeInOutCubic = (t: number) =>
  t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;

// Ray-sphere first intersection. Returns null if the ray misses or the hit
// is behind the origin. `out` is populated in place; the same vector is
// returned for chaining.
function raySphereFirst(
  origin: THREE.Vector3,
  dir: THREE.Vector3,
  center: THREE.Vector3,
  radius: number,
  out: THREE.Vector3,
): THREE.Vector3 | null {
  const ocx = origin.x - center.x;
  const ocy = origin.y - center.y;
  const ocz = origin.z - center.z;
  const b = ocx * dir.x + ocy * dir.y + ocz * dir.z;
  const c = ocx * ocx + ocy * ocy + ocz * ocz - radius * radius;
  const disc = b * b - c;
  if (disc < 0) return null;
  const t = -b - Math.sqrt(disc);
  if (t < 0) return null;
  out.set(origin.x + dir.x * t, origin.y + dir.y * t, origin.z + dir.z * t);
  return out;
}

export default function CinematicCamera({
  bounds,
  autoOrbit = true,
  fitSignal = 0,
  focus,
  onFocusChange,
  onDoubleClickNode,
  hitCandidates,
}: Props) {
  const { camera, gl } = useThree();

  // Camera state stored in spherical coords around a moveable target.
  const target = useRef(new THREE.Vector3(...bounds.center));
  const spherical = useRef({
    radius: 8000,
    phi: Math.PI * 0.42,
    theta: 0,
  });

  // Warp-in bookkeeping.
  const warpStart = useRef<number | null>(null);
  const WARP_MS = 2500;

  const fitDistance = useMemo(() => {
    const fov = (camera as THREE.PerspectiveCamera).fov ?? 55;
    const half = bounds.size * 0.5;
    return (half / Math.tan((fov * Math.PI) / 360)) * 1.15;
  }, [camera, bounds.size]);

  const lastInteractionAt = useRef(performance.now() - 999_999);

  // Drag / pointer state.
  const dragMode = useRef<"none" | "rotate" | "pan" | "pinch">("none");
  const lastMouse = useRef<{ x: number; y: number } | null>(null);
  const activePointers = useRef(new Map<number, { x: number; y: number }>());
  const pinchState = useRef<{ distance: number; x: number; y: number } | null>(null);

  // Momentum from a rotation drag.
  const angularVel = useRef({ theta: 0, phi: 0 });
  const momentumActive = useRef(false);

  // Time-based fly-to tween (used by focus prop AND double-click).
  const flyTween = useRef<{
    start: number;
    duration: number;
    fromTarget: THREE.Vector3;
    toTarget: THREE.Vector3;
    fromRadius: number; toRadius: number;
    fromPhi: number; toPhi: number;
    fromTheta: number; toTheta: number;
  } | null>(null);

  // Double-click detection at the DOM layer.
  const lastPointerUpAt = useRef(0);
  const lastFitSignal = useRef(fitSignal);

  // Keyboard state.
  const keys = useRef(new Set<string>());

  // Latest `focus` + callbacks captured in refs so the DOM handler effect
  // doesn't have to re-register whenever they change identity.
  const focusRef = useRef(focus);
  const onDoubleClickNodeRef = useRef(onDoubleClickNode);
  const onFocusChangeRef = useRef(onFocusChange);
  useEffect(() => { focusRef.current = focus; }, [focus]);
  useEffect(() => { onDoubleClickNodeRef.current = onDoubleClickNode; }, [onDoubleClickNode]);
  useEffect(() => { onFocusChangeRef.current = onFocusChange; }, [onFocusChange]);

  // ── Scratch vectors (avoid per-frame allocations) ────────────────────────
  const scratchDir = useMemo(() => new THREE.Vector3(), []);
  const scratchOrigin = useMemo(() => new THREE.Vector3(), []);
  const scratchHit = useMemo(() => new THREE.Vector3(), []);
  const scratchViewingPos = useMemo(() => new THREE.Vector3(), []);
  const scratchNdc = useMemo(() => new THREE.Vector2(), []);
  const scratchRight = useMemo(() => new THREE.Vector3(), []);
  const scratchUp = useMemo(() => new THREE.Vector3(), []);
  const scratchForward = useMemo(() => new THREE.Vector3(), []);
  const raycasterRef = useRef(new THREE.Raycaster());

  const boundsCenter = useMemo(
    () => new THREE.Vector3(bounds.center[0], bounds.center[1], bounds.center[2]),
    [bounds.center[0], bounds.center[1], bounds.center[2]], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const boundsRadius = useMemo(() => Math.max(1, bounds.size * 0.5), [bounds.size]);

  // ── Helpers ───────────────────────────────────────────────────────────────
  const getMouseNdc = (ev: { clientX: number; clientY: number }, out: THREE.Vector2) => {
    const rect = gl.domElement.getBoundingClientRect();
    out.set(
      ((ev.clientX - rect.left) / rect.width) * 2 - 1,
      -(((ev.clientY - rect.top) / rect.height) * 2 - 1),
    );
    return out;
  };

  const setCursor = (c: string) => {
    if (gl.domElement.style.cursor !== c) gl.domElement.style.cursor = c;
  };

  // Rebuild spherical (phi/theta/radius) so that camera-at-`cameraPos`
  // looks-at `newTarget`.
  const setSphericalFromLookAt = (cameraPos: THREE.Vector3, newTarget: THREE.Vector3) => {
    const dx = cameraPos.x - newTarget.x;
    const dy = cameraPos.y - newTarget.y;
    const dz = cameraPos.z - newTarget.z;
    const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
    if (r < 1e-4) return;
    spherical.current.radius = clamp(r, 20, 20000);
    spherical.current.phi = clamp(Math.acos(dy / r), 0.05, Math.PI - 0.05);
    spherical.current.theta = Math.atan2(dx, dz);
  };

  const startFlyTween = (
    toTarget: THREE.Vector3,
    toRadius: number,
    toPhi: number,
    toTheta: number,
    durationMs = 1200,
  ) => {
    flyTween.current = {
      start: performance.now(),
      duration: durationMs,
      fromTarget: target.current.clone(),
      toTarget: toTarget.clone(),
      fromRadius: spherical.current.radius, toRadius,
      fromPhi: spherical.current.phi, toPhi,
      fromTheta: spherical.current.theta, toTheta,
    };
    momentumActive.current = false;
    angularVel.current.theta = 0;
    angularVel.current.phi = 0;
    warpStart.current = null;
    lastInteractionAt.current = performance.now();
  };

  // Given a node position + desired viewing distance, compute the fly-to
  // spherical + target and start the tween. Viewing position is
  // `nodePos + normalize(currentCamPos - nodePos) * dist`.
  const flyToNode = (nodePos: THREE.Vector3, size: number) => {
    const dist = Math.max(80, size * 30);
    scratchViewingPos.copy(camera.position).sub(nodePos);
    if (scratchViewingPos.lengthSq() < 1) {
      scratchViewingPos.set(0, 0, dist); // camera at same point — just push +Z
    } else {
      scratchViewingPos.setLength(dist);
    }
    scratchViewingPos.add(nodePos);
    // Derive target-spherical from viewing pos → nodePos.
    const dx = scratchViewingPos.x - nodePos.x;
    const dy = scratchViewingPos.y - nodePos.y;
    const dz = scratchViewingPos.z - nodePos.z;
    const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
    const toPhi = clamp(Math.acos(dy / r), 0.05, Math.PI - 0.05);
    const toTheta = Math.atan2(dx, dz);
    startFlyTween(nodePos, dist, toPhi, toTheta, 1200);
    onFocusChangeRef.current?.(nodePos.clone());
  };

  // Raycast hitCandidates as spheres of radius `size * 2.5`. Returns nearest
  // hit or null.
  const pickNodeAtMouse = (clientX: number, clientY: number): HitCandidate | null => {
    if (!hitCandidates || hitCandidates.length === 0) return null;
    getMouseNdc({ clientX, clientY }, scratchNdc);
    raycasterRef.current.setFromCamera(scratchNdc, camera);
    const ray = raycasterRef.current.ray;
    let best: HitCandidate | null = null;
    let bestT = Infinity;
    for (const c of hitCandidates) {
      const threshold = c.size * 2.5;
      const ocx = c.position.x - ray.origin.x;
      const ocy = c.position.y - ray.origin.y;
      const ocz = c.position.z - ray.origin.z;
      const proj = ocx * ray.direction.x + ocy * ray.direction.y + ocz * ray.direction.z;
      if (proj < 0) continue;
      const d2 = ocx * ocx + ocy * ocy + ocz * ocz - proj * proj;
      if (d2 > threshold * threshold) continue;
      if (proj < bestT) { bestT = proj; best = c; }
    }
    return best;
  };

  // ── External `focus` prop → start a fly-tween ─────────────────────────────
  useEffect(() => {
    if (!focus) return;
    const dist = focus.distance ?? 220;
    // Derive spherical from a viewing pos that keeps current view direction.
    scratchViewingPos.copy(camera.position).sub(focus.position);
    if (scratchViewingPos.lengthSq() < 1) scratchViewingPos.set(0, 0, dist);
    else scratchViewingPos.setLength(dist);
    scratchViewingPos.add(focus.position);
    const dx = scratchViewingPos.x - focus.position.x;
    const dy = scratchViewingPos.y - focus.position.y;
    const dz = scratchViewingPos.z - focus.position.z;
    const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
    const toPhi = clamp(Math.acos(dy / r), 0.05, Math.PI - 0.05);
    const toTheta = Math.atan2(dx, dz);
    startFlyTween(focus.position, dist, toPhi, toTheta, 1200);
  }, [focus]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (fitSignal === lastFitSignal.current) return;
    lastFitSignal.current = fitSignal;
    startFlyTween(boundsCenter, fitDistance, Math.PI * 0.42, Math.PI * 0.25, 850);
  }, [fitSignal, boundsCenter, fitDistance]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── DOM handlers (rotate / pan / wheel / dblclick / keys) ────────────────
  useEffect(() => {
    const dom = gl.domElement;
    setCursor("grab");
    dom.style.touchAction = "none";

    const onDown = (ev: PointerEvent) => {
      activePointers.current.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
      if (activePointers.current.size >= 2) {
        const [a, b] = [...activePointers.current.values()];
        pinchState.current = {
          distance: Math.max(1, Math.hypot(b.x - a.x, b.y - a.y)),
          x: (a.x + b.x) * 0.5,
          y: (a.y + b.y) * 0.5,
        };
        dragMode.current = "pinch";
      } else if (ev.button === 2 || ev.shiftKey || ev.altKey) {
        // 0=left, 1=middle, 2=right.
        dragMode.current = "pan";
      } else if (ev.button === 0) {
        dragMode.current = "rotate";
      } else {
        return;
      }
      lastMouse.current = { x: ev.clientX, y: ev.clientY };
      lastInteractionAt.current = performance.now();
      warpStart.current = null;
      flyTween.current = null;
      momentumActive.current = false;
      angularVel.current.theta = 0;
      angularVel.current.phi = 0;
      setCursor(dragMode.current === "pan" ? "crosshair" : "grabbing");
      (dom as any).setPointerCapture?.(ev.pointerId);
    };

    const onMove = (ev: PointerEvent) => {
      if (activePointers.current.has(ev.pointerId)) {
        activePointers.current.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
      }
      if (activePointers.current.size >= 2) {
        const [a, b] = [...activePointers.current.values()];
        const next = {
          distance: Math.max(1, Math.hypot(b.x - a.x, b.y - a.y)),
          x: (a.x + b.x) * 0.5,
          y: (a.y + b.y) * 0.5,
        };
        const prev = pinchState.current;
        if (prev) {
          spherical.current.radius = clamp(
            spherical.current.radius * clamp(prev.distance / next.distance, 0.8, 1.2),
            20,
            20000,
          );
          camera.getWorldDirection(scratchForward);
          scratchRight.crossVectors(scratchForward, camera.up).normalize();
          scratchUp.crossVectors(scratchRight, scratchForward).normalize();
          const rect = gl.domElement.getBoundingClientRect();
          const worldPerPixel = (spherical.current.radius * 2) / Math.max(200, rect.height);
          target.current.addScaledVector(scratchRight, -(next.x - prev.x) * worldPerPixel);
          target.current.addScaledVector(scratchUp, (next.y - prev.y) * worldPerPixel);
        }
        pinchState.current = next;
        dragMode.current = "pinch";
        lastInteractionAt.current = performance.now();
        flyTween.current = null;
        return;
      }
      if (dragMode.current === "none" || !lastMouse.current) return;
      const dx = ev.clientX - lastMouse.current.x;
      const dy = ev.clientY - lastMouse.current.y;
      lastMouse.current = { x: ev.clientX, y: ev.clientY };
      lastInteractionAt.current = performance.now();

      if (dragMode.current === "rotate") {
        const dTheta = -dx * 0.005;
        const dPhi = -dy * 0.005;
        spherical.current.theta += dTheta;
        spherical.current.phi = clamp(spherical.current.phi + dPhi, 0.05, Math.PI - 0.05);
        // Track velocity for momentum (blend for smoothness).
        angularVel.current.theta = angularVel.current.theta * 0.5 + dTheta * 0.5;
        angularVel.current.phi   = angularVel.current.phi   * 0.5 + dPhi   * 0.5;
      } else if (dragMode.current === "pan") {
        // Camera-space right/up scaled by current radius so pan speed is
        // proportional to zoom level.
        camera.getWorldDirection(scratchForward);
        scratchRight.crossVectors(scratchForward, camera.up).normalize();
        scratchUp.crossVectors(scratchRight, scratchForward).normalize();
        const rect = gl.domElement.getBoundingClientRect();
        const worldPerPixel = (spherical.current.radius * 2) / Math.max(200, rect.height);
        target.current.addScaledVector(scratchRight, -dx * worldPerPixel);
        target.current.addScaledVector(scratchUp,     dy * worldPerPixel);
      }
    };

    const onUp = (ev: PointerEvent) => {
      if (dragMode.current === "rotate") {
        // Kick off momentum if we've got meaningful velocity.
        if (Math.abs(angularVel.current.theta) + Math.abs(angularVel.current.phi) > 0.001) {
          momentumActive.current = true;
        }
      }
      activePointers.current.delete(ev.pointerId);
      pinchState.current = null;
      const remaining = [...activePointers.current.values()][0];
      dragMode.current = remaining ? "rotate" : "none";
      lastMouse.current = remaining ?? null;
      lastPointerUpAt.current = performance.now();
      setCursor("grab");
      (dom as any).releasePointerCapture?.(ev.pointerId);
    };

    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      // Cast a ray from the cursor into a virtual sphere around the graph.
      // The intersection is our "zoom pivot" — camera and target both move
      // toward/away from this point so zoom feels toward what you're pointing at.
      getMouseNdc(ev, scratchNdc);
      raycasterRef.current.setFromCamera(scratchNdc, camera);
      scratchOrigin.copy(raycasterRef.current.ray.origin);
      scratchDir.copy(raycasterRef.current.ray.direction);
      const hit = raySphereFirst(scratchOrigin, scratchDir, boundsCenter, boundsRadius, scratchHit)
        ?? scratchHit.copy(scratchDir).multiplyScalar(spherical.current.radius).add(scratchOrigin);

      const normalizedDelta = ev.deltaY * (ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? 120 : 1);
      const factor = clamp(Math.exp(normalizedDelta * 0.0012), 0.65, 1.55);
      // Move camera and target toward hit by (1 - factor) fraction.
      // newCam = lerp(hit, cam, factor); newTarget = lerp(hit, target, factor).
      const camPos = camera.position;
      const newCamX = hit.x + (camPos.x - hit.x) * factor;
      const newCamY = hit.y + (camPos.y - hit.y) * factor;
      const newCamZ = hit.z + (camPos.z - hit.z) * factor;
      target.current.set(
        hit.x + (target.current.x - hit.x) * factor,
        hit.y + (target.current.y - hit.y) * factor,
        hit.z + (target.current.z - hit.z) * factor,
      );
      // Rebuild spherical from the new (cam, target) pair.
      scratchViewingPos.set(newCamX, newCamY, newCamZ);
      setSphericalFromLookAt(scratchViewingPos, target.current);

      lastInteractionAt.current = performance.now();
      warpStart.current = null;
      flyTween.current = null;
    };

    const onDblClick = (ev: MouseEvent) => {
      const hit = pickNodeAtMouse(ev.clientX, ev.clientY);
      if (!hit) return;
      ev.preventDefault();
      flyToNode(hit.position, hit.size);
      onDoubleClickNodeRef.current?.(hit.id);
    };

    const onContextMenu = (ev: MouseEvent) => {
      // Suppress the native menu so right-drag pan can breathe.
      ev.preventDefault();
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      // Ignore if focus is inside an editable element.
      const t = ev.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      const k = ev.key.toLowerCase();
      keys.current.add(k);
      if (k === " " || k === "home" || k === "0") {
        // Reset to fit-bounds.
        startFlyTween(
          boundsCenter,
          fitDistance,
          Math.PI * 0.42,
          Math.PI * 0.25,
          1000,
        );
        ev.preventDefault();
      } else if (k === "f" && focusRef.current) {
        // Re-focus current focus target.
        const f = focusRef.current;
        const dist = f.distance ?? 220;
        scratchViewingPos.copy(camera.position).sub(f.position);
        if (scratchViewingPos.lengthSq() < 1) scratchViewingPos.set(0, 0, dist);
        else scratchViewingPos.setLength(dist);
        scratchViewingPos.add(f.position);
        const dx = scratchViewingPos.x - f.position.x;
        const dy = scratchViewingPos.y - f.position.y;
        const dz = scratchViewingPos.z - f.position.z;
        const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
        const toPhi = clamp(Math.acos(dy / r), 0.05, Math.PI - 0.05);
        const toTheta = Math.atan2(dx, dz);
        startFlyTween(f.position, dist, toPhi, toTheta, 1000);
        ev.preventDefault();
      } else if (k === "=" || k === "+" || k === "-" || k === "_") {
        const factor = k === "=" || k === "+" ? 0.82 : 1.22;
        spherical.current.radius = clamp(spherical.current.radius * factor, 20, 20000);
        flyTween.current = null;
        warpStart.current = null;
        ev.preventDefault();
      } else if (k.startsWith("arrow") || k === "pageup" || k === "pagedown") {
        ev.preventDefault();
      }
      lastInteractionAt.current = performance.now();
    };
    const onKeyUp = (ev: KeyboardEvent) => {
      keys.current.delete(ev.key.toLowerCase());
    };

    dom.addEventListener("pointerdown", onDown);
    dom.addEventListener("pointermove", onMove);
    dom.addEventListener("pointerup", onUp);
    dom.addEventListener("pointercancel", onUp);
    dom.addEventListener("wheel", onWheel, { passive: false });
    dom.addEventListener("dblclick", onDblClick);
    dom.addEventListener("contextmenu", onContextMenu);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    return () => {
      dom.removeEventListener("pointerdown", onDown);
      dom.removeEventListener("pointermove", onMove);
      dom.removeEventListener("pointerup", onUp);
      dom.removeEventListener("pointercancel", onUp);
      dom.removeEventListener("wheel", onWheel as any);
      dom.removeEventListener("dblclick", onDblClick);
      dom.removeEventListener("contextmenu", onContextMenu);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
    };
  }, [gl, camera, boundsCenter, boundsRadius, fitDistance, hitCandidates]); // eslint-disable-line react-hooks/exhaustive-deps

  // Kick off warp-in on first frame.
  useEffect(() => {
    warpStart.current = performance.now();
  }, []);

  useFrame((_state, delta) => {
    const now = performance.now();

    // 1. Warp-in.
    if (warpStart.current != null) {
      const t = clamp((now - warpStart.current) / WARP_MS, 0, 1);
      const k = 1 - Math.pow(1 - t, 3);
      spherical.current.radius = 8000 + (fitDistance - 8000) * k;
      spherical.current.theta = 0 + (Math.PI * 0.25) * k;
      spherical.current.phi = Math.PI * 0.42 + (Math.PI * 0.06) * k;
      target.current.set(
        bounds.center[0] * k,
        bounds.center[1] * k,
        bounds.center[2] * k,
      );
      if (t >= 1) warpStart.current = null;
    }

    // 2. Fly-to tween.
    if (flyTween.current) {
      const ft = flyTween.current;
      const t = clamp((now - ft.start) / ft.duration, 0, 1);
      const k = easeInOutCubic(t);
      target.current.set(
        ft.fromTarget.x + (ft.toTarget.x - ft.fromTarget.x) * k,
        ft.fromTarget.y + (ft.toTarget.y - ft.fromTarget.y) * k,
        ft.fromTarget.z + (ft.toTarget.z - ft.fromTarget.z) * k,
      );
      spherical.current.radius = ft.fromRadius + (ft.toRadius - ft.fromRadius) * k;
      spherical.current.phi    = ft.fromPhi    + (ft.toPhi    - ft.fromPhi)    * k;
      // Shortest-arc theta interpolation to avoid taking the long way round.
      let dTheta = ft.toTheta - ft.fromTheta;
      while (dTheta > Math.PI) dTheta -= 2 * Math.PI;
      while (dTheta < -Math.PI) dTheta += 2 * Math.PI;
      spherical.current.theta = ft.fromTheta + dTheta * k;
      if (t >= 1) flyTween.current = null;
    }

    // 3. Momentum.
    if (momentumActive.current && dragMode.current === "none" && !flyTween.current) {
      spherical.current.theta += angularVel.current.theta;
      spherical.current.phi = clamp(
        spherical.current.phi + angularVel.current.phi,
        0.05, Math.PI - 0.05,
      );
      angularVel.current.theta *= 0.94;
      angularVel.current.phi   *= 0.94;
      if (Math.abs(angularVel.current.theta) + Math.abs(angularVel.current.phi) < 0.0002) {
        momentumActive.current = false;
        angularVel.current.theta = 0;
        angularVel.current.phi = 0;
      }
    }

    // 4. Keyboard nudging of target (view-plane + world-Y).
    if (keys.current.size > 0 && dragMode.current === "none") {
      const speed = spherical.current.radius * 0.5 * delta;
      camera.getWorldDirection(scratchForward);
      scratchRight.crossVectors(scratchForward, camera.up).normalize();
      scratchUp.crossVectors(scratchRight, scratchForward).normalize();
      if (keys.current.has("w") || keys.current.has("arrowup")) target.current.addScaledVector(scratchForward,  speed);
      if (keys.current.has("s") || keys.current.has("arrowdown")) target.current.addScaledVector(scratchForward, -speed);
      if (keys.current.has("a") || keys.current.has("arrowleft")) target.current.addScaledVector(scratchRight,   -speed);
      if (keys.current.has("d") || keys.current.has("arrowright")) target.current.addScaledVector(scratchRight,    speed);
      if (keys.current.has("e") || keys.current.has("pageup")) target.current.y += speed;
      if (keys.current.has("q") || keys.current.has("pagedown")) target.current.y -= speed;
      lastInteractionAt.current = now;
    }

    // 5. Auto-orbit (idle > 4s, no drag, no tween, no momentum).
    const idleMs = now - lastInteractionAt.current;
    if (
      autoOrbit &&
      idleMs > 4000 &&
      warpStart.current == null &&
      !flyTween.current &&
      !momentumActive.current &&
      dragMode.current === "none"
    ) {
      spherical.current.theta += 0.01 * delta;
    }

    // Compose final camera position from spherical + target.
    const { radius, phi, theta } = spherical.current;
    const sinPhi = Math.sin(phi);
    const x = target.current.x + radius * sinPhi * Math.sin(theta);
    const y = target.current.y + radius * Math.cos(phi);
    const z = target.current.z + radius * sinPhi * Math.cos(theta);
    camera.position.set(x, y, z);
    camera.lookAt(target.current);
    camera.updateMatrixWorld();
  });

  return null;
}
