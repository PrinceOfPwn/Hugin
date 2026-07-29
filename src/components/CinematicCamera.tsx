import { useEffect, useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  // Bounding box of the universe — used for warp-in framing.
  bounds: {
    center: [number, number, number];
    size: number;
  };
  autoOrbit?: boolean;
  // Optional external focus target. When set, the camera tweens to look at
  // this point from `distance` away.
  focus?: { position: THREE.Vector3; distance?: number } | null;
}

// ═════════════════════════════════════════════════════════════════════════════
//  CinematicCamera
//
//  • Warp-in: on mount, animates camera from (0,0,8000) to a fit-bounds
//    framing around `center` over ~2.5s using an ease-out cubic.
//  • Manual: composes with a minimal orbit controls (mouse-drag rotates,
//    wheel zooms — no drei dependency). Pointer down pauses everything.
//  • Auto-orbit: after 4s of no interaction (and if `autoOrbit` is true),
//    the camera slowly precesses around the universe centroid at ~0.01 rad/s.
//  • Focus tween: when `focus` changes, animates the camera to observe that
//    point from `distance` away. This runs concurrently with (and overrides)
//    auto-orbit until the tween settles.
//
//  State is stored in spherical coords around a moveable target so all three
//  behaviors can coexist smoothly.
// ═════════════════════════════════════════════════════════════════════════════

const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));

export default function CinematicCamera({ bounds, autoOrbit = true, focus }: Props) {
  const { camera, gl } = useThree();

  // Target and spherical coords own the "current" camera state; useFrame
  // synthesises the final camera.position each tick.
  const target = useRef(new THREE.Vector3(...bounds.center));
  const spherical = useRef({
    // Start looking at the target from far along +Z during warp-in.
    radius: 8000,
    phi: Math.PI * 0.42,     // slight downward tilt
    theta: 0,
  });

  // Warp-in progress: 0..1 over ~2.5s.
  const warpStart = useRef<number | null>(null);
  const WARP_MS = 2500;

  // Target framing distance computed from bounds.size (fits sphere in view).
  const fitDistance = useMemo(() => {
    const fov = (camera as THREE.PerspectiveCamera).fov ?? 55;
    const half = bounds.size * 0.5;
    // add some breathing room
    return (half / Math.tan((fov * Math.PI) / 360)) * 1.15;
  }, [camera, bounds.size]);

  // Interaction bookkeeping — last time the user touched anything.
  const lastInteractionAt = useRef(performance.now() - 999_999); // sentinel: idle
  const isDragging = useRef(false);
  const lastMouse = useRef<{ x: number; y: number } | null>(null);

  // Focus tween state — when `focus` changes, we blend the current spherical
  // toward a "look at focus point" configuration for a few frames.
  const focusTweenActive = useRef(false);
  const desiredTarget = useRef(new THREE.Vector3(...bounds.center));
  const desiredRadius = useRef(fitDistance);

  useEffect(() => {
    if (!focus) return;
    desiredTarget.current.copy(focus.position);
    desiredRadius.current = focus.distance ?? 180;
    focusTweenActive.current = true;
    lastInteractionAt.current = performance.now();
  }, [focus]);

  // ── Manual orbit controls (raw DOM) ──────────────────────────────────────
  useEffect(() => {
    const dom = gl.domElement;

    const onDown = (ev: PointerEvent) => {
      if (ev.button !== 0) return;
      isDragging.current = true;
      lastMouse.current = { x: ev.clientX, y: ev.clientY };
      lastInteractionAt.current = performance.now();
      warpStart.current = null; // interrupt any warp
      focusTweenActive.current = false;
      (dom as any).setPointerCapture?.(ev.pointerId);
    };
    const onMove = (ev: PointerEvent) => {
      if (!isDragging.current || !lastMouse.current) return;
      const dx = ev.clientX - lastMouse.current.x;
      const dy = ev.clientY - lastMouse.current.y;
      lastMouse.current = { x: ev.clientX, y: ev.clientY };
      spherical.current.theta -= dx * 0.005;
      spherical.current.phi = clamp(spherical.current.phi - dy * 0.005, 0.05, Math.PI - 0.05);
      lastInteractionAt.current = performance.now();
    };
    const onUp = (ev: PointerEvent) => {
      isDragging.current = false;
      lastMouse.current = null;
      (dom as any).releasePointerCapture?.(ev.pointerId);
    };
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const factor = Math.exp(ev.deltaY * 0.0012);
      spherical.current.radius = clamp(spherical.current.radius * factor, 40, 12000);
      lastInteractionAt.current = performance.now();
      warpStart.current = null;
      focusTweenActive.current = false;
    };

    dom.addEventListener("pointerdown", onDown);
    dom.addEventListener("pointermove", onMove);
    dom.addEventListener("pointerup", onUp);
    dom.addEventListener("pointercancel", onUp);
    dom.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      dom.removeEventListener("pointerdown", onDown);
      dom.removeEventListener("pointermove", onMove);
      dom.removeEventListener("pointerup", onUp);
      dom.removeEventListener("pointercancel", onUp);
      dom.removeEventListener("wheel", onWheel as any);
    };
  }, [gl]);

  // Kick off warp-in on first frame.
  useEffect(() => {
    warpStart.current = performance.now();
  }, []);

  useFrame((_state, delta) => {
    const now = performance.now();

    // Warp-in: interpolate radius from 8000 → fitDistance and pull target to
    // bounds.center. Runs once, disabled by any user interaction.
    if (warpStart.current != null) {
      const t = clamp((now - warpStart.current) / WARP_MS, 0, 1);
      // ease-out cubic
      const k = 1 - Math.pow(1 - t, 3);
      spherical.current.radius = 8000 + (fitDistance - 8000) * k;
      spherical.current.theta = 0 + (Math.PI * 0.25) * k;
      spherical.current.phi = Math.PI * 0.42 + (Math.PI * 0.06) * k;
      // Interpolate target from origin to bounds.center (in case bounds
      // isn't at origin).
      target.current.set(
        bounds.center[0] * k,
        bounds.center[1] * k,
        bounds.center[2] * k,
      );
      if (t >= 1) warpStart.current = null;
    }

    // Focus tween: pull target and radius toward desired.
    if (focusTweenActive.current) {
      target.current.lerp(desiredTarget.current, 0.08);
      spherical.current.radius += (desiredRadius.current - spherical.current.radius) * 0.08;
      if (
        target.current.distanceTo(desiredTarget.current) < 0.5 &&
        Math.abs(spherical.current.radius - desiredRadius.current) < 1
      ) {
        focusTweenActive.current = false;
      }
    }

    // Auto-orbit: if idle for >4s and enabled, precess theta at ~0.01 rad/s.
    const idleMs = now - lastInteractionAt.current;
    if (autoOrbit && idleMs > 4000 && warpStart.current == null && !focusTweenActive.current) {
      spherical.current.theta += 0.01 * delta;
    }

    // Compose final camera position from spherical.
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
