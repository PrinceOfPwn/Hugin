import { useEffect, useRef, useState } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import { Html } from "@react-three/drei";
import * as THREE from "three";

interface Props {
  active: boolean;
  onExit?: () => void;
  initialPosition?: THREE.Vector3;
  worldUp?: THREE.Vector3;
}

const KEYS = {
  forward: ["KeyW"],
  back: ["KeyS"],
  left: ["KeyA"],
  right: ["KeyD"],
  rollL: ["KeyQ"],
  rollR: ["KeyE"],
  up: ["Space"],
  down: ["ShiftLeft", "ShiftRight"],
  boost: ["ShiftLeft", "ShiftRight"],
};

function FreeFlyCamera({ active, onExit, initialPosition, worldUp }: Props) {
  const { camera, gl } = useThree();
  const pressed = useRef<Set<string>>(new Set());
  const velocity = useRef(new THREE.Vector3());
  const roll = useRef(0);
  const yaw = useRef(0);
  const pitch = useRef(0);
  const locked = useRef(false);
  const [visible, setVisible] = useState(false);
  const [speed, setSpeed] = useState(0);

  useEffect(() => {
    if (!active) return;
    const canvas = gl.domElement;

    if (initialPosition) camera.position.copy(initialPosition);
    const euler = new THREE.Euler().setFromQuaternion(camera.quaternion, "YXZ");
    yaw.current = euler.y;
    pitch.current = euler.x;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.code === "Escape") { document.exitPointerLock?.(); return; }
      pressed.current.add(e.code);
    };
    const onKeyUp = (e: KeyboardEvent) => pressed.current.delete(e.code);

    const onMouseMove = (e: MouseEvent) => {
      if (!locked.current) return;
      const s = 0.0022;
      yaw.current -= e.movementX * s;
      pitch.current -= e.movementY * s;
      const lim = Math.PI / 2 - 0.02;
      if (pitch.current > lim) pitch.current = lim;
      if (pitch.current < -lim) pitch.current = -lim;
    };

    const onClick = () => { if (!locked.current) canvas.requestPointerLock(); };
    const onLockChange = () => {
      locked.current = document.pointerLockElement === canvas;
      setVisible(locked.current);
      if (!locked.current) onExit?.();
    };

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    window.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("click", onClick);
    document.addEventListener("pointerlockchange", onLockChange);

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      window.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("click", onClick);
      document.removeEventListener("pointerlockchange", onLockChange);
      if (document.pointerLockElement === canvas) document.exitPointerLock?.();
    };
  }, [active, camera, gl, initialPosition, onExit]);

  const up = worldUp ?? new THREE.Vector3(0, 1, 0);
  const forwardVec = useRef(new THREE.Vector3());
  const rightVec = useRef(new THREE.Vector3());
  const upVec = useRef(new THREE.Vector3());
  const q = useRef(new THREE.Quaternion());

  useFrame((_, dt) => {
    if (!active) return;

    q.current.setFromEuler(new THREE.Euler(pitch.current, yaw.current, roll.current, "YXZ"));
    camera.quaternion.copy(q.current);

    forwardVec.current.set(0, 0, -1).applyQuaternion(camera.quaternion);
    rightVec.current.set(1, 0, 0).applyQuaternion(camera.quaternion);
    upVec.current.copy(up);

    const held = pressed.current;
    const boost = KEYS.boost.some(k => held.has(k)) && (held.has("KeyW") || held.has("KeyS") || held.has("KeyA") || held.has("KeyD")) ? 2.0 : 1.0;
    const accel = 60 * boost * dt;

    if (KEYS.forward.some(k => held.has(k))) velocity.current.addScaledVector(forwardVec.current, accel);
    if (KEYS.back.some(k => held.has(k)))    velocity.current.addScaledVector(forwardVec.current, -accel);
    if (KEYS.right.some(k => held.has(k)))   velocity.current.addScaledVector(rightVec.current, accel);
    if (KEYS.left.some(k => held.has(k)))    velocity.current.addScaledVector(rightVec.current, -accel);
    if (held.has("Space"))                   velocity.current.addScaledVector(upVec.current, accel);
    if (KEYS.down.some(k => held.has(k)) && !held.has("KeyW") && !held.has("KeyS") && !held.has("KeyA") && !held.has("KeyD"))
      velocity.current.addScaledVector(upVec.current, -accel);

    if (held.has("KeyQ")) roll.current += 1.8 * dt;
    if (held.has("KeyE")) roll.current -= 1.8 * dt;
    roll.current *= 0.96;

    velocity.current.multiplyScalar(0.94);
    camera.position.addScaledVector(velocity.current, dt);

    setSpeed(velocity.current.length());
  });

  if (!visible) return null;

  const cx = Math.round(camera.position.x);
  const cy = Math.round(camera.position.y);
  const cz = Math.round(camera.position.z);

  return (
    <Html fullscreen style={{ pointerEvents: "none" }}>
      <div style={{
        position: "absolute", inset: 0,
        color: "#9d7cf4", fontFamily: "monospace", fontSize: "12px",
        textShadow: "0 0 6px #9d7cf4",
      }}>
        <svg viewBox="-20 -20 40 40" width="40" height="40"
             style={{ position: "absolute", top: "50%", left: "50%",
                      transform: "translate(-50%, -50%)", opacity: 0.9 }}>
          <circle cx="0" cy="0" r="12" fill="none" stroke="#9d7cf4" strokeWidth="0.6" />
          <line x1="-16" y1="0" x2="-6" y2="0" stroke="#9d7cf4" strokeWidth="0.8" />
          <line x1="6" y1="0" x2="16" y2="0" stroke="#9d7cf4" strokeWidth="0.8" />
          <line x1="0" y1="-16" x2="0" y2="-6" stroke="#9d7cf4" strokeWidth="0.8" />
          <line x1="0" y1="6" x2="0" y2="16" stroke="#9d7cf4" strokeWidth="0.8" />
          <circle cx="0" cy="0" r="1.5" fill="#9d7cf4" />
        </svg>
        <div style={{ position: "absolute", bottom: 24, left: 24, textTransform: "uppercase", letterSpacing: "0.15em" }}>
          <div style={{ opacity: 0.65, fontSize: 10 }}>FREE FLIGHT MODE</div>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{speed.toFixed(1)} <span style={{ fontSize: 12, opacity: 0.7 }}>u/s</span></div>
          <div style={{ opacity: 0.6, fontSize: 10, marginTop: 6 }}>WASD · SPACE/SHIFT · Q/E · ESC to exit</div>
        </div>
        <div style={{ position: "absolute", top: 24, right: 24, textAlign: "right", letterSpacing: "0.1em" }}>
          <div style={{ opacity: 0.6, fontSize: 10 }}>COORDINATES</div>
          <div style={{ fontSize: 14 }}>X: {cx}</div>
          <div style={{ fontSize: 14 }}>Y: {cy}</div>
          <div style={{ fontSize: 14 }}>Z: {cz}</div>
        </div>
      </div>
    </Html>
  );
}

export default FreeFlyCamera;
