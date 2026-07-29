import { useEffect, useRef } from "react";
import type * as THREE from "three";
import type { Entity } from "../lib/types";

// Local palette — mirrors GraphThreeV3.GALAXY_COLORS (kept in sync, not imported
// to keep this component decoupled from the 3D scene).
const KIND_COLORS: Record<string, string> = {
  techniques:    "#ff2244",
  internals:     "#00f0ff",
  defenses:      "#39ff14",
  chains:        "#ffb700",
  evidence:      "#00e5ff",
  sources:       "#e040fb",
  gaps:          "#ff5555",
  architecture:  "#9d4edd",
  tradecraft_qa: "#00e5bf",
};

interface Props {
  entities: Entity[];
  cameraRef: React.MutableRefObject<THREE.Camera | null>;
  onTeleport: (x: number, z: number) => void;
}

// Half-extent in world units mapped to half the minimap edge. Slightly padded
// so nodes at the extremes aren't clipped by the border.
const UNIVERSE_HALF = 2500;
const MAP_SIZE = 200;

function worldToMap(x: number, z: number): [number, number] {
  const nx = (x / UNIVERSE_HALF) * 0.5 + 0.5;
  const nz = (z / UNIVERSE_HALF) * 0.5 + 0.5;
  return [nx * MAP_SIZE, nz * MAP_SIZE];
}

function mapToWorld(px: number, pz: number): [number, number] {
  const nx = (px / MAP_SIZE) * 2 - 1;
  const nz = (pz / MAP_SIZE) * 2 - 1;
  return [nx * UNIVERSE_HALF, nz * UNIVERSE_HALF];
}

export default function Minimap({ entities, cameraRef, onTeleport }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);

  // Cache dot list to avoid recomputing every frame — only redo when entity
  // list identity changes.
  const dotsRef = useRef<{ x: number; y: number; color: string }[]>([]);
  useEffect(() => {
    const dots: { x: number; y: number; color: string }[] = [];
    for (const e of entities) {
      const p = e.position;
      if (!p) continue;
      const [mx, my] = worldToMap(p.x, p.z);
      if (mx < 0 || mx > MAP_SIZE || my < 0 || my > MAP_SIZE) continue;
      dots.push({
        x: mx,
        y: my,
        color: KIND_COLORS[e.galaxyId] || "rgba(255,255,255,0.6)",
      });
    }
    dotsRef.current = dots;
  }, [entities]);

  useEffect(() => {
    const c = canvasRef.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;

    const draw = () => {
      ctx.clearRect(0, 0, MAP_SIZE, MAP_SIZE);

      // Faint radial bg — hints at the universe's roughly-spherical shape.
      const grd = ctx.createRadialGradient(MAP_SIZE / 2, MAP_SIZE / 2, 10, MAP_SIZE / 2, MAP_SIZE / 2, MAP_SIZE / 2);
      grd.addColorStop(0, "rgba(60,80,120,0.10)");
      grd.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, MAP_SIZE, MAP_SIZE);

      // Dots.
      const dots = dotsRef.current;
      for (let i = 0; i < dots.length; i++) {
        const d = dots[i];
        ctx.fillStyle = d.color;
        ctx.globalAlpha = 0.75;
        ctx.beginPath();
        ctx.arc(d.x, d.y, 1.2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;

      // Camera frustum approximation.
      const cam = cameraRef.current;
      if (cam) {
        const [cx, cy] = worldToMap(cam.position.x, cam.position.z);
        const heightAbs = Math.max(200, Math.abs(cam.position.y));
        // Rough view size — higher camera = wider footprint on the map.
        const viewWorld = Math.min(4000, heightAbs * 0.9);
        const viewPx = (viewWorld / UNIVERSE_HALF) * 0.5 * MAP_SIZE;
        ctx.strokeStyle = "rgba(157,124,244,0.78)";
        ctx.lineWidth = 1;
        ctx.fillStyle = "rgba(157,124,244,0.10)";
        ctx.fillRect(cx - viewPx / 2, cy - viewPx / 2, viewPx, viewPx);
        ctx.strokeRect(cx - viewPx / 2, cy - viewPx / 2, viewPx, viewPx);

        // Camera dot — violet accent (matches --nav-accent).
        ctx.fillStyle = "#9d7cf4";
        ctx.beginPath();
        ctx.arc(cx, cy, 2.5, 0, Math.PI * 2);
        ctx.fill();
      }

      // "MAP" label.
      ctx.fillStyle = "rgba(255,255,255,0.4)";
      ctx.font = "9px monospace";
      ctx.fillText("MAP", 8, 14);

      rafRef.current = requestAnimationFrame(draw);
    };
    rafRef.current = requestAnimationFrame(draw);
    return () => { if (rafRef.current != null) cancelAnimationFrame(rafRef.current); };
  }, [cameraRef]);

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const c = canvasRef.current;
    if (!c) return;
    const rect = c.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * MAP_SIZE;
    const py = ((e.clientY - rect.top) / rect.height) * MAP_SIZE;
    const [wx, wz] = mapToWorld(px, py);
    onTeleport(wx, wz);
  };

  return (
    <div
      style={{
        position: "absolute",
        bottom: 16,
        right: 16,
        zIndex: 25,
        borderRadius: 8,
        border: "1px solid rgba(255,255,255,0.15)",
        background: "rgba(10,10,20,0.55)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        overflow: "hidden",
        boxShadow: "0 4px 24px rgba(0,0,0,0.5)",
      }}
    >
      <canvas
        ref={canvasRef}
        width={MAP_SIZE}
        height={MAP_SIZE}
        onClick={handleClick}
        style={{ display: "block", width: MAP_SIZE, height: MAP_SIZE, cursor: "crosshair" }}
      />
    </div>
  );
}
