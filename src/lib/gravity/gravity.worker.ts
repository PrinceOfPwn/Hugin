/// <reference lib="webworker" />
import { GravityEngine, type GravityBodyInput, type GravityConfig } from "./physics";

type StartMessage = { type: "start"; bodies: GravityBodyInput[]; config?: Partial<GravityConfig> };
type ConfigureMessage = { type: "configure"; config: Partial<GravityConfig> };
type SetBodyMessage = { type: "set-body"; index: number; position: [number, number, number]; velocity?: [number, number, number] };
type RunMessage = { type: "run"; running: boolean; timeScale?: number };
type ActiveMessage = { type: "active"; center?: [number, number, number] };
type InMessage = StartMessage | ConfigureMessage | SetBodyMessage | RunMessage | ActiveMessage;

let engine: GravityEngine | null = null;
let running = false;
let timeScale = 1;
let timer: number | null = null;

function tick() {
  if (!engine || !running) return;
  const config = engine.getConfig();
  const steps = Math.max(1, Math.min(8, Math.round(timeScale / (config.fixedDt * 30))));
  const metrics = engine.step(steps);
  const positions = new Float32Array(engine.positions.length);
  const velocities = new Float32Array(engine.velocities.length);
  for (let i = 0; i < positions.length; i++) { positions[i] = engine.positions[i]; velocities[i] = engine.velocities[i]; }
  postMessage({ type: "frame", metrics, positions, velocities }, [positions.buffer, velocities.buffer]);
}

self.onmessage = ({ data }: MessageEvent<InMessage>) => {
  if (data.type === "start") {
    engine = new GravityEngine(data.bodies, data.config);
    postMessage({ type: "ready", bodyCount: data.bodies.length, config: engine.getConfig() });
    if (timer === null) timer = self.setInterval(tick, 1000 / 30);
  } else if (!engine) return;
  else if (data.type === "configure") engine.setConfig(data.config);
  else if (data.type === "set-body") engine.setBodyState(data.index, data.position, data.velocity);
  else if (data.type === "active") engine.setActiveBodies(data.center);
  else if (data.type === "run") { running = data.running; timeScale = data.timeScale ?? timeScale; }
};

export {};
