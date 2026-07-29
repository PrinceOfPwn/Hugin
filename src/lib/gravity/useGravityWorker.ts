import { useCallback, useEffect, useRef, useState } from "react";
import type { GravityBodyInput, GravityConfig, PhysicsMetrics } from "./physics";

export type GravityWorkerState = {
  ready: boolean;
  positions: Float32Array | null;
  velocities: Float32Array | null;
  metrics: PhysicsMetrics | null;
};

export function useGravityWorker(bodies: GravityBodyInput[], config: Partial<GravityConfig>, enabled: boolean) {
  const workerRef = useRef<Worker | null>(null);
  const [state, setState] = useState<GravityWorkerState>({ ready: false, positions: null, velocities: null, metrics: null });
  useEffect(() => {
    if (!enabled || bodies.length === 0) return;
    const worker = new Worker(new URL("./gravity.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    worker.onmessage = ({ data }) => {
      if (data.type === "ready") setState((s) => ({ ...s, ready: true }));
      if (data.type === "frame") setState({ ready: true, positions: data.positions, velocities: data.velocities, metrics: data.metrics });
    };
    worker.postMessage({ type: "start", bodies, config });
    return () => { worker.terminate(); if (workerRef.current === worker) workerRef.current = null; };
  // The caller intentionally passes memoized bodies/config. Restarting resets a scenario.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, bodies]);

  const run = useCallback((running: boolean, timeScale = 1) => workerRef.current?.postMessage({ type: "run", running, timeScale }), []);
  const configure = useCallback((next: Partial<GravityConfig>) => workerRef.current?.postMessage({ type: "configure", config: next }), []);
  const setBody = useCallback((index: number, position: [number, number, number], velocity?: [number, number, number]) => workerRef.current?.postMessage({ type: "set-body", index, position, velocity }), []);
  const setActive = useCallback((center?: [number, number, number]) => workerRef.current?.postMessage({ type: "active", center }), []);
  const reset = useCallback(() => workerRef.current?.postMessage({ type: "start", bodies, config }), [bodies, config]);
  return { ...state, run, configure, setBody, setActive, reset };
}
