import { useRef, useState, type ChangeEvent, type CSSProperties } from "react";
import { benchmarkDirectPairs, type CollisionEvent, type PhysicsMetrics, type SolverMode } from "../lib/gravity/physics";
import { exportScenario, importScenario, requestDurableStorage, saveScenario, type StoredScenario } from "../lib/gravity/scenario-store";

export interface GravityLabProps {
  open: boolean;
  onOpenChange(open: boolean): void;
  running: boolean;
  onRunningChange(running: boolean): void;
  solver: SolverMode;
  onSolverChange(solver: SolverMode): void;
  timeScale: number;
  onTimeScaleChange(value: number): void;
  activeLimit: number;
  onActiveLimitChange(value: number): void;
  bodyCount: number;
  metrics: PhysicsMetrics | null;
  lastCollisions: CollisionEvent[];
  onReset(): void;
  onSaveScenario(): StoredScenario;
  onImportScenario(scenario: StoredScenario): void;
}

const panel: CSSProperties = { position: "absolute", zIndex: 42, left: 16, bottom: 16, width: 330, maxHeight: "min(680px, calc(100vh - 110px))", overflowY: "auto", background: "rgba(3, 7, 18, .94)", border: "1px solid rgba(120, 176, 255, .42)", boxShadow: "0 18px 60px rgba(0,0,0,.48)", color: "#dfeaff", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 11 };
const section: CSSProperties = { padding: "12px 14px", borderTop: "1px solid rgba(140,180,255,.14)" };
const button: CSSProperties = { minHeight: 36, border: "1px solid rgba(140,180,255,.34)", background: "rgba(100,150,255,.08)", color: "#dfeaff", font: "inherit", fontSize: 10, padding: "6px 8px", cursor: "pointer" };

export default function GravityLabPanel(props: GravityLabProps) {
  const [status, setStatus] = useState("");
  const [confirmExact, setConfirmExact] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);
  const benchmark = benchmarkDirectPairs(props.bodyCount, 30);
  if (!props.open) return <button type="button" aria-label="Open Gravity Lab" onClick={() => props.onOpenChange(true)} style={{ ...button, position: "absolute", left: 16, bottom: 16, zIndex: 42, letterSpacing: ".12em" }}>GRAVITY LAB</button>;

  const save = async () => {
    try {
      const scenario = props.onSaveScenario();
      await saveScenario(scenario);
      const durable = await requestDurableStorage();
      setStatus(durable ? "Saved locally; durable storage granted." : "Saved locally; browser may evict storage under pressure.");
    } catch (error) { setStatus(`Could not save locally: ${error instanceof Error ? error.message : "unknown error"}`); }
  };
  const download = () => {
    const scenario = props.onSaveScenario();
    const url = URL.createObjectURL(new Blob([exportScenario(scenario)], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `${scenario.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.hugin-scenario.json`; anchor.click(); URL.revokeObjectURL(url);
  };
  const readImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (!file) return;
    try { props.onImportScenario(importScenario(await file.text())); setStatus(`Imported ${file.name}.`); }
    catch (error) { setStatus(`Import rejected: ${error instanceof Error ? error.message : "invalid scenario"}`); }
    event.target.value = "";
  };
  const requestSolver = (solver: SolverMode) => {
    if (solver !== "exact-n2") { setConfirmExact(false); props.onSolverChange(solver); return; }
    setConfirmExact(true);
  };

  return <aside aria-label="Gravity Lab controls" style={panel}>
    <header style={{ padding: "14px", display: "flex", justifyContent: "space-between", gap: 8, background: "linear-gradient(135deg, rgba(44,93,195,.22), transparent)" }}>
      <div><div style={{ color: "#9ecbff", letterSpacing: ".16em", fontSize: 10 }}>HUGIN GRAVITY LAB</div><div style={{ marginTop: 5, opacity: .72, fontFamily: "system-ui, sans-serif", fontSize: 12 }}>Local, reversible simulation — never canonical data.</div></div>
      <button type="button" aria-label="Close Gravity Lab" onClick={() => props.onOpenChange(false)} style={button}>×</button>
    </header>
    <div style={section}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <button type="button" onClick={() => props.onRunningChange(!props.running)} style={button}>{props.running ? "PAUSE" : "RUN"}</button>
        <button type="button" onClick={props.onReset} style={button}>RESET</button>
        <button type="button" onClick={save} style={button}>SAVE LOCAL</button>
        <button type="button" onClick={download} style={button}>EXPORT</button>
        <button type="button" onClick={() => importRef.current?.click()} style={button}>IMPORT</button>
      </div>
      {status && <p role="status" style={{ margin: "8px 0 0", color: "#9ecbff", lineHeight: 1.45 }}>{status}</p>}
    </div>
    <div style={section}>
      <label>Solver
        <select value={props.solver} onChange={(e) => requestSolver(e.target.value as SolverMode)} style={{ display: "block", width: "100%", minHeight: 40, marginTop: 5, background: "#080e1e", color: "#dfeaff", border: "1px solid rgba(140,180,255,.3)", padding: 7 }}>
          <option value="adaptive">Adaptive neighborhood</option>
          <option value="all-barnes-hut">All bodies — Barnes-Hut</option>
          <option value="exact-n2">Exact N² — research</option>
        </select>
      </label>
      {confirmExact && <div role="alert" style={{ marginTop: 8, padding: 8, border: "1px solid #805f35", color: "#ffd785", lineHeight: 1.45 }}>This runs {benchmark.pairsPerStep.toLocaleString()} direct pairs per step ({benchmark.pairEvaluationsPerSecond.toLocaleString()}/s target). It may make this tab unresponsive on ordinary hardware.<br /><button type="button" style={{ ...button, marginTop: 7 }} onClick={() => { props.onSolverChange("exact-n2"); setConfirmExact(false); }}>I UNDERSTAND — ENABLE EXACT</button></div>}
      {props.solver === "exact-n2" && <p style={{ margin: "8px 0 0", color: "#ffd785", lineHeight: 1.45 }}>Direct all-body CPU worker mode. Fixed timestep is retained; frame rate may fall instead of silently lowering fidelity.</p>}
    </div>
    <div style={section}>
      <label>Time scale · {props.timeScale.toFixed(1)}×<input aria-label="Simulation time scale" type="range" min="0.1" max="12" step="0.1" value={props.timeScale} onChange={(e) => props.onTimeScaleChange(Number(e.target.value))} style={{ width: "100%" }} /></label>
      {props.solver === "adaptive" && <label style={{ display: "block", marginTop: 8 }}>Active bodies · {props.activeLimit}<input aria-label="Active simulated bodies" type="range" min="32" max="1024" step="32" value={props.activeLimit} onChange={(e) => props.onActiveLimitChange(Number(e.target.value))} style={{ width: "100%" }} /></label>}
    </div>
    <div style={section}>
      <div style={{ color: "#9ecbff", letterSpacing: ".13em", fontSize: 9, marginBottom: 7 }}>TELEMETRY</div>
      {props.metrics ? <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "5px 12px" }}>
        <span>Body field</span><strong>{props.metrics.activeBodies.toLocaleString()} / {props.metrics.bodyCount.toLocaleString()}</strong>
        <span>Pair evaluations</span><strong>{props.metrics.pairEvaluations.toLocaleString()}</strong>
        <span>Simulation time</span><strong>{props.metrics.simulationTime.toFixed(2)} HU</strong>
        <span>Kinetic energy</span><strong>{props.metrics.kineticEnergy.toFixed(3)} HEU</strong>
        <span>Potential energy</span><strong>{props.metrics.potentialEnergy?.toFixed(3) ?? "—"} HEU</strong>
      </div> : <span style={{ opacity: .65 }}>Initialize the local simulation to see metrics.</span>}
    </div>
    <div style={section}>
      <div style={{ color: "#9ecbff", letterSpacing: ".13em", fontSize: 9, marginBottom: 7 }}>LAST EVENTS</div>
      {props.lastCollisions.length ? props.lastCollisions.slice(-4).reverse().map((event, i) => <div key={`${event.a}:${event.b}:${i}`} style={{ padding: "5px 0", borderTop: i ? "1px solid rgba(140,180,255,.1)" : undefined }}><strong>{event.outcome.toUpperCase()}</strong> · {event.a} ↔ {event.b}<br /><span style={{ opacity: .7 }}>{event.kineticEnergy.toFixed(2)} HEU · {event.relativeSpeed.toFixed(2)} HU/s</span></div>) : <span style={{ opacity: .65 }}>No simulated collision events.</span>}
    </div>
    <input ref={importRef} onChange={readImport} type="file" accept="application/json,.json" hidden />
  </aside>;
}
