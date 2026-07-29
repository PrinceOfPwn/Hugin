# HUGIN Gravity Lab — implementation contract

## Purpose

Turn the existing universe renderer into an inspectable, local-first knowledge
laboratory. The canonical dataset remains read-only. Every position override,
collision, generated cluster, and inferred relation lives in a reversible local
scenario and is always labelled as simulated or inferred.

## Non-negotiable rules

- The universe must never represent generated relations as curated evidence.
- A body with no original relations remains visible and receives a stable
  semantic placement; it is never collapsed into a central hairball.
- The page must remain useful on integrated GPUs. High quality is progressive,
  not the default requirement.
- The physics is Newtonian simulation in declared HUGIN units, not a claim of
  particle-physics accuracy or real astronomical measurement.
- The canvas has keyboard controls, textual telemetry, and an accessible
  catalogue escape route.

## Model

### Semantic mass

`semanticMass = f(raw content, evidence count, curated degree, centrality)` is
precomputed at build time. The visual engine may apply a scenario-only mass
override but cannot mutate the canonical value.

### Physics

- Stable default: analytic Kepler orbits for bound satellites, fixed-step
  velocity-Verlet integration for the active neighborhood.
- All bodies: Barnes-Hut approximation, all 5,608 bodies active.
- Exact N² research mode: direct pair evaluation, visibly labelled as power
  intensive and only enabled after an in-browser benchmark and confirmation.
- Collision broad phase: spatial hash. Narrow phase conserves linear momentum
  and emits one of flyby, capture, accretion, fragmentation, or ejection.
- The simulation records its timestep and energy/momentum drift. It never
  silently lowers numerical accuracy when a device is slow.

### Spatial language

- Galaxies are semantic clusters.
- High-mass/high-centrality concepts are attractors.
- Low-mass related concepts are satellites or asteroid belts.
- Unrelated records remain in their semantic galaxy on deterministic orbital
  lanes. Edges appear only on focus, path analysis, or explicit density mode.
- The fabric is a shader displacement of the potential field of the strongest
  visible attractors. It is not a second physics engine.

## UX

`Observatory` is read-only and stable. `Gravity Lab` unlocks pause, timeline,
body dragging, collision prediction, local scenarios, and candidate relation
drafts. The default camera is always interactive: drag rotates, shift/right
drag pans, wheel/pinch zooms, WASD/QE moves, F focuses, and Space fits.

The gravity panel exposes a quality profile, active-body budget, physics rate,
time scale, grid visibility, collision mode, exact-mode benchmark, and
scenario controls. Inspector copy separates Observed, Derived, Simulated, and
Inferred values.

## Local persistence

The shipped repository is IndexedDB and requests durable storage only after a
user save. SQLite WASM in an OPFS worker remains an optional, explicitly
unshipped enhancement; the UI must not claim that IndexedDB is SQLite. Store
deltas only, never a second copy of the corpus:

- scenario metadata and dataset version;
- body position, velocity, rotation, and mass overrides;
- checkpoints, simulation events, and relation drafts;
- camera bookmarks and quality preference.

Request durable origin storage only after a user elects to save. Export/import
must use a versioned JSON scenario bundle even when local SQLite is available.

## Delivery phases

1. Pure deterministic physics core plus unit tests.
2. Instanced renderer bridge and gravitational fabric shader.
3. Gravity Lab controls, telemetry, timeline, inspector, and direct dragging.
4. Scenario repository, checkpoints, export/import, then optional SQLite WASM
   worker backed by OPFS.
5. WebGPU exact solver behind feature detection; CPU direct solver only for
   deliberately small active sets.
6. Profiling, mobile fallback, reduced motion, E2E/a11y, and PR artifact.

## Acceptance gates

- 5,608 bodies render without edges by default at a usable frame rate.
- A single selected body exposes explainable mass and relevant relationships.
- Dragging a body updates the fabric and creates an undoable local event.
- Collision events never change canonical entities or curated edges.
- Default and all-bodies modes are deterministic for a seed and fixed timestep.
- Exact N² mode is opt-in, benchmarked, visibly telemetered, and can pause.
- A scenario reload restores the same body state and time.
- No local name, path, secret, or raw private source is stored or displayed.
