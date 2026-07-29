# Gravity Lab completion ledger

This is deliberately kept in the PR. Checked items were implemented and type-checked; unchecked items are not represented as complete.

- [x] Physics core: deterministic fixed-step Verlet, Barnes-Hut, direct N2, collision outcomes, energy and momentum metrics.
- [x] Worker bridge: transfer-safe simulation frames, pausing, configuration and reset.
- [x] Renderer: existing instanced node cloud consumes live positions; existing gravitational fabric consumes dominant live masses.
- [x] Interaction: pause, reset, drag through the existing playground mode, focus, and 36 px minimum control targets.
- [x] Investigation: visual celestial metadata is explicitly labelled as derived and simulated in the entity inspector.
- [x] Persistence: IndexedDB scenarios, import/export, and durable-browser-storage request.
- [x] Exact N2 benchmark and explicit opt-in confirmation; no hidden reduction in solver fidelity.
- [ ] SQLite-WASM OPFS backend packaged locally. IndexedDB is the shipped dependable local store; do not claim this is SQLite.
- [ ] Relation-drafting editor with explicit human review and export contract.
- [ ] Tests: deterministic physics, collision invariants, persistence round trip, E2E and a11y.
- [ ] Performance: measured 5,608-node render, all-body run, low-end profile and reduced-motion review in CI/browser.
- [ ] Rebase after the active HUGIN PR merges, then open a stacked-independent PR.
