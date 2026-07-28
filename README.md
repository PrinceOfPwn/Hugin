# 🐦‍⬛ HUGIN Knowledge Universe

**HUGIN** is a state-of-the-art, fully static technical knowledge graph meticulously engineered for GitHub Pages. It projects a massive curated knowledge layer, anonymized supporting evidence, immutable HTML records, and eight stunning WebGL galaxies—all without requiring a backend, browser tokens, paid services, or runtime AI dependencies. 

It is blazing fast, perfectly secure, and purely static: the ultimate platform for visualizing and navigating complex technical intelligence.

---

## 🔗 The Hugin & Munin Ecosystem

In Norse mythology, Odin relied on his two ravens, **Hugin** (Thought) and **Munin** (Memory), who flew across the world to bring back hidden knowledge. Our architecture embodies this legend:

- 🧠 **Munin (The Memory):** Acts as the intelligence gatherer. Munin autonomously explores, collects, standardizes, and structures raw artifacts and technical intelligence from diverse, unstructured sources.
- 🌌 **Hugin (The Thought - This Repository):** Takes that memory and transforms it into actionable insight. Hugin ingests Munin's raw intelligence, rigorously sanitizes it, processes it through advanced embeddings, and projects it into a breathtaking, interactive WebGL universe for exploration.

Together, they form a flawless, end-to-end pipeline for gathering, securing, and visualizing global technical intelligence.

---

## 🧭 Explore the Universe

Dive into the cosmos of knowledge:
- **Dashboard:** [Launch Dashboard](https://princeofpwn.github.io/Hugin/)
- **Catalog:** [Explore Entities](https://princeofpwn.github.io/Hugin/explore/)
- **Knowledge Graph:** [WebGL Galaxies](https://princeofpwn.github.io/Hugin/graph/)
- **Dataset Contract:** [View Data Structures](https://princeofpwn.github.io/Hugin/dataset/)
- **Quality Report:** [Review Telemetry](https://princeofpwn.github.io/Hugin/quality/)

---

## 📊 Scale & Projection

Hugin operates at a massive scale while remaining entirely static:
- **1,845** core knowledge entities meticulously curated.
- **3,256** anonymous evidence records dynamically loaded only in context.
- **2,806** curated graph relations binding the universe together.
- **Eight** generated semantic neighbors for *every single* core entity.
- Absolute privacy: Provider names, local paths, and private usernames are rigorously stripped from every public artifact.

---

## 🏗️ Cutting-Edge Architecture

- **Astro** powers the core engine, generating ultra-fast static HTML under the `/Hugin/` base path.
- **React** is deployed surgically—handling only search, catalog filters, and rendering the high-performance **Sigma.js WebGL graph**.
- **GitHub Actions** orchestrates the heavy lifting:
  - **Local AI (Qwen3.5-4B-Instruct-ONNX):** Fast, local inference for simple entity extraction and metadata generation.
  - **Complex AI (GLM-5.2):** High-tier reasoning for technical abstraction, cross-document synthesis, and conceptual graph generation.
  - **Embeddings (q8 MiniLM):** Pinned embeddings for vector similarity and semantic neighbor mapping.
  - **Build & Test:** Layout computing, `Pagefind` indexing, `Playwright` E2E testing, and `Lighthouse` audits.
- **GitHub Pages** securely serves the final, verified artifact.

---

## 🧬 Relationship Semantics

- **`curated`**: Owner-authorized, verified knowledge relation.
- **`membership`**: Structural galaxy placement (taxonomic grouping).
- **`similarity`**: Build-generated exploratory relation backed by scoring, ranks, corpus hashing, and pinned models.

---

## 🛠️ Reproduce Locally

The supported runtime is **Node.js 24 LTS**.

```bash
npm ci
npm run data:import   # Requires owner-supplied local import
npm run build
npm run check
npm run test:e2e
```
*Note: All expensive model inference and browser work is offloaded seamlessly to GitHub Actions.*
