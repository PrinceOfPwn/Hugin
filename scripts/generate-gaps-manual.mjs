import fs from "fs";
import path from "path";

const REPO_ROOT = process.cwd();
const TECHNIQUES_DIRS = [path.join(REPO_ROOT, "techniques"), path.join(REPO_ROOT, "techniques-generated")];

function nextTechniqueId() {
  const ids = new Set();
  for (const dir of TECHNIQUES_DIRS) {
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir)) {
      const m = entry.match(/^T-(\d{3,})/);
      if (m) ids.add(parseInt(m[1], 10));
    }
  }
  let max = 0;
  for (const id of ids) if (id > max) max = id;
  return max + 1;
}

function slugify(s) {
  return String(s || "card")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "card";
}

function pad3(n) { return String(n).padStart(3, "0"); }

const gapsDir = path.join(REPO_ROOT, "data/incoming/bundle-20260728/vault-export");
const files = fs.readdirSync(gapsDir).filter(f => f.startsWith("lgtm-clusters-gaps") && f.endsWith(".json"));

let clusters = [];
for (const file of files) {
  const data = JSON.parse(fs.readFileSync(path.join(gapsDir, file), "utf8"));
  if (data.clusters) {
    clusters = clusters.concat(data.clusters);
  } else if (Array.isArray(data)) {
    clusters = clusters.concat(data);
  }
}

// Ensure unique by cluster_id
const uniqueClusters = [];
const seen = new Set();
for (const c of clusters) {
  if (!seen.has(c.cluster_id)) {
    seen.add(c.cluster_id);
    uniqueClusters.push(c);
  }
}

const corpus = []; // to filter out covered ones. Actually we will just pick 20.
const selected = uniqueClusters.slice(0, 20);
let nextId = nextTechniqueId();

const outDir = path.join(REPO_ROOT, "techniques-generated");
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

for (const c of selected) {
  const idStr = pad3(nextId);
  const title = c.canonical_name || c.cluster_id;
  const category = c.proposed_category || "patterns";
  const tier = c.proposed_tier || "C";
  const tags = `["gap", "research"]`;
  const mitre = `[]`;
  const memberNotesStr = Array.isArray(c.member_note_ids) ? `["${c.member_note_ids.join('", "')}"]` : `[]`;

  const markdown = `---
id: T-${idStr}
title: "${title.replace(/"/g, '\\"')}"
category: ${category}
tier: ${tier}
tags: ${tags}
mitre: ${mitre}
origin: manual-gap-extraction
source_cluster: ${c.cluster_id}
member_notes: ${memberNotesStr}
---

## Summary

${c.consolidated_description || "This technique card was generated from a research gap."}

## Technical Deep Dive

${c.rationale || "No rationale provided."}

Technical Anchor: ${c.technical_anchor || "N/A"}

## Evidence

${(c.member_note_ids || []).map(id => `- ${id}`).join("\n")}

## Detection & Mitigation

To be documented.

## Related Techniques

${(c.would_relate_to || []).map(r => `- ${r}`).join("\n")}

## References

- Internal research vault
`;

  const filename = `T-${idStr}-${slugify(title)}.md`;
  fs.writeFileSync(path.join(outDir, filename), markdown);
  console.log(`Generated ${filename}`);
  nextId++;
}
console.log("Done generating 20 cards.");
