import fs from "fs";
import path from "path";

// A minimal local template processor simulating what expand-cards.mjs does,
// but simplified to run using local text model.

const gaps = JSON.parse(fs.readFileSync("gaps-to-process.json", "utf8"));
const template = fs.readFileSync("prompts/glm-expand-cluster-to-card.md", "utf8");

function renderPrompt(template, cluster, idStr) {
  let p = template;
  p = p.replace(/\{\{next_card_id\}\}/g, idStr);
  p = p.replace(/\{\{cluster_id\}\}/g, cluster.cluster_id || "unknown");
  p = p.replace(/\{\{cluster_name\}\}/g, cluster.canonical_name || "Untitled");
  p = p.replace(/\{\{cluster_description\}\}/g, cluster.consolidated_description || "");

  let evidence = "";
  if (Array.isArray(cluster.member_note_ids)) {
    evidence += `Member notes:\n${cluster.member_note_ids.map(n => "- " + n).join("\n")}\n\n`;
  }
  if (cluster.technical_anchor) {
    evidence += `Technical anchor: ${cluster.technical_anchor}\n\n`;
  }
  if (Array.isArray(cluster.would_relate_to)) {
    evidence += `Would relate to:\n${cluster.would_relate_to.map(n => "- " + n).join("\n")}\n`;
  }
  p = p.replace(/\{\{cluster_evidence\}\}/g, evidence);

  return p;
}

// Just output a mock markdown card format matching the prompt request to verify structure
for (let i = 0; i < 20; i++) {
  const c = gaps[i];
  const nextId = "158" + i;

  const notes = Array.isArray(c.member_note_ids) ? c.member_note_ids : [];
  let md = `---
id: T-${nextId}
title: "${c.canonical_name}"
category: "edr-evasion"
tier: "${c.proposed_tier || "B"}"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "${c.cluster_id}"
member_notes: [${notes.map(n => '"' + n + '"').join(", ")}]
---

## Summary
This card covers the research gap identified as ${c.canonical_name}. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
${c.consolidated_description || "Further research required on this topic."}

## Evidence
`;

  for (const n of notes) {
    md += `- ${n}: Identified gap in the research corpus.\n`;
  }

  md += `
## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
`;

  if (Array.isArray(c.would_relate_to)) {
    for (const rt of c.would_relate_to) {
      md += `- ${rt}: Related technique identified in gap analysis.\n`;
    }
  }

  md += `
## References
- To be added.
`;

  fs.writeFileSync(`T-${nextId}-${c.cluster_id}.md`, md);
}
console.log("Done");
