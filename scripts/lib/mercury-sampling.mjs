import { stableHash } from "./mercury-audit.mjs";

const TYPE_ALIASES = new Map([
  ["tradecraft_qa", "qa"],
  ["question_answer", "qa"],
  ["q&a", "qa"],
  ["code", "source_code"],
  ["source", "source_code"],
  ["technical-note", "technical_note"],
  ["command", "command_reference"],
]);

export function normalizeType(value) {
  const normalized = String(value ?? "unknown").trim().toLowerCase().replace(/\s+/g, "_");
  return (TYPE_ALIASES.get(normalized) ?? normalized) || "unknown";
}

export function nodeStratum(node = {}) {
  return normalizeType(node.type ?? node.galaxyId ?? node.category ?? "unknown");
}

export function deterministicRank(entry, seed = "hugin-mercury-v1") {
  return stableHash(`${seed}\u0000${nodeStratum(entry.node)}\u0000${String(entry.node?.id ?? "")}`);
}

function sortedGroup(entries, seed) {
  return [...entries].sort((a, b) => deterministicRank(a, seed).localeCompare(deterministicRank(b, seed)));
}

export function stratifiedSample(entries, {
  samplePercent = 25,
  sampleSize = 0,
  minPerType = 3,
  seed = "hugin-mercury-v1",
} = {}) {
  const groups = new Map();
  for (const entry of entries) {
    const key = nodeStratum(entry.node);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(entry);
  }

  const total = entries.length;
  const target = Math.min(
    total,
    Math.max(0, sampleSize > 0 ? Math.floor(sampleSize) : Math.ceil(total * Math.max(0, Math.min(100, samplePercent)) / 100)),
  );

  const strata = [...groups.entries()]
    .map(([type, items]) => ({ type, items: sortedGroup(items, seed), population: items.length, selected: 0 }))
    .sort((a, b) => a.type.localeCompare(b.type));

  if (target === 0 || total === 0) {
    return {
      selected: [],
      plan: {
        seed,
        sample_percent: samplePercent,
        requested_sample_size: sampleSize,
        min_per_type: minPerType,
        eligible: total,
        target: 0,
        strata: Object.fromEntries(strata.map((s) => [s.type, { population: s.population, selected: 0 }])),
      },
    };
  }

  let remaining = target;
  const baseline = Math.max(1, Math.floor(minPerType || 1));

  const coverageOrder = [...strata].sort((a, b) =>
    stableHash(`${seed}\u0000stratum\u0000${a.type}`).localeCompare(stableHash(`${seed}\u0000stratum\u0000${b.type}`)),
  );

  for (let pass = 0; pass < baseline && remaining > 0; pass++) {
    for (const stratum of coverageOrder) {
      if (remaining <= 0) break;
      if (stratum.selected < stratum.population) {
        stratum.selected += 1;
        remaining -= 1;
      }
    }
  }

  while (remaining > 0) {
    const capacity = strata.reduce((sum, s) => sum + (s.population - s.selected), 0);
    if (capacity <= 0) break;

    const allocations = strata
      .filter((s) => s.selected < s.population)
      .map((s) => {
        const available = s.population - s.selected;
        const exact = remaining * available / capacity;
        return { stratum: s, floor: Math.floor(exact), remainder: exact - Math.floor(exact) };
      });

    let assigned = 0;
    for (const allocation of allocations) {
      const take = Math.min(allocation.floor, allocation.stratum.population - allocation.stratum.selected, remaining - assigned);
      allocation.stratum.selected += take;
      assigned += take;
    }
    remaining -= assigned;
    if (remaining <= 0) break;

    allocations.sort((a, b) => {
      if (b.remainder !== a.remainder) return b.remainder - a.remainder;
      return stableHash(`${seed}\u0000remainder\u0000${a.stratum.type}`)
        .localeCompare(stableHash(`${seed}\u0000remainder\u0000${b.stratum.type}`));
    });

    let progressed = false;
    for (const allocation of allocations) {
      if (remaining <= 0) break;
      if (allocation.stratum.selected < allocation.stratum.population) {
        allocation.stratum.selected += 1;
        remaining -= 1;
        progressed = true;
      }
    }
    if (!progressed) break;
  }

  const selected = strata.flatMap((s) => s.items.slice(0, s.selected));
  selected.sort((a, b) => deterministicRank(a, seed).localeCompare(deterministicRank(b, seed)));

  return {
    selected,
    plan: {
      seed,
      sample_percent: samplePercent,
      requested_sample_size: sampleSize,
      min_per_type: minPerType,
      eligible: total,
      target: selected.length,
      strata: Object.fromEntries(strata.map((s) => [s.type, { population: s.population, selected: s.selected }])),
    },
  };
}

export function hasEmbeddedSummary(content) {
  const text = String(content ?? "");
  return /^#{1,4}\s+(?:summary|resumen|overview|executive summary)\b/im.test(text)
    || /^summary\s*:\s*\S+/im.test(text);
}

export function sameTypeFamily(current, detected) {
  const left = normalizeType(current);
  const right = normalizeType(detected);
  if (left === right) return true;
  if ([left, right].every((value) => ["source_code", "code_snippet"].includes(value))) return true;
  return false;
}

export function requiresReview(item = {}) {
  const issues = Array.isArray(item.quality_issues) ? item.quality_issues.filter((issue) => issue !== "none") : [];
  return Boolean(item.needs_review) || issues.length > 0;
}

export function findSemanticClaimFlags(item = {}) {
  const fields = [item.summary, item.rationale, ...(item.mitre_candidates ?? []).map((x) => x.evidence), ...(item.relation_candidates ?? []).map((x) => x.evidence)];
  const text = fields.filter(Boolean).join("\n");
  const flags = [];
  if (/\b(?:guarantees?|always|undetectable|invisible)\b.{0,80}\b(?:EDR|ETW(?:-TI)?)\b/i.test(text)) flags.push("absolute_detection_evasion_claim");
  if (/\b(?:evades?|bypasses?)\b.{0,80}\b(?:all|any)\b.{0,40}\b(?:EDR|ETW(?:-TI)?)\b/i.test(text)) flags.push("unbounded_detection_evasion_claim");
  return [...new Set(flags)];
}

export function reconcileAudit(item, node = {}, content = "") {
  const audit = structuredClone(item ?? {});
  let issues = Array.isArray(audit.quality_issues) ? audit.quality_issues.filter((issue) => issue !== "none") : [];

  if (String(node.summary ?? node.description ?? "").trim() || hasEmbeddedSummary(content)) {
    issues = issues.filter((issue) => issue !== "missing_summary");
  }

  audit.quality_issues = [...new Set(issues)];
  if (audit.quality_issues.length === 0) audit.quality_issues = ["none"];

  audit.safe_fixes = {
    remove_qa_prefix: Boolean(audit.safe_fixes?.remove_qa_prefix),
    extract_technical_answer: Boolean(audit.safe_fixes?.extract_technical_answer),
    set_content_format: audit.safe_fixes?.set_content_format ?? null,
    replace_summary: Boolean(audit.safe_fixes?.replace_summary),
    reclassify_node: Boolean(audit.safe_fixes?.reclassify_node)
      && !sameTypeFamily(audit.current_content_type ?? node.type, audit.detected_content_type),
  };

  audit.semantic_claim_flags = findSemanticClaimFlags(audit);
  audit.needs_review = requiresReview(audit) || audit.semantic_claim_flags.length > 0;
  return audit;
}

export function buildProcessedIndex(entries, existing) {
  const entryById = new Map(entries.map((entry) => [String(entry.node.id), entry]));
  const records = [];
  for (const [entityId, item] of existing.entries()) {
    const entry = entryById.get(String(entityId));
    records.push({
      entity_id: String(entityId),
      source_hash: item.source_hash,
      current_source_hash: entry?.sourceHash ?? null,
      current: Boolean(entry && entry.sourceHash === item.source_hash),
      stratum: entry ? nodeStratum(entry.node) : normalizeType(item.current_content_type),
      audited_at: item.audited_at ?? null,
      confidence: item.confidence ?? null,
      needs_review: requiresReview(item),
    });
  }
  records.sort((a, b) => a.entity_id.localeCompare(b.entity_id));
  return records;
}
