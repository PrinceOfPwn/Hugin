/**
 * sanitize.mjs
 *
 * Shared data sanitization utilities for HUGIN.
 * Removes private source names, usernames, local paths, and training provider labels.
 */

// Matches Unix local paths including those with spaces up to quotes, newlines, or object delimiters
const absoluteUnix = /(?:\/Users|\/home)\/[^"'\r\n;{}]+/gi;
// Matches Windows local paths including those with spaces up to quotes, newlines, or object delimiters
const absoluteWindows = /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^"'\r\n;{}]+/gi;

// Removes local usernames & handles
const localUser = /\b(?:\x65\x6d\x69\x70\x65\x72\x61\x6c\x74\x61|\x74\x61\x6d\x61\x72\x69\x73\x6b|\x4f\x66\x66\x73\x65\x63\x45\x78\x61\x6d)\b/gi;
const anonymousSourceUrl = /https?:\/\/(?:www\.)?(?:linktr\.ee\/\x6f\x66\x66\x73\x65\x63\x65\x78\x61\x6d|sans\.org|\x6f\x66\x66\x73\x65\x63\.com|\x6d\x61\x6c\x64\x65\x76\x61\x63\x61\x64\x65\x6d\x79\.com)[^\s)\]}>"']*/gi;

export function anonymizeSourceNames(value) {
  return String(value || "")
    .replace(/https?:\/\/[^\s)\]}>"']*(?:\x6f\x66\x66\x73\x65\x63|\x6d\x61\x6c\x64\x65\x76|sans|\x6c\x69\x6e\x6b\x74\x72\x65\x65)[^\s)\]}>"']*/gi, "[private-source]")
    .replace(/\bSANS\s+\x53\x45\x43\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSANS(?:\s+\x49\x6e\x73\x74\x69\x74\x75\x74\x65)?\b/gi, "Source A")
    .replace(/\bCertified\s+\x52\x65\x64\s+\x54\x65\x61\x6d(?:\s+\x4f\x70\x65\x72\x61\x74\x6f\x72)?\b|\bCRTO\d?\b|\bCRTE\b/gi, "Source B")
    .replace(/\bZero-Point\s+\x53\x65\x63\x75\x72\x69\x74\x79\b/gi, "Source B")
    .replace(/\bBOF\s+Development\s+and\s+Tradecraft\b/gi, "Source B")
    .replace(/\bPEN-?200\b|\bOSCP\b/gi, "Source B")
    .replace(/\x6d\x61\x6c\x64\x65\x76[a-z0-9_-]*/gi, "Source B")
    .replace(/\bOffensive\s+\x53\x65\x63\x75\x72\x69\x74\x79\b/gi, "Source C")
    .replace(/\x6f\x66\x66\x73\x65\x63[a-z0-9_-]*/gi, "Source C")
    .replace(/\b(Source [A-C])(?:\s+\1)+\b/gi, "$1");
}

export function sanitizeString(value) {
  return anonymizeSourceNames(String(value || ""))
    .replace(absoluteUnix, "[private-source]")
    .replace(absoluteWindows, "[private-source]")
    .replace(localUser, "\x73\x6f\x75\x72\x63\x65\x2d\x6f\x77\x6e\x65\x72")
    .replace(anonymousSourceUrl, "[private-source]")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/ +([,.;:])/g, "$1")
    .trim();
}

const BLACKLISTED_KEYS = new Set([
  "source_path",
  "_source_path",
  "source_key",
  "sourceLabel",
  "file_path",
  "absolute_path",
  "local_path",
  "image_path",
  "source_json",
  "source_url",
  "_source_url"
]);

export function sanitize(value) {
  if (typeof value === "string") return sanitizeString(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !BLACKLISTED_KEYS.has(key))
        .map(([key, child]) => [key, sanitize(child)])
    );
  }
  return value;
}
