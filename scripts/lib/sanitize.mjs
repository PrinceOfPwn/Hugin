/**
 * sanitize.mjs
 *
 * Shared data sanitization utilities for HUGIN.
 * Removes private source names, usernames, local paths, and training provider labels.
 */

const absoluteUnix = /\/(?:Users|home)\/[^\s/]+\/[^\s)\]}>"']+/gi;
const absoluteWindows = /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^\s)\]}>"']+/gi;
const localUser = /\b(?:emiperalta|tamarisk)\b/gi;
const anonymousSourceUrl = /https?:\/\/(?:www\.)?(?:linktr\.ee\/offsecexam|sans\.org|offsec\.com|maldevacademy\.com)[^\s)\]}>"']*/gi;

export function anonymizeSourceNames(value) {
  return String(value || "")
    .replace(/https?:\/\/[^\s)\]}>"']*(?:offsec|maldev|sans|linktree)[^\s)\]}>"']*/gi, "[private-source]")
    .replace(/\bSANS\s+SEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSANS(?:\s+Institute)?\b/gi, "Source A")
    .replace(/\bCertified\s+Red\s+Team\s+Operator\b|\bCRTO\d?\b|\bCRTE\b/gi, "Source B")
    .replace(/maldev[a-z0-9_-]*/gi, "Source B")
    .replace(/\bOffensive\s+Security\b/gi, "Source C")
    .replace(/offsec[a-z0-9_-]*/gi, "Source C")
    .replace(/\b(Source [A-C])(?:\s+\1)+\b/gi, "$1");
}

export function sanitizeString(value) {
  return anonymizeSourceNames(String(value || ""))
    .replace(absoluteUnix, "[private-source]")
    .replace(absoluteWindows, "[private-source]")
    .replace(localUser, "source-owner")
    .replace(anonymousSourceUrl, "[private-source]")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/ +([,.;:])/g, "$1")
    .trim();
}

export function sanitize(value) {
  if (typeof value === "string") return sanitizeString(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => ![
          "source_path",
          "source_key",
          "sourceLabel",
          "file_path",
          "absolute_path",
          "local_path"
        ].includes(key))
        .map(([key, child]) => [key, sanitize(child)])
    );
  }
  return value;
}
