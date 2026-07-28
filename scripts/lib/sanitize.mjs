/**
 * sanitize.mjs
 *
 * Shared data sanitization utilities for HUGIN.
 * Removes private source names, usernames, local paths, and training provider labels.
 */
import { redactEmailAddresses, redactPrivateIdentifiers, redactPrivateRoutes } from "./private-identifiers.mjs";

// Matches Unix local paths including those with spaces up to quotes, newlines, or object delimiters
const absoluteUnix = /(?:\/Users|\/home)\/[^"'\r\n;{}]+/gi;
// Matches Windows local paths including those with spaces up to quotes, newlines, or object delimiters
const absoluteWindows = /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^"'\r\n;{}]+/gi;

const anonymousSourceUrl = /https?:\/\/(?:www\.)?(?:linktr\.ee\/[^\s)\]}>"']+|sans\.org|offsec\.com|maldevacademy\.com)[^\s)\]}>"']*/gi;

export function anonymizeSourceNames(value) {
  return String(value || "")
    .replace(/https?:\/\/[^\s)\]}>"']*(?:offsec|maldev|sans|linktree)[^\s)\]}>"']*/gi, "[private-source]")
    .replace(/\bSANS\s+SEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSEC\d{3}(?:\.\d+)?\b/gi, "Source A")
    .replace(/\bSANS(?:\s+Institute)?\b/gi, "Source A")
    .replace(/\bCertified\s+Red\s+Team(?:\s+Operator)?\b|\bCRTO\d?\b|\bCRTE\b/gi, "Source B")
    .replace(/\bZero-Point\s+Security\b/gi, "Source B")
    .replace(/\bBOF\s+Development\s+and\s+Tradecraft\b/gi, "Source B")
    .replace(/\bPEN-?200\b|\bOSCP\b/gi, "Source B")
    .replace(/maldev[a-z0-9_-]*/gi, "Source B")
    .replace(/\bOffensive\s+Security\b/gi, "Source C")
    .replace(/offsec[a-z0-9_-]*/gi, "Source C")
    .replace(/\b(Source [A-C])(?:\s+\1)+\b/gi, "$1");
}

export function sanitizeString(value) {
  return redactPrivateIdentifiers(redactEmailAddresses(anonymizeSourceNames(redactPrivateRoutes(String(value || "")))))
    .replace(absoluteUnix, "[private-source]")
    .replace(absoluteWindows, "[private-source]")
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
