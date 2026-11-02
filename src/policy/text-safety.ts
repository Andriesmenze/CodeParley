// Text the user or the host supplies, as the engine stores and shows it (Phase 2.1; shared with
// Phase 2.3's user records). PURE.

/**
 * Control characters (C0 and C1) other than tab and line breaks, and bidirectional overrides
 * ("Trojan Source"). One character class: linear, nothing to backtrack.
 */
const UNSAFE_CHAR = /(?![\t\n\r])[\p{Cc}\u202a-\u202e\u2066-\u2069]/u;

/** Display text cannot be used to rewrite a terminal or a later prompt (P2.1-3). */
export function hasUnsafeChars(s: string): boolean {
  return UNSAFE_CHAR.test(s);
}
