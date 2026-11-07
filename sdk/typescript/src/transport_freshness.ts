// SPDX-License-Identifier: Apache-2.0
/**
 * The freshness inputs a signed request carries: its anti-replay nonce and the clock its
 * validity window is read from.
 *
 * Freshness is generated here, not by the caller: a nonce that repeats inside the window
 * is a defect, not a policy knob.
 */
import { randomBytes } from "node:crypto";

import { McpReSdkError } from "./custody.js";

/** 128 bits from the OS CSPRNG: the freshness window rejects a repeat, so the only
 * requirement here is that a collision is not reachable in practice. */
export const defaultNonce = (): string => randomBytes(16).toString("base64url");

/**
 * Minimum characters in an anti-replay nonce. 128 bits base64url-encodes to 22, which
 * is what {@link defaultNonce} produces — so this floor never constrains the default
 * path. It constrains an OVERRIDE: `nonceFactory` is caller-supplied and was accepted
 * unchecked, so a factory returning a counter, a timestamp, or a truncated value
 * silently weakened replay protection for every request while every signature still
 * verified.
 */
export const MIN_NONCE_CHARS = 22;

/**
 * Draw a nonce and refuse a sub-floor one, at SIGN time.
 *
 * Fails closed rather than signing: a request signed under a guessable nonce is
 * accepted by the verifier, which is precisely what the replay window cannot save you
 * from. Enforced only where a nonce is EMITTED, so the accepted wire language is
 * unchanged — no cross-implementation coordination, no fixture regeneration.
 */
export const checkedNonce = (factory: () => string): string => {
  const nonce = factory();
  if (typeof nonce !== "string" || nonce.length < MIN_NONCE_CHARS) {
    const got = typeof nonce === "string" ? `${nonce.length} characters` : typeof nonce;
    // `McpReSdkError`, matching the Python twin: a local misconfiguration is not a
    // protocol verdict, so it must not be an `McpReError` carrying an invented
    // `wireCode` — and it must not be an untyped `Error` either, or a caller cannot
    // catch it the same way in both SDKs.
    throw new McpReSdkError(
      `mcp-re-sdk: nonceFactory returned ${got}; a nonce must be at least ${MIN_NONCE_CHARS} (128 bits base64url)`,
    );
  }
  return nonce;
};

export const defaultClock = (): number => Math.floor(Date.now() / 1000);
