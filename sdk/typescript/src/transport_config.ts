// SPDX-License-Identifier: Apache-2.0
/**
 * The transport's configuration: the shapes a caller supplies, and the checks that refuse
 * an unusable or unsafe one when the transport is constructed.
 *
 * `McpReConfig` is a plain interface, so {@link validateConfig} is the earliest point this
 * SDK controls: a value that cannot be honoured is refused where it first enters SDK-owned
 * code, not on the first request it would have corrupted.
 */
import { maxClockSkewBound, type HttpHeader } from "../native/binding.js";
import type {
  AuthorizationBindingPolicy,
  AuthorizationBindingProvider,
} from "./authorization.js";
import type { ContinuationHandles } from "./correlation.js";
import { McpReSdkError, type Signer, type SignerPolicy } from "./custody.js";

/**
 * Widest delegation clock skew a caller may configure, in seconds: the native core's own
 * bound, read from it, so one deployment does not run two different notions of "close
 * enough" — beyond it the credential's nbf/exp window stops bounding anything.
 */
const MAX_CLOCK_SKEW_BOUND = maxClockSkewBound();

/**
 * A verified ADR-MCPS-047 elicitation, and everything answering it needs.
 *
 * Everything here was read from the VERIFIED response — the signature, content digest and
 * request binding all checked out before this was built.
 */
export interface InputRequired {
  /** The two evidence handles + opaque state the answer leg signs over. */
  handles: ContinuationHandles;
  /** The MCP method being continued, unchanged across the chain. */
  method: string;
  /** The params of the leg that earned this elicitation. */
  params: Record<string, unknown>;
  /**
   * The verified `InputRequiredResult` — `requestState` plus whatever the server used to
   * describe what it wants (`elicitation` / `inputRequests`). Passed through
   * uninterpreted: what to ask, and how, is the application's decision.
   */
  result: Record<string, unknown>;
  /** Which continuation round this is, counting from 1. */
  round: number;
}

/** What a {@link Poster} returns: the raw HTTP response, unparsed and unverified. */
export interface HttpReply {
  status: number;
  headers: HttpHeader[];
  body: Buffer;
}

/** Send one signed POST. */
export type Poster = (
  method: string,
  targetUri: string,
  headers: HttpHeader[],
  body: Buffer,
) => Promise<HttpReply>;

/**
 * Everything the adapter needs to sign one request and verify one response.
 *
 * Freshness is generated here, not by the caller: a nonce that repeats inside the window
 * is a defect, not a policy knob.
 */
export interface McpReConfig {
  // --- signing ---
  signer: Signer;
  audienceId: string;
  targetUri: string;
  dpopToken: string;
  route?: string | null;
  policy?: SignerPolicy;

  // --- delegated verification (ADR-MCPRE-052): the trusted ROOT ISSUER anchor ---
  issuerKeyId: string;
  issuerPubkeyB64Url: string;
  issuerRole?: string;
  issuerTrustDomain: string;
  issuerSubject: string;
  verifierAudiences: readonly string[];
  expectedAudienceHash: string;
  acceptedEpochs: readonly string[];
  maxClockSkew?: number;
  revokedIdentifiers?: readonly string[];

  // --- authorization bindings (bind-not-interpret) ---
  authorization?: readonly AuthorizationBindingProvider[];
  authorizationPolicy?: AuthorizationBindingPolicy;

  // --- freshness ---
  requestTtl?: number;
  clock?: () => number;
  nonceFactory?: () => string;

  /**
   * How many signed exchanges may be in flight at once. Defaults to 8.
   *
   * MCP is not lock-step — a client may have several requests outstanding, and each
   * MCP-RE exchange is an independent signed POST with its own nonce and its own
   * correlation entry, so nothing about the protocol requires serializing them.
   *
   * It is bounded rather than unlimited because each in-flight exchange holds a
   * connection in the caller's `poster` and a signing operation (a KMS round trip under
   * non-exporting custody); an unbounded fan-out would let a burst of calls exhaust
   * either. Raise it for a client that genuinely wants more parallelism.
   */
  maxConcurrentExchanges?: number;

  /**
   * Called with `(method, serverKeyid)` for each client->server notification whose signed
   * 202 verified. Observability only — the acceptance claim has already been checked by
   * the time this runs, and declining to observe it changes nothing.
   *
   * What a verified acknowledgement means is exactly: the enforcement boundary
   * authenticated and accepted the message. NOT that the action completed — a verified
   * ack for `notifications/cancelled` does not mean anything was cancelled.
   */
  onNotificationAcknowledged?: (method: string, serverKeyid: string) => void;

  /**
   * Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
   * handles its answer leg must sign over. Observability only: it fires once per
   * continuation round and decides nothing. Answering is
   * {@link answerInputRequired}'s job.
   */
  onInputRequired?: (handles: ContinuationHandles) => void;

  /**
   * Answers an elicitation, so the adapter can drive the ADR-MCPS-047 answer leg itself.
   * Resolve with the `inputResponses` to continue with, or `null`/`undefined` to decline.
   *
   * With a handler installed, a multi-round-trip tool is an ordinary `callTool` from the
   * application's side: the adapter signs the answer leg over the verified handles, posts
   * it, verifies the reply, and repeats until a terminal result — which is what the
   * caller's await resolves to. Without one, an elicitation cannot be continued and the
   * exchange fails closed with {@link ContinuationNotAnswered}, because a pause delivered
   * as a result would read as a finished call.
   */
  answerInputRequired?: (
    prompt: InputRequired,
  ) => Promise<Record<string, unknown> | null | undefined> | Record<string, unknown> | null | undefined;

  /**
   * How many times one call may be elicited before the adapter gives up. Defaults to 4.
   *
   * A continuation chain is driven by whatever the server asks for, so it is the server
   * that decides how long it runs. Without a ceiling a hostile or looping peer could keep
   * one `callTool` in an elicitation cycle indefinitely, re-prompting a user each round.
   * Four is well past any interactive tool's genuine need; raise it for a workflow that
   * really does have more steps.
   */
  maxContinuationRounds?: number;
}

const isIntegerInRange = (value: number, min: number, max: number): boolean =>
  Number.isInteger(value) && value >= min && value <= max;

/**
 * Refuse a configuration the transport cannot honour, and return the validated bound on
 * concurrent exchanges the transport sizes its semaphore with.
 */
export function validateConfig(config: McpReConfig): number {
  const bound = config.maxConcurrentExchanges ?? 8;
  checkConcurrencyBound(bound, config.maxConcurrentExchanges);
  checkContinuationRounds(config);
  checkClockSkew(config);
  checkTrustAnchor(config);
  checkRevocationDenylist(config.revokedIdentifiers);
  return bound;
}

// A bound of 0 is not a degenerate case that merely throttles: every sender waits for a
// slot that can never be released, so the session deadlocks in silence.
function checkConcurrencyBound(bound: number, configured: number | undefined): void {
  if (!isIntegerInRange(bound, 1, Infinity)) {
    throw new McpReSdkError(
      `maxConcurrentExchanges must be a positive integer, got ${JSON.stringify(configured)}`,
    );
  }
}

// Zero rounds is a meaningful setting — it refuses continuation outright — so only a
// negative or non-integer bound is rejected here.
function checkContinuationRounds(config: McpReConfig): void {
  const rounds = config.maxContinuationRounds ?? 4;
  if (!isIntegerInRange(rounds, 0, Infinity)) {
    throw new McpReSdkError(
      `maxContinuationRounds must be a non-negative integer, got ${JSON.stringify(
        config.maxContinuationRounds,
      )}`,
    );
  }
}

// The delegation credential's nbf/exp window is only as strong as the skew allowed around
// it: `now + skew < nbf` and `now - skew > exp` are how it is applied, so a large value
// accepts a credential arbitrarily far outside its validity window and a negative one
// distorts the comparison rather than tightening it. Nothing downstream bounds it —
// DelegationPolicy stores it verbatim — so it is checked here, against the same ceiling the
// RFC 9421 verifier uses for its own skew.
function checkClockSkew(config: McpReConfig): void {
  const skew = config.maxClockSkew ?? 60;
  if (!isIntegerInRange(skew, 0, MAX_CLOCK_SKEW_BOUND)) {
    throw new McpReSdkError(
      `maxClockSkew must be an integer in 0..=${MAX_CLOCK_SKEW_BOUND} seconds, got ${JSON.stringify(
        config.maxClockSkew,
      )}`,
    );
  }
}

// The delegated-verification anchor. TypeScript's type system makes these fields required
// but cannot make them non-empty, and an empty value cannot match anything it is compared
// against: empty `acceptedEpochs` fails every response as a stale trust epoch, empty
// `verifierAudiences` as an audience mismatch, an empty issuer key as an invalid key. The
// client is therefore not *unsafe* with them blank — it is unusable — but it does not
// discover that until the first response comes back looking like a server fault.
function checkTrustAnchor(config: McpReConfig): void {
  const missing = (
    [
      ["issuerKeyId", config.issuerKeyId],
      ["issuerPubkeyB64Url", config.issuerPubkeyB64Url],
      ["issuerTrustDomain", config.issuerTrustDomain],
      ["issuerSubject", config.issuerSubject],
      ["expectedAudienceHash", config.expectedAudienceHash],
      ["verifierAudiences", config.verifierAudiences?.length ? "set" : ""],
      ["acceptedEpochs", config.acceptedEpochs?.length ? "set" : ""],
    ] as const
  )
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new McpReSdkError(
      `the delegated-verification trust anchor is incomplete: ${missing
        .slice()
        .sort()
        .join(", ")} must be set. Every response is verified against these, so an ` +
        `empty value rejects every response the server sends rather than relaxing the check.`,
    );
  }
}

// The revocation denylist, checked for SHAPE because this is the one config field whose
// wrong value fails OPEN. `readonly string[]` is erased at runtime, and `[..."kid-1"]`
// spreads a bare string into one entry per character: the denylist is non-empty, reports as
// configured, and matches no delegated kid, issuer kid or credential `jti` that can exist.
// The operator believes a compromised key is revoked while the client accepts it for its
// whole TTL and epoch window. The sibling anchor fields degrade the same way but fail
// CLOSED, which is why this one is checked for shape and not merely for emptiness.
function checkRevocationDenylist(configured: readonly string[] | undefined): void {
  const revoked: unknown = configured;
  if (revoked === undefined || revoked === null) return;
  checkDenylistIsAnArray(revoked);
  checkDenylistEntries(revoked);
}

function checkDenylistIsAnArray(revoked: unknown): asserts revoked is unknown[] {
  if (!Array.isArray(revoked)) {
    throw new McpReSdkError(
      `revokedIdentifiers must be an array of identifier strings, not ${
        typeof revoked === "string" ? "a bare string" : typeof revoked
      }: a string spreads one character per entry, matching no identifier and ` +
        `disabling revocation while reporting a denylist as configured`,
    );
  }
}

function checkDenylistEntries(revoked: unknown[]): void {
  for (const id of revoked) {
    if (typeof id !== "string" || id.length === 0) {
      throw new McpReSdkError(
        `revokedIdentifiers entries must be non-empty strings, got ${JSON.stringify(id)}; ` +
          `an entry that cannot match an identifier silently revokes nothing`,
      );
    }
  }
}
