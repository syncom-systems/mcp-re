// SPDX-License-Identifier: Apache-2.0
/**
 * The MCP-RE transport adapter (ADR-MCPS-044 §wrap-or-fork rule).
 *
 * `Client` speaks plain MCP; this adapter signs the outgoing bytes and verifies the
 * incoming bytes underneath it, so application code never calls `signRequest` /
 * `verifyResponse` itself.
 *
 *     application code
 *       -> Client (@modelcontextprotocol/client)  plain MCP; unaware of MCP-RE
 *       -> McpReHttpTransport                  signs outbound bytes / verifies inbound
 *       -> ../native/binding (napi-rs)         the audited mcp-re-client-core, in Rust
 *       -> mcp-re-proxy (HTTP profile)         one signed mTLS POST per request
 *
 * Why a transport and not a wrapper: the MCP SDK serializes JSON-RPC *inside* each
 * transport — `Client` hands the transport parsed objects, not bytes. The transport is
 * therefore the only seam with exact-byte control, which is what a byte-exact signature
 * requires.
 *
 * **Every failure is delivered, correlated to the request id, as a JSON-RPC error.** A
 * transport that dropped a failed exchange would leave `Client` awaiting a reply that
 * never comes; a hang is a worse failure mode than a raise, and an unverifiable response
 * must never reach the application as a result.
 *
 * **One-way notifications are carried, not dropped.** A notification is its own signed
 * POST, and the acknowledgement it earns — a signed bodyless 202 bound to that exact
 * transmission — is verified before the adapter treats it as delivered. See
 * {@link NotificationNotAcknowledged} for what happens when it is not.
 *
 * **A multi-round-trip call is driven to a terminal result.** An ADR-MCPS-047 elicitation
 * pauses a call rather than finishing it, so the adapter signs the answer leg over the
 * verified handles of the leg before it and continues until the server returns a terminal
 * result — that result, and only that, is what the caller's await resolves to. Supply
 * {@link McpReConfig.answerInputRequired} to answer; without it an elicitation fails
 * closed ({@link ContinuationNotAnswered}) rather than reaching the application as if the
 * call had completed.
 *
 * MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
 * a `poster` so this layer stays transport-agnostic and testable. {@link connectMtlsHttp}
 * builds the mTLS leg on top of it, mirroring the Rust client's
 * `mcp_re_transport::remote::MtlsRemoteTransport`.
 */

import type { JSONRPCMessage, RequestId, Transport } from "@modelcontextprotocol/client";
import { JSONRPCMessageSchema } from "@modelcontextprotocol/core";

import type { SignedRequestJs } from "../native/binding.js";
import { CorrelationStore, type ContinuationHandles, type PendingRequest } from "./correlation.js";
import { McpReError, McpReSdkError } from "./custody.js";
import { authzBindingDigest, bindingsJsonFor } from "./transport_binding.js";
import {
  validateConfig,
  type HttpReply,
  type McpReConfig,
  type Poster,
} from "./transport_config.js";
import {
  answerHandlerFor,
  answerLegId,
  answerLegParams,
  collectAnswer,
} from "./transport_continuation.js";
import { plainMcpReply, verifiedResult } from "./transport_envelope.js";
import {
  ConnectionClosed,
  NO_PEER_WIRE_CODE,
  NotificationNotAcknowledged,
  VerifiedReplyNotAResponse,
  ClientResponseUnsupported,
  errorMessage,
  plainErrorWireCode,
  rejectionData,
} from "./transport_errors.js";
import { MIN_NONCE_CHARS, checkedNonce, defaultClock, defaultNonce } from "./transport_freshness.js";
import { verifyAcknowledgement, verifyReply } from "./transport_verify.js";

export {
  ClientResponseUnsupported,
  ConnectionClosed,
  ContinuationNotAnswered,
  NotificationNotAcknowledged,
  VerifiedReplyNotAResponse,
} from "./transport_errors.js";
export type { HttpReply, InputRequired, McpReConfig, Poster } from "./transport_config.js";

/**
 * The transport's lifecycle state (#421).
 *
 * Explicit because the alternative is a boolean that cannot express "closing": work must
 * be refused the instant close begins, not once it finishes.
 */
export enum TransportState {
  New = "NEW",
  Open = "OPEN",
  Closing = "CLOSING",
  Closed = "CLOSED",
}

/**
 * Bounds how many exchanges run at once.
 *
 * `send()` is called once per outgoing request and each call awaits its own reply, so
 * without a bound a burst of concurrent requests would fan out into unbounded in-flight
 * POSTs and signing operations.
 */
class Semaphore {
  #free: number;
  readonly #waiting: (() => void)[] = [];

  constructor(slots: number) {
    this.#free = slots;
  }

  async acquire(): Promise<void> {
    if (this.#free > 0) {
      this.#free -= 1;
      return;
    }
    await new Promise<void>((resolve) => this.#waiting.push(resolve));
  }

  release(): void {
    // Hand the slot straight to the next waiter rather than returning it to the pool —
    // incrementing here would let a later arrival overtake the queue.
    const next = this.#waiting.shift();
    if (next) next();
    else this.#free += 1;
  }
}

/** What one outgoing leg is signed over, drawn fresh for each signature. */
interface SigningBasis {
  targetUri: string;
  audienceId: string;
  route: string | null;
  dpopToken: string;
  nonce: string;
  created: number;
  expires: number;
  bindingsJson: string | null;
}

/** The mutable state of one logical call as its legs run. */
interface CallState {
  params: Record<string, unknown>;
  legId: RequestId;
  cont: ContinuationHandles | null;
  round: number;
  /**
   * Correlation entries this call still holds. An open leg stays outstanding while its
   * answer leg runs — ADR-MCPS-047 associates without consuming — so there can be more
   * than one, and every entry left here when the call ends is retired.
   */
  outstanding: Set<string>;
}

/** A verified `InputRequiredResult`: the open leg it pauses, and what its answer leg signs over. */
interface PausedLeg {
  correlationId: string;
  responseDigestAlg: string;
  responseDigestValue: string;
  requestState: string;
  replyBody: Buffer;
}

/** A request message: it has a method and an id, so it earns a signed reply. */
type RequestMessage = JSONRPCMessage & { method: string; id: RequestId };

/**
 * An MCP client transport that signs requests and verifies responses.
 *
 * ```ts
 * const transport = new McpReHttpTransport(config, poster);
 * const client = new Client({ name: "app", version: "1.0.0" });
 * await client.connect(transport);
 * await client.callTool({ name: "read_file", arguments: { path: "/etc/hosts" } });
 * ```
 *
 * The signer is checked against the route's policy in `start()`, so a custody violation
 * fails the connection rather than a request.
 */
export class McpReHttpTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  readonly #config: McpReConfig;
  readonly #poster: Poster;
  readonly #correlation = new CorrelationStore();
  readonly #slots: Semaphore;
  #state: TransportState = TransportState.New;
  /** Aborts in-flight exchanges when close() begins. */
  #abort = new AbortController();

  constructor(config: McpReConfig, poster: Poster) {
    this.#slots = new Semaphore(validateConfig(config));
    this.#config = config;
    this.#poster = poster;
  }

  get #clock(): () => number {
    return this.#config.clock ?? defaultClock;
  }

  /** The lifecycle state (#421). */
  get state(): TransportState {
    return this.#state;
  }

  /** Outstanding correlation entries. Observable so "close clears it" is testable. */
  get pendingCorrelations(): number {
    return this.#correlation.size;
  }

  /**
   * The outstanding requests, in issue order — the ADR-MCPS-044 in-flight correlation
   * state this transport holds, including each request's authorization-binding digest.
   *
   * Read-only: the entries are what the store already recorded, and consuming one is the
   * response path's business.
   */
  pendingRequests(): PendingRequest[] {
    return this.#correlation.pending();
  }

  async start(): Promise<void> {
    if (this.#state !== TransportState.New) {
      // The MCP SDK's own transports treat a double start as a defect; a second start
      // would sign under a policy that was already accepted, hiding the first one.
      throw new McpReSdkError(
        `McpReHttpTransport cannot start from state ${this.#state}; a transport is ` +
          `single-use and start() is not a reset`,
      );
    }
    this.#config.policy?.check(this.#config.signer);
    this.#config.authorizationPolicy?.check(this.#config.authorization ?? []);
    this.#state = TransportState.Open;
  }

  async send(message: JSONRPCMessage): Promise<void> {
    this.#requireOpen();
    if (!("method" in message)) {
      // A client->server RESPONSE or error. It has no `method`, so the notification path
      // below could only carry it by signing a fabricated message; refuse it instead of
      // inventing one.
      throw new ClientResponseUnsupported(
        "a client->server response has no MCP-RE carrier; the profile covers a signed " +
          "request and a signed notification, and a response is neither",
      );
    }
    if (!("id" in message)) {
      // A one-way notification: its own signed POST, answered by a signed bodyless 202
      // rather than a JSON-RPC reply. A failure throws from here rather than becoming a
      // delivered message: there is no request id to correlate one to, and this caller is
      // the only party that can learn the message was not acknowledged.
      await this.#underSlot(() => this.#notify(message.method, paramsOf(message)));
      return;
    }

    const reply = await this.#requestReply(message as RequestMessage);
    // No message callback after the close callback: delivering to an application that
    // believes it has disconnected is worse than dropping (#421).
    if (this.#state === TransportState.Open) this.onmessage?.(reply);
  }

  /**
   * Refuse the instant close begins, not once it finishes: a signed request must never
   * leave a transport the caller has already torn down (#421).
   */
  #requireOpen(): void {
    if (this.#state !== TransportState.Open) {
      throw new ConnectionClosed(
        `McpReHttpTransport is ${this.#state}, not OPEN; it accepts no work`,
      );
    }
  }

  /**
   * The message to deliver for one request: its terminal reply, or a JSON-RPC error
   * correlated to it. A transport that went away is not a wire outcome and is rethrown.
   */
  async #requestReply(request: RequestMessage): Promise<JSONRPCMessage> {
    try {
      return await this.#underSlot(() => this.#exchange(request));
    } catch (e) {
      return this.#failureReply(request.id, e);
    }
  }

  /**
   * The JSON-RPC error a failed exchange is delivered as, or the failure itself when it is
   * not one that may be delivered.
   */
  #failureReply(id: RequestId, e: unknown): JSONRPCMessage {
    if (e instanceof ConnectionClosed) {
      // Not a wire outcome: the local transport went away. The upstream Client already
      // rejects its pending requests from onclose, so this must not be laundered into a
      // JSON-RPC error that claims the peer said something.
      throw e;
    }
    if (e instanceof McpReError) return errorMessage(id, e.wireCode);
    // A local failure (e.g. the signing device). No wire code describes it.
    if (e instanceof McpReSdkError) return errorMessage(id, `mcp-re-sdk: ${e.message}`);
    // Two unrelated things arrive here as plain Errors: the core's own fail-closed
    // refusals, which carry a frozen `mcp-re.*` token in `code`, and whatever the caller's
    // `poster` throws while doing real I/O — a reset connection, a TLS error, a timeout.
    // Delivering both verbatim would put "socket hang up" in the same field that otherwise
    // only ever holds something the peer said, so only a core refusal's token is passed
    // through as one. Everything else is delivered under the prefix that means "local
    // condition", named, exactly as Python does it.
    if (e instanceof Error) return errorMessage(id, plainErrorWireCode(e));
    throw e;
  }

  /**
   * Run `work` under the concurrency bound, raced against close().
   *
   * A notification runs under the same bound as an exchange because it costs the same
   * resources — a connection and a signing operation. The abort listener is registered per
   * unit of work and removed in the finally below. An AbortSignal outlives every request
   * raced against it, so a listener left behind is retained — with its captured promise —
   * until the transport itself is collected; a long session would accumulate one per
   * request it ever sent.
   *
   * The finally releases the slot on every path, including a rethrown non-Error: leaking a
   * slot would shrink the pool permanently, and enough of them would deadlock the session.
   */
  async #underSlot<T>(work: () => Promise<T>): Promise<T> {
    await this.#slots.acquire();
    let releaseAbortListener: () => void = () => {};
    try {
      // Re-check AFTER the queue wait. The state check in `send()` happened before this
      // work waited for a slot, and close() can land during that wait. Without this the
      // work below would still sign and POST — `Promise.race` starts both arms, so racing
      // `#aborted()` only decides which result the caller sees, not whether the request
      // reaches the server. A queued request is not already-dispatched work, so emitting
      // it after close() would hand the server a valid, fresh, correctly-signed request
      // the caller believes it cancelled.
      //
      // READ FROM THIS TRANSPORT'S OWN STATE, not from `AbortSignal.aborted`. Both are
      // set by `close()`, but only one of them is ours: relying on the signal made the
      // guard rest on a RUNTIME semantic — that an already-aborted signal is observable
      // without yielding — which had to be registered as a trusted premise (ASM-0043).
      // `#state` is an ordinary field this class assigns before it aborts anything, so
      // the guard rests on nothing but this file (#747).
      this.#refuseIfClosed();
      // Race the work against close(): an aborted exchange fails its request with
      // ConnectionClosed rather than waiting out a poster the caller no longer wants.
      const aborted = this.#aborted();
      releaseAbortListener = aborted.release;
      return await Promise.race([work(), aborted.promise]);
    } finally {
      this.#slots.release();
      releaseAbortListener();
    }
  }

  /**
   * Refuse, right now, if this transport is no longer open.
   *
   * The guard a queued unit of work runs before it is signed and sent. It reads `#state`
   * — assigned synchronously by `close()` before anything is aborted — rather than
   * `AbortSignal.aborted`, so what stops a signed request from leaving a closed transport
   * is a field this class owns and not a runtime semantic taken on trust. The reason
   * lives in the call site; this is one function so the paths cannot drift apart.
   */
  #refuseIfClosed(): void {
    if (this.#state !== TransportState.Open) {
      throw new ConnectionClosed("the transport was closed");
    }
  }

  /**
   * A promise that rejects with ConnectionClosed as soon as close() begins, paired with
   * the `release` that unregisters it.
   *
   * The caller MUST call `release` once the race it feeds has settled. `{ once: true }`
   * only removes the listener when it actually fires, which is the rare case: the common
   * one is an exchange that completes normally, leaving the listener registered on a
   * signal that lives as long as the transport.
   */
  #aborted(): { promise: Promise<never>; release: () => void } {
    const signal = this.#abort.signal;
    let release = () => {};
    const promise = new Promise<never>((_resolve, reject) => {
      if (signal.aborted) return reject(signal.reason);
      const onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
      release = () => signal.removeEventListener("abort", onAbort);
    });
    // An already-aborted signal rejects synchronously above and registers nothing, so the
    // no-op release is correct there. Attach a catch so a promise that loses the race
    // cannot surface as an unhandled rejection when it is abandoned.
    promise.catch(() => {});
    return { promise, release: () => release() };
  }

  /**
   * Close the transport: abortive, idempotent (#421).
   *
   * New work is refused immediately, in-flight exchanges are aborted and fail with
   * {@link ConnectionClosed}, and abandoned correlation state is cleared. `onmessage`
   * never fires after `onclose` — a message delivered to an application that believes it
   * has disconnected is worse than a dropped one.
   *
   * **Abortive, matching the upstream client's rejection of pending requests.** It makes
   * no claim that already-dispatched remote work has stopped: the server may have
   * received the request and acted on it. Only that this client will not process an
   * answer.
   */
  async close(): Promise<void> {
    if (this.#state === TransportState.Closing || this.#state === TransportState.Closed) {
      return; // idempotent
    }
    this.#state = TransportState.Closing;
    this.#abort.abort(new ConnectionClosed("the transport was closed"));
    // Abandoned correlation entries would otherwise outlive the transport that owns them.
    this.#correlation.expireBefore(Number.MAX_SAFE_INTEGER);
    this.#state = TransportState.Closed;
    this.onclose?.();
  }

  /**
   * What the next signature is made over: a fresh validity window, the authorization
   * bindings for `method`, and a nonce that has cleared the floor.
   */
  #signingBasis(method: string): SigningBasis {
    const config = this.#config;
    const created = this.#clock();
    return {
      targetUri: config.targetUri,
      audienceId: config.audienceId,
      route: config.route ?? null,
      dpopToken: config.dpopToken,
      created,
      expires: created + (config.requestTtl ?? 300),
      bindingsJson: bindingsJsonFor(config, method),
      nonce: checkedNonce(config.nonceFactory ?? defaultNonce),
    };
  }

  /** POST exactly what was signed: the verifier is later shown these same bytes. */
  #transmit(signed: SignedRequestJs): Promise<HttpReply> {
    return this.#poster(signed.method, signed.targetUri, signed.headers, signed.body);
  }

  /**
   * Sign one notification, POST it, and verify the acknowledgement it earns.
   *
   * A notification is signed by the ordinary request rules — same evidence block, same
   * covered components, same freshness triple. What it gets back is a signed bodyless
   * 202 whose `;req` components plus `mcp-re-request-evidence` bind it to THIS
   * transmission (owner ruling C019b), so a 202 captured from an earlier send of the
   * same notification does not verify here.
   *
   * There is deliberately no "sent it anyway" path: an unverified acknowledgement
   * establishes nothing, and treating it as delivery is what the profile removes.
   */
  async #notify(method: string, params: unknown): Promise<void> {
    const config = this.#config;
    const signed = config.signer.signNotification({
      method,
      paramsJson: JSON.stringify(params ?? {}),
      ...this.#signingBasis(method),
    });
    const httpReply = await this.#transmit(signed);

    let accepted;
    try {
      accepted = verifyAcknowledgement(config, httpReply, signed, this.#clock());
    } catch (e) {
      // The same normalization the request path applies: `wireCode` is documented as the
      // frozen token, which a core refusal carries in its `code`. Anything else is a local
      // condition and says so, rather than travelling as an invented wire code.
      throw new NotificationNotAcknowledged(method, acknowledgementFailureCode(e));
    }

    config.onNotificationAcknowledged?.(method, accepted.serverKeyid);
  }

  /**
   * Run one logical call to a terminal result: sign, POST, verify, correlate.
   *
   * An ADR-MCPS-047 elicitation does not end the call — it pauses it. So this drives the
   * whole chain: every leg is signed, posted and verified here, and an answer leg binds
   * to the verified handles of the leg before it. What returns is the TERMINAL result the
   * client asked for, or a JSON-RPC error carrying the frozen wire code from whichever
   * hop failed.
   *
   * Because every hop verified, handing up the terminal result is honest under §9.3 of
   * the continuation profile: a chain with an unverifiable middle hop never gets here.
   */
  async #exchange(request: RequestMessage): Promise<JSONRPCMessage> {
    const state: CallState = {
      params:
        "params" in request && request.params !== undefined
          ? (request.params as Record<string, unknown>)
          : {},
      legId: request.id,
      cont: null,
      round: 0,
      outstanding: new Set<string>(),
    };
    try {
      for (;;) {
        const terminal = await this.#runLeg(request, state);
        if (terminal !== null) return terminal;
      }
    } finally {
      // Whatever is still outstanding can never be bound now: a failed leg gets no
      // answer, and an open leg's answer leg has either terminated the call or failed
      // with it. Everything that lands here is remotely triggerable — a reset connection,
      // an unverifiable reply, an elicitation nobody answers — so leaving entries
      // outstanding would let a peer grow the store one call at a time, for the life of
      // the session. Retiring them is not a security decision: a response arriving for
      // one afterwards is refused either way.
      for (const id of state.outstanding) this.#correlation.abandon(id);
    }
  }

  /**
   * One leg of a call: the terminal message when the leg ends the call, or `null` after
   * preparing `state` for the answer leg that continues it.
   */
  async #runLeg(request: RequestMessage, state: CallState): Promise<JSONRPCMessage | null> {
    // Checked every leg, not only before the first. `Promise.race` in `send()` decides
    // which result the CALLER sees; it does not stop the losing arm, so without this an
    // ADR-MCPS-047 continuation chain would go on signing and POSTing fresh answer legs,
    // re-populating the correlation store, and re-prompting a human through
    // `answerInputRequired`, after `close()` has aborted and `onclose` has fired. A queued
    // or continuing leg is not already-dispatched work: emitting it after close() hands
    // the server a valid, fresh, correctly-signed request the caller believes it
    // cancelled. The Python twin's task group really cancels.
    if (this.#abort.signal.aborted) throw this.#abort.signal.reason;
    const { signed, correlationId } = this.#signLeg(request.method, state);
    state.outstanding.add(correlationId);

    const httpReply = await this.#transmit(signed);
    const verified = verifyReply(this.#config, httpReply, signed, this.#clock());

    // A verified rejection receipt is genuine evidence, but it is NOT an acceptance:
    // it must reach the app as an error, never as a result.
    //
    // `bound` is the core's verdict on whether the receipt is tied to THIS
    // transmission. A preflight-unbound receipt carries no binding to this request's
    // nonce or evidence, so one such signed receipt answers any request from any
    // client of that issuer for the credential's whole validity window. It is still
    // an error and never a result, but the application must be able to tell "the
    // boundary rejected MY request" from "a generic rejection arrived" (RSP-7), so
    // the binding fact travels in `data` — beside the frozen token rather than
    // inside it, because the token is what the peer said.
    if (verified.outcome !== "success") {
      this.#retire(state, correlationId);
      // A missing or EMPTY wire code is the SDK's own condition, not a peer token: an
      // empty message is an error no application can act on, and an `mcp-re.*` token
      // would name a statement the peer never made.
      return errorMessage(
        request.id,
        verified.wireCode ? verified.wireCode : NO_PEER_WIRE_CODE,
        rejectionData(verified),
      );
    }

    if (verified.requestState === undefined || verified.requestState === null) {
      this.#retire(state, correlationId);
      return deliverResult(httpReply.body, request.id);
    }

    await this.#prepareAnswerLeg(request, state, {
      correlationId,
      responseDigestAlg: verified.respEvidenceDigestAlg,
      responseDigestValue: verified.respEvidenceDigestValue,
      requestState: verified.requestState,
      replyBody: httpReply.body,
    });
    return null;
  }

  /** Sign one leg of the call and record it as outstanding. */
  #signLeg(method: string, state: CallState): { signed: SignedRequestJs; correlationId: string } {
    const config = this.#config;
    const basis = this.#signingBasis(method);
    const signed = config.signer.signRequest({
      idJson: JSON.stringify(state.legId),
      method,
      paramsJson: JSON.stringify(state.params),
      ...basis,
      ...(state.cont ? state.cont.asSignArgs() : {}),
    });
    const correlationId = this.#correlation.record(signed, {
      requestId: String(state.legId),
      // The nonce rode into the signature; the handle is the evidence digest.
      nonce: "",
      audienceId: config.audienceId,
      expectedSignerId: config.issuerKeyId,
      created: basis.created,
      expires: basis.expires,
      route: config.route ?? null,
      authzBindingDigest: authzBindingDigest(basis.bindingsJson),
    });
    return { signed, correlationId };
  }

  /** Consume a leg's correlation entry: the call is over, and this leg is answered. */
  #retire(state: CallState, correlationId: string): void {
    this.#correlation.take(correlationId, this.#clock());
    state.outstanding.delete(correlationId);
  }

  /**
   * A pause. Associate without consuming — the open leg is answered by its answer leg, not
   * by this response — hand up the handles it signs over, obtain the application's answer,
   * and set `state` up so the next leg is the answer leg.
   */
  async #prepareAnswerLeg(
    request: RequestMessage,
    state: CallState,
    pause: PausedLeg,
  ): Promise<void> {
    const config = this.#config;
    const handles = this.#correlation.recordInputRequired(pause.correlationId, {
      responseDigestAlg: pause.responseDigestAlg,
      responseDigestValue: pause.responseDigestValue,
      requestState: pause.requestState,
      now: this.#clock(),
    });
    config.onInputRequired?.(handles);

    state.round += 1;
    const handler = answerHandlerFor(config, request.method, state.round);

    // Re-checked immediately before the handler runs: `answerInputRequired` is where
    // a human is prompted, and a transport the caller has already closed must not
    // raise a prompt for an answer leg it will never send.
    if (this.#abort.signal.aborted) throw this.#abort.signal.reason;

    const responses = await collectAnswer(handler, {
      handles,
      method: request.method,
      params: state.params,
      result: verifiedResult(pause.replyBody),
      round: state.round,
    });

    state.params = answerLegParams(state.params, responses, handles);
    state.legId = answerLegId(request.id, state.round);
    state.cont = handles;
  }
}

/** The `params` a message carries, or `undefined` when it carries none. */
const paramsOf = (message: JSONRPCMessage): unknown =>
  "params" in message ? message.params : undefined;

/**
 * The wire code a failed acknowledgement is reported under: the core's frozen token, a
 * local condition under the SDK prefix, or the stringified throwable when it is neither.
 */
function acknowledgementFailureCode(e: unknown): string {
  if (e instanceof McpReError) return e.wireCode;
  if (e instanceof Error) return plainErrorWireCode(e);
  return String(e);
}

/**
 * The terminal message for a verified result reply.
 *
 * The shape check runs BEFORE the union schema, which accepts a request arm: a verified
 * body carrying a `method` would otherwise be dispatched by `Client` as a server-initiated
 * request. `plainMcpReply` rebuilds the envelope, so nothing beyond `result` / `error` can
 * reach the parser.
 */
function deliverResult(body: Buffer, id: RequestId): JSONRPCMessage {
  let plain: unknown;
  try {
    plain = plainMcpReply(body, id);
  } catch (e) {
    if (!(e instanceof VerifiedReplyNotAResponse)) throw e;
    return errorMessage(id, "mcp-re.malformed_envelope", {
      detail: e.message,
    });
  }
  return JSONRPCMessageSchema.parse(plain);
}

/**
 * Internals exposed for this package's own tests only. Not part of the public API and
 * not re-exported from the package entry point; the security check itself runs on the
 * ordinary signing path, not through this seam.
 */
export const __testing = { checkedNonce, defaultNonce, MIN_NONCE_CHARS };
