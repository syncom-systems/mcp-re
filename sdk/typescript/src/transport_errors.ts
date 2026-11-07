// SPDX-License-Identifier: Apache-2.0
/**
 * The transport's failure vocabulary: the typed errors it throws, and the one JSON-RPC
 * error envelope it delivers a failed exchange as.
 *
 * Every failure of an exchange is delivered, correlated to the request id, as a JSON-RPC
 * error built by {@link errorMessage}; the classes here are the failures a caller can tell
 * apart by type rather than by message.
 */
import type { JSONRPCMessage, RequestId } from "@modelcontextprotocol/client";

import { McpReSdkError } from "./custody.js";

/**
 * JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
 * always the frozen `mcp-re.*` token in `.message`.
 *
 * This envelope is synthesized locally by the transport, never received from the peer, so
 * MCP 2026-07-28 requires that it cannot be mistaken for a peer error: it sits outside
 * JSON-RPC's reserved band, and it differs from the proxy's own rejection code (-31000) so
 * a caller can tell "my transport refused this" from "the peer rejected this".
 */
const MCP_RE_ERROR_CODE = -31001;

// A verified rejection receipt that carried no (or an empty) wire code. The receipt is a
// genuine refusal whose signature verified, so no `mcp-re.*` token may stand in for the one
// the peer did not send; the condition is the SDK's own and carries its prefix.
export const NO_PEER_WIRE_CODE = "mcp-re-sdk: verified rejection carried no wire code";

/**
 * The client tried to send a client->server RESPONSE, which has no MCP-RE carrier.
 *
 * A server-initiated request (sampling, elicitation over the same session) would be
 * answered by a JSON-RPC response travelling client->server. MCP-RE profiles two client
 * message shapes — a request that earns a signed reply, and a notification that earns a
 * signed bodyless 202 — and a response is neither.
 *
 * Failing closed here is the narrow choice on purpose. The alternative the notification
 * path makes available is worse: a response has no `method`, so carrying it as a
 * notification would mean signing a fabricated message and reporting the acknowledgement
 * of THAT as if the response had been delivered.
 */
export class ClientResponseUnsupported extends McpReSdkError {
  override name = "ClientResponseUnsupported";
}

/**
 * A notification was transmitted and its acknowledgement did not verify.
 *
 * The message left this process. What could not be established is that the enforcement
 * boundary authenticated and accepted it: the 202 was absent, unsigned, signed by an
 * untrusted key, or bound to a different transmission.
 *
 * It is thrown from `send()`, so the caller that emitted the notification is the one
 * that learns it was not acknowledged — there is no reply for a JSON-RPC error to ride
 * back on, and treating an unverifiable acknowledgement as delivery is the
 * take-it-on-faith posture this protocol exists to remove. `wireCode` carries the frozen
 * reason when the failure has one.
 */
export class NotificationNotAcknowledged extends McpReSdkError {
  readonly method: string;
  readonly wireCode: string;

  constructor(method: string, wireCode: string) {
    super(
      `'${method}' was sent but its acknowledgement did not verify (${wireCode}); ` +
        `it must not be treated as delivered`,
    );
    this.name = "NotificationNotAcknowledged";
    this.method = method;
    this.wireCode = wireCode;
  }
}

/**
 * The transport is not open for work: it has not started, or it is closing/closed.
 *
 * Also what queued and in-flight local requests fail with when `close()` aborts them.
 *
 * **This says nothing about the server.** Cancelling a local `poster` call does not mean
 * the request never arrived or that already-dispatched remote work has stopped — only
 * that this client will not process an answer to it.
 */
export class ConnectionClosed extends McpReSdkError {
  override name = "ConnectionClosed";
}

/**
 * A verified elicitation could not be answered, so the call did not complete.
 *
 * An ADR-MCPS-047 `InputRequiredResult` is a PAUSE, not an outcome. When no answer leg can
 * be driven — no {@link McpReConfig.answerInputRequired}, a handler that declined, or a
 * server that elicited past {@link McpReConfig.maxContinuationRounds} — the exchange ends
 * here.
 *
 * It ends as an ERROR, never as a result. Handing the pause up as the reply to
 * `callTool` would present a call that is still waiting for input as one that finished,
 * which is the misrepresentation the continuation profile's protected non-terminal
 * classification exists to make detectable (§5.2, §9.3).
 */
export class ContinuationNotAnswered extends McpReSdkError {
  override name = "ContinuationNotAnswered";
}

/**
 * A verified reply body is not a JSON-RPC RESPONSE, so it is not an answer at all.
 *
 * A signature proves the server said these bytes. It does not prove the bytes are a reply
 * to anything, and `JSONRPCMessageSchema` is a UNION: a body carrying both a legal
 * `result` and a top-level `method` validates as a `JSONRPCRequest`, and `Protocol`
 * dispatches it as a server-initiated request — `sampling/createMessage`,
 * `elicitation/create`, `roots/list` — running the application's handlers on
 * peer-chosen params over a channel MCP-RE profiles no carrier for, and one `send()`
 * explicitly refuses in the other direction. The awaiting `callTool` never resolves
 * either, because its id was consumed as an inbound request id.
 *
 * The Rust ambassador refuses the same body and so does the Python twin; this is the
 * behaviour the byte-parity fixtures cannot see.
 */
export class VerifiedReplyNotAResponse extends McpReSdkError {
  override name = "VerifiedReplyNotAResponse";
}

/**
 * The structured facts a verified rejection receipt carried, for `error.data`.
 *
 * `requestBound` is the core's verdict on whether the receipt is tied to THIS
 * transmission (RSP-7). The rest is the ADR-MCPRE-058 §10 execution / retry contract the
 * server derived from its exchange machine and signed into the body: without it a
 * post-dispatch refusal is indistinguishable from an ordinary outage, and the caller's
 * retry re-executes a tool call that already ran.
 *
 * Only members the receipt actually carried are emitted. An absent `executionStatus`
 * means the server stated nothing, and inventing `not_executed` for it would collapse
 * "unknown whether it ran" into "it did not run" at the one place that decides. The
 * Python twin emits the same keys — this is behaviour, so byte fixtures do not cover it.
 */
export function rejectionData(verified: {
  bound: boolean;
  executionStatus?: string | null;
  retrySafety?: string | null;
  continuationStatus?: string | null;
  retentionStatus?: string | null;
}): Record<string, unknown> {
  const data: Record<string, unknown> = { requestBound: verified.bound };
  const members: [string, string | null | undefined][] = [
    ["executionStatus", verified.executionStatus],
    ["retrySafety", verified.retrySafety],
    ["continuationStatus", verified.continuationStatus],
    ["retentionStatus", verified.retentionStatus],
  ];
  for (const [key, value] of members) {
    if (value !== undefined && value !== null) data[key] = value;
  }
  return data;
}

/**
 * The frozen `mcp-re.*` token a core refusal carries, or `null`.
 *
 * The napi binding throws a core refusal with the frozen token as the error's `code` —
 * a typed field, never prose to parse — and nothing else it throws has a `code` in that
 * namespace. What the taxonomy pins, and what a caller branches on (REQ-14/POL-6), is that
 * token; the Python twin reads the same token from `WireRefusal.wire_code`.
 *
 * `null` for anything else, so a local condition — a reset connection, a TLS error, a
 * timeout thrown by the caller's `poster` — is delivered under the `mcp-re-sdk:` prefix
 * instead of occupying the field that otherwise only ever holds something the peer said.
 */
const coreWireCode = (e: unknown): string | null => {
  const code = (e as { code?: unknown }).code;
  return typeof code === "string" && code.startsWith("mcp-re.") ? code : null;
};

/**
 * The wire code a plain `Error` is delivered under: the frozen token when it is a core
 * refusal, otherwise the `mcp-re-sdk:` prefix that means "local condition", named.
 */
export const plainErrorWireCode = (e: Error): string =>
  coreWireCode(e) ?? `mcp-re-sdk: ${e.name}: ${e.message}`;

/**
 * A JSON-RPC error correlated to the request, so the awaiting call rejects.
 *
 * `data` carries structured facts about the verdict that are not part of the frozen
 * token — the token itself stays exactly what the peer said.
 */
export const errorMessage = (id: RequestId, wireCode: string, data?: unknown): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  error: {
    code: MCP_RE_ERROR_CODE,
    message: wireCode,
    ...(data === undefined ? {} : { data }),
  },
});
