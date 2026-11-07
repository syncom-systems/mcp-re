// SPDX-License-Identifier: Apache-2.0
/**
 * Shaping a verified reply into what `Client` is awaiting: a plain JSON-RPC response with
 * the evidence block removed and the id the client issued.
 */
import type { RequestId } from "@modelcontextprotocol/client";

import { VerifiedReplyNotAResponse } from "./transport_errors.js";

/**
 * The verified reply as plain MCP: evidence block removed, id the client's own.
 *
 * Read only AFTER verification: the content-digest covered these bytes.
 *
 * MCP-RE's own evidence is not part of the MCP result, and the rebuild below drops it
 * with every other top-level member the server sent. The id is restored because an ADR-MCPS-047 answer leg is an independent request with its own id
 * (SEP-2322 §retry), while the client issued exactly one call and is awaiting the id it
 * chose. Relabelling is the adapter's job at that seam — every hop was verified here, so
 * the terminal result it hands up is a complete record (§9.3), not a spliced one.
 *
 * The envelope is REBUILT from the one member the server sent, not edited in place.
 * Editing left every other top-level key in the document, and `JSONRPCMessageSchema` is a
 * union that accepts a request — so a body carrying both a legal `result` and a `method`
 * validated as a `JSONRPCRequest` and was dispatched by `Client` as a SERVER-INITIATED
 * request. See {@link VerifiedReplyNotAResponse}.
 */
export function plainMcpReply(body: Buffer, requestId: RequestId): unknown {
  const response = plainResponseObject(JSON.parse(body.toString("utf8")));
  response.id = requestId;
  return response;
}

const isJsonObject = (doc: unknown): doc is Record<string, unknown> =>
  doc !== null && typeof doc === "object" && !Array.isArray(doc);

/**
 * The verified reply as a JSON-RPC RESPONSE, or throw.
 *
 * The one shape `Client` is awaiting is a response object carrying exactly one of
 * `result` / `error`. Every other shape is refused here rather than handed to the union
 * schema, which would pick whichever arm matched. Mirrors the Rust ambassador's
 * `plain_response_from_verified` and the Python twin's `_plain_response_object`.
 */
function plainResponseObject(doc: unknown): Record<string, unknown> {
  if (!isJsonObject(doc)) {
    throw new VerifiedReplyNotAResponse(
      `a verified reply must be a JSON-RPC response object, got ${Array.isArray(doc) ? "array" : typeof doc}`,
    );
  }
  const member = responseMember(doc);
  return { jsonrpc: "2.0", id: doc.id, [member]: doc[member] };
}

/** The one of `result` / `error` a response object carries; anything else is refused. */
function responseMember(object: Record<string, unknown>): "result" | "error" {
  if ("method" in object) {
    // A JSON-RPC response has no `method`. Its presence is what makes the union schema
    // pick the REQUEST arm, so this is not a stray field — it is the whole confusion.
    // Refused rather than dropped: rebuilding would silently accept a reply the peer
    // deliberately shaped as something else.
    throw new VerifiedReplyNotAResponse(
      "a verified reply carries a top-level `method`; a JSON-RPC response has none",
    );
  }
  const hasResult = "result" in object;
  const hasError = "error" in object;
  if (hasResult && hasError) {
    throw new VerifiedReplyNotAResponse("a verified reply carries both a result and an error");
  }
  if (!hasResult && !hasError) {
    throw new VerifiedReplyNotAResponse("a verified reply carries neither a result nor an error");
  }
  return hasResult ? "result" : "error";
}

/** The `result` object of a verified reply, for an answer-leg handler to read. */
export function verifiedResult(body: Buffer): Record<string, unknown> {
  const result = JSON.parse(body.toString("utf8"))?.result;
  return isJsonObject(result) ? result : {};
}
