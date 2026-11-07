// SPDX-License-Identifier: Apache-2.0
/**
 * One signed request over one verifying mTLS connection: the request that is dialled, the
 * header block that is emitted, and the bounded read of the response.
 */
import { request as httpsRequest } from "node:https";
import type { ClientRequest, IncomingMessage } from "node:http";

import type { HttpHeader } from "../native/binding.js";
import { MtlsTransportError } from "./mtls_errors.js";
import type { MtlsOptions, MtlsSettings } from "./mtls_settings.js";
import type { HttpReply } from "./transport.js";

/**
 * Headers this transport owns because it owns the framing. A caller that could set one
 * could desynchronise the message boundary from what the peer parses — the classic
 * request-smuggling shape — so supplying one fails closed rather than being silently
 * dropped or duplicated. Same list the Rust client refuses.
 */
const TRANSPORT_OWNED_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding"]);

/** The refusal for the first header this transport owns, or `undefined` when none is. */
function transportOwnedHeaderRefusal(headers: HttpHeader[]): MtlsTransportError | undefined {
  for (const { key } of headers) {
    if (TRANSPORT_OWNED_HEADERS.has(key.toLowerCase())) {
      return new MtlsTransportError(
        `${key.toLowerCase()} is set by the transport and must not be signed into a request`,
      );
    }
  }
  return undefined;
}

function openRequest(
  settings: MtlsSettings,
  options: MtlsOptions,
  method: string,
  bodyLength: number,
): ClientRequest {
  const { serverName, port, host, path } = settings.endpoint;
  return httpsRequest({
    host,
    port,
    path,
    method,
    // `servername` is BOTH the SNI sent and the name the certificate is checked
    // against, and it is the configured identity — not `host`, which is only where
    // the connection goes.
    servername: serverName,
    ca: options.serverCa,
    cert: options.clientCert,
    key: options.clientKey,
    passphrase: options.clientKeyPassphrase,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    // One connection per exchange, as the proxy frames it. `agent: false` also keeps
    // this off the global pool, where a socket authenticated for another identity
    // could otherwise be reused.
    agent: false,
    setHost: false,
    headers: {
      // The identity proven, not the address dialled: a Host header naming the load
      // balancer would describe a different resource than the one authenticated.
      Host: serverName,
      "Content-Length": String(bodyLength),
      Connection: "close",
    },
    timeout: settings.timeoutMs,
  });
}

/**
 * Grouped by name before emitting: `setHeader` REPLACES a header of the same
 * name, so two fields with one name would transmit only the last — dropping
 * bytes the RFC 9421 signature covers, and producing a request whose own
 * signature base no longer matches. The core emits no repeated names today;
 * this keeps the leg correct if the profile ever covers one, which is what the
 * Python twin already does by writing header by header.
 */
function groupByName(headers: HttpHeader[]): Map<string, string[]> {
  const grouped = new Map<string, string[]>();
  for (const { key, value } of headers) {
    const existing = grouped.get(key);
    if (existing) existing.push(value);
    else grouped.set(key, [value]);
  }
  return grouped;
}

/** `setHeader` refuses a CR/LF in a value, so a header that would split the request never emits. */
function emitHeaders(req: ClientRequest, headers: HttpHeader[]): void {
  for (const [key, values] of groupByName(headers)) {
    req.setHeader(key, values.length === 1 ? values[0] : values);
  }
}

/**
 * The response headers from `rawHeaders`, not `headers`: lowercased and in WIRE ORDER,
 * keeping repeats distinct. The signature base is built from what arrived, and Node's
 * parsed map folds duplicates into arrays.
 */
function wireHeaders(res: IncomingMessage): HttpHeader[] {
  const parsed: HttpHeader[] = [];
  for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
    parsed.push({ key: res.rawHeaders[i].toLowerCase(), value: res.rawHeaders[i + 1] });
  }
  return parsed;
}

/**
 * The AGGREGATE bound on reading the response, in addition to the per-socket
 * inactivity timer. `timeout` is re-armed by every byte that arrives, so a
 * peer trickling just under it holds this exchange — and the transport semaphore
 * slot it occupies — open for as long as it cares to; `maxConcurrentExchanges`
 * such responses wedge the whole client session with no error and no timeout.
 * The Rust client leg this module mirrors bounds total read time at the same
 * value (MCPS-093 `read_response_bounded`); this is that bound.
 *
 * `undefined` timeoutMs disables both, preserving the "no bound" knob's meaning.
 */
function armReadDeadline(
  res: IncomingMessage,
  timeoutMs: number | undefined,
  reject: (e: MtlsTransportError) => void,
): (() => void) {
  if (timeoutMs === undefined) return () => undefined;
  const deadline = setTimeout(() => {
    res.destroy();
    reject(
      new MtlsTransportError(`the aggregate response read exceeded ${timeoutMs}ms (slow-loris trickle)`),
    );
  }, timeoutMs);
  return () => clearTimeout(deadline);
}

function readResponse(
  res: IncomingMessage,
  settings: MtlsSettings,
  resolve: (reply: HttpReply) => void,
  reject: (e: MtlsTransportError) => void,
): void {
  const { maxResponseBytes, timeoutMs } = settings;
  const chunks: Buffer[] = [];
  let size = 0;
  const settled = armReadDeadline(res, timeoutMs, reject);
  res.on("data", (chunk: Buffer) => {
    size += chunk.length;
    if (size > maxResponseBytes) {
      // Stop reading rather than buffer a hostile length to find out how big it is.
      settled();
      res.destroy();
      reject(new MtlsTransportError(`response exceeded maxResponseBytes (${maxResponseBytes})`));
      return;
    }
    chunks.push(chunk);
  });
  res.on("error", (e) => {
    settled();
    reject(new MtlsTransportError(`the response could not be read: ${e.message}`));
  });
  res.on("end", () => {
    settled();
    resolve({ status: res.statusCode ?? 0, headers: wireHeaders(res), body: Buffer.concat(chunks) });
  });
}

/** The signed request one exchange carries, exactly as it was signed. */
export interface SignedRequest {
  method: string;
  headers: HttpHeader[];
  body: Buffer;
}

/** Send one signed request and resolve with exactly what arrived. */
export function exchange(
  settings: MtlsSettings,
  options: MtlsOptions,
  { method, headers, body }: SignedRequest,
): Promise<HttpReply> {
  return new Promise<HttpReply>((resolve, reject) => {
    const refusal = transportOwnedHeaderRefusal(headers);
    if (refusal) {
      reject(refusal);
      return;
    }

    const req = openRequest(settings, options, method, body.length);

    // Registered BEFORE anything can destroy the request. `destroy()` emits `error` on
    // the next tick, and a ClientRequest with no `error` listener throws that as an
    // unhandled exception — taking down the host process for what is, here, a refusal
    // this poster has already reported by rejecting.
    req.on("timeout", () => {
      req.destroy(new MtlsTransportError(`the exchange timed out after ${settings.timeoutMs}ms`));
    });
    req.on("error", (e) => {
      // A handshake rejection — untrusted chain, wrong identity, expired certificate —
      // arrives here, as does a reset or a timeout. All are failed channels. Rejecting
      // an already-settled promise is a no-op, which is what makes it safe to also
      // reject at the throw sites below.
      reject(e instanceof MtlsTransportError ? e : new MtlsTransportError(`the connection failed: ${e.message}`));
    });

    try {
      emitHeaders(req, headers);
    } catch (e) {
      reject(new MtlsTransportError(`refusing to emit a malformed header: ${String(e)}`));
      req.destroy();
      return;
    }

    req.on("response", (res) => readResponse(res, settings, resolve, reject));
    req.end(body);
  });
}
