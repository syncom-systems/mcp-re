// SPDX-License-Identifier: Apache-2.0
/**
 * What a verifying mTLS client is configured with, and the refusals that keep a
 * configuration from silently weakening the channel: the options a caller writes, the
 * endpoint they resolve to, and the bounds every exchange runs under.
 */
import type { Buffer } from "node:buffer";

import { McpReSdkError } from "./custody.js";

/** Default response ceiling, mirroring the proxy's own `max_body_bytes`. */
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/** Default connect/read/write bound in ms, mirroring the Rust client's `ClientLimits`. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** The material and bounds for one verifying mTLS client. */
export interface MtlsOptions {
  /**
   * PEM of the ONLY roots trusted to authenticate the proxy. Node's bundled root store is
   * not consulted in addition to it.
   */
  serverCa: string | Buffer | (string | Buffer)[];
  /** PEM of the client certificate chain presented to the proxy. */
  clientCert: string | Buffer;
  /** PEM of its private key. */
  clientKey: string | Buffer;
  /** Passphrase for an encrypted `clientKey`. */
  clientKeyPassphrase?: string;

  /**
   * The identity the proxy must PROVE, matched against its certificate, and sent as SNI
   * and in the `Host` header. Defaults to the host of the config's `targetUri`.
   */
  serverName?: string;
  /**
   * Where to dial, when that is not `serverName`'s own address — a load balancer, a
   * port-forward, a test listener. The identity proven is still `serverName`.
   */
  connectHost?: string;
  /** The port to dial. Defaults to the target URI's, or 443. */
  connectPort?: number;

  /**
   * Bound on connect, on socket inactivity, and — as an aggregate wall clock — on
   * reading the whole response. Defaults to 30s. `null` disables all three, which lets a
   * stalled peer hold an exchange open indefinitely.
   */
  timeoutMs?: number | null;
  /** Response bytes buffered before failing closed. Defaults to 16 MiB. */
  maxResponseBytes?: number;
}

/** Where one exchange goes, and the name it must prove. */
export interface Endpoint {
  serverName: string;
  port: number;
  host: string;
  path: string;
}

/** The endpoint and the bounds every exchange of one client runs under. */
export interface MtlsSettings {
  endpoint: Endpoint;
  maxResponseBytes: number;
  /** `undefined` is "no bound", which only an explicit `null` option can ask for. */
  timeoutMs: number | undefined;
}

/**
 * Refuse TLS material that Node would silently treat as "not supplied".
 *
 * `createSecureContext` branches on truthiness: a falsy `ca` installs the bundled
 * public root store, and a falsy `cert`/`key` omits the client certificate. Neither
 * produces an error, so the failure is a working connection with the wrong trust.
 * A Buffer of length 0 and an empty (or whitespace-only) string are both that case.
 */
function assertTlsMaterial(
  field: string,
  value: string | Buffer | Array<string | Buffer> | undefined,
  purpose: string,
): void {
  const empty = (v: string | Buffer): boolean =>
    typeof v === "string" ? v.trim().length === 0 : v.length === 0;
  const missing =
    value === undefined ||
    (Array.isArray(value) ? value.length === 0 || value.every(empty) : empty(value));
  if (missing) {
    throw new McpReSdkError(
      `${field} is empty, so there is nothing to ${purpose}. Node treats absent TLS material ` +
        `as "not supplied" — an empty CA falls back to the bundled public roots and an empty ` +
        `client certificate is simply not sent, both without an error.`,
    );
  }
}

/** The target as an absolute `https:` URL, or the refusal that names why it is not one. */
function parseTarget(targetUri: string): URL {
  let url: URL;
  try {
    url = new URL(targetUri);
  } catch {
    throw new McpReSdkError(`targetUri is not absolute: ${JSON.stringify(targetUri)}`);
  }
  if (url.protocol !== "https:") {
    // An http:// target would be signed and sent in the clear. The evidence would still
    // verify, which is exactly why this cannot be left to the deployment.
    throw new McpReSdkError(
      `connectMtlsHttp needs an https:// targetUri, got ${JSON.stringify(targetUri)}`,
    );
  }
  return url;
}

function isTcpPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function resolvePort(url: URL, options: MtlsOptions): number {
  const port = options.connectPort ?? (url.port ? Number(url.port) : 443);
  if (!isTcpPort(port)) {
    throw new McpReSdkError(`connectPort must be a TCP port in 1..65535, got ${JSON.stringify(port)}`);
  }
  return port;
}

function resolveEndpoint(targetUri: string, options: MtlsOptions): Endpoint {
  const url = parseTarget(targetUri);
  const serverName = options.serverName ?? url.hostname;
  if (!serverName) {
    throw new McpReSdkError(`targetUri has no host to authenticate: ${JSON.stringify(targetUri)}`);
  }
  return {
    serverName,
    port: resolvePort(url, options),
    host: options.connectHost ?? serverName,
    // The signature covers the ABSOLUTE target URI; the request line carries the origin
    // form of it. Both sides derive the covered value from their own configuration, so
    // this conversion never feeds the signature base — it only routes the request.
    path: `${url.pathname || "/"}${url.search}`,
  };
}

function resolveMaxResponseBytes(options: MtlsOptions): number {
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new McpReSdkError(
      `maxResponseBytes must be a positive integer, got ${JSON.stringify(options.maxResponseBytes)}`,
    );
  }
  return maxResponseBytes;
}

/** A timeout the caller wrote that is neither absent, `null`, nor a positive number. */
function isInvalidTimeout(timeoutMs: number | null | undefined): boolean {
  if (timeoutMs === undefined || timeoutMs === null) return false;
  return !Number.isFinite(timeoutMs) || timeoutMs < 1;
}

function resolveTimeoutMs(options: MtlsOptions): number | undefined {
  // Node treats `timeout: 0` as NO timeout, and `??` only substitutes for null and
  // undefined — so a caller writing `timeoutMs: config.timeout ?? 0`, or reading a
  // numeric config that defaults to 0, silently removed the bound instead of getting
  // the default. Each exchange also holds a transport semaphore slot, so a handful of
  // stalls with no timeout wedge the whole client. `null` is the ONLY way to ask for
  // no bound, and it has to be written deliberately. The Python twin refuses `<= 0`
  // at construction; this is the same refusal.
  if (isInvalidTimeout(options.timeoutMs)) {
    throw new McpReSdkError(
      `timeoutMs must be a positive number, or null for no bound, got ${JSON.stringify(options.timeoutMs)}`,
    );
  }
  return options.timeoutMs === null ? undefined : (options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
}

/** Refuse every configuration that would weaken the channel, once, at construction. */
export function resolveSettings(targetUri: string, options: MtlsOptions): MtlsSettings {
  const endpoint = resolveEndpoint(targetUri, options);
  const maxResponseBytes = resolveMaxResponseBytes(options);
  const timeoutMs = resolveTimeoutMs(options);

  // TLS MATERIAL. Node's `createSecureContext` documents ca/cert/key as PERMITTED TO BE
  // FALSY, and takes the `else` branch for each: an empty `ca` installs Node's ~150
  // bundled public roots INSTEAD of the pinned CA, and an empty `cert`/`key` sends no
  // client certificate at all. Both handshake, both report success, and both are the
  // opposite of what this module's own docs promise ("Node's bundled roots are
  // replaced, not extended"; "There is no way to turn verification off").
  //
  // The realistic way in is not a hostile caller: it is `process.env.PROXY_CA ?? ""`,
  // an unpopulated secret mount, or `readFileSync` of a zero-byte file. So it is
  // refused here rather than documented.
  assertTlsMaterial("serverCa", options.serverCa, "authenticate the proxy");
  assertTlsMaterial("clientCert", options.clientCert, "prove this client's identity");
  assertTlsMaterial("clientKey", options.clientKey, "prove this client's identity");

  return { endpoint, maxResponseBytes, timeoutMs };
}
