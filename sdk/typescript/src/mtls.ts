// SPDX-License-Identifier: Apache-2.0
/**
 * The mTLS connect helper (ADR-MCPS-044 §client obligation).
 *
 * {@link McpReHttpTransport} takes its HTTP leg as an injected `poster` so that layer
 * stays transport-agnostic and testable. This module builds the leg a real deployment
 * needs: a **verifying** mutual-TLS connection to `mcp-re-proxy`.
 *
 * ```ts
 * const transport = connectMtlsHttp(config, { serverCa, clientCert, clientKey });
 * const client = new Client({ name: "app", version: "1.0.0" });
 * await client.connect(transport);
 * ```
 *
 * It mirrors the Rust client leg (`mcp_re_transport::remote::MtlsRemoteTransport`), and
 * the properties that matter are the same ones:
 *
 * - **only the configured CA authenticates the proxy.** Node's bundled roots are
 *   replaced, not extended, so a certificate from any other public or corporate root is
 *   refused.
 * - **the server's identity is proven, not assumed.** The certificate must be valid for
 *   `serverName` — what the address is dialled for, not merely where it answered.
 * - **a client certificate is presented**, for the proxy's own binding check.
 * - **one connection per exchange**, matching the proxy's framing.
 * - **every bound fails closed**: a connect/read that stalls past `timeoutMs`, or a
 *   response past `maxResponseBytes`, rejects rather than hanging or buffering without
 *   bound. `timeoutMs` is BOTH the per-socket inactivity bound and an aggregate
 *   wall-clock bound on reading the response, because the first alone bounds nothing: it
 *   is re-armed by every byte, so a peer trickling under it holds an exchange — and its
 *   concurrency slot — indefinitely.
 *
 * There is no way to turn verification off. A helper with a `rejectUnauthorized: false`
 * knob is how mTLS deployments quietly become TLS-shaped plaintext, and the evidence
 * layer above it cannot detect that — a response signature verifies identically whether
 * or not the channel proved who produced it.
 *
 * The signed request is carried unchanged: MCP-RE's evidence lives in the headers and
 * body (RFC 9421 `Signature`/`Signature-Input`, RFC 9530 `Content-Digest`), so this must
 * transmit exactly what was signed and hand back exactly what arrived.
 */
import type { Buffer } from "node:buffer";

import { exchange } from "./mtls_exchange.js";
import { MtlsTransportError } from "./mtls_errors.js";
import { resolveSettings, type MtlsOptions } from "./mtls_settings.js";
import { McpReHttpTransport, type McpReConfig, type Poster } from "./transport.js";

export { MtlsTransportError, type MtlsOptions };

/**
 * A {@link Poster} that sends each signed request over one verifying mTLS connection.
 *
 * The endpoint is resolved once, here, so a malformed target fails at construction rather
 * than on the first request. Use this directly to compose the connection with an existing
 * transport; {@link connectMtlsHttp} is the one-call form.
 */
export function mtlsPoster(config: McpReConfig, options: MtlsOptions): Poster {
  const settings = resolveSettings(config.targetUri, options);
  return (method, _targetUri, headers, body: Buffer) =>
    exchange(settings, options, { method, headers, body });
}

/**
 * An {@link McpReHttpTransport} whose HTTP leg is a verifying mTLS connection.
 *
 * Returns the transport ready for `client.connect(...)`; this only supplies the
 * connection, so everything the adapter guarantees — signing, delegated verification,
 * correlation, continuation — is unchanged.
 */
export function connectMtlsHttp(config: McpReConfig, options: MtlsOptions): McpReHttpTransport {
  return new McpReHttpTransport(config, mtlsPoster(config, options));
}
