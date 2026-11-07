// SPDX-License-Identifier: Apache-2.0
import { McpReSdkError } from "./custody.js";

/**
 * The channel failed: handshake refused, timed out, or an over-sized response.
 *
 * A LOCAL condition, never an MCP-RE verdict. A proxy that cannot authenticate itself is
 * a failed channel, not a failed signature, and it must not be reported as bad evidence —
 * nothing was signed, verified, or rejected here.
 */
export class MtlsTransportError extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "MtlsTransportError";
  }
}
