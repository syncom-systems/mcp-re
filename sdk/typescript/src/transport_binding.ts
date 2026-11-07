// SPDX-License-Identifier: Apache-2.0
/**
 * Authorization bindings as the transport signs them: the serialized bytes that ride in the
 * evidence block, and the digest kept for audit.
 */
import { createHash } from "node:crypto";

import {
  bindingsJson as serializeBindings,
  type BindingRequestContext,
} from "./authorization.js";
import type { McpReConfig } from "./transport_config.js";

/**
 * `sha-256:<b64url>` over the exact authorization-binding bytes that were signed.
 *
 * ADR-MCPS-044 enumerates this among the fields a conforming client keeps per outstanding
 * request. It is retained for audit only and never re-interpreted (bind-not-interpret): it
 * records WHICH authorization artefacts this request was bound to, so an audit trail can
 * be reconciled against the signed bytes without the transport ever parsing them. `null`
 * when the request carried no bindings.
 */
export function authzBindingDigest(bindingsJson: string | null): string | null {
  if (bindingsJson === null) return null;
  return `sha-256:${createHash("sha256").update(bindingsJson, "utf8").digest("base64url")}`;
}

/** The serialized authorization bindings for one outgoing `method`, or `null` when none. */
export function bindingsJsonFor(config: McpReConfig, method: string): string | null {
  const providers = config.authorization ?? [];
  if (providers.length === 0) return null;
  const context: BindingRequestContext = {
    audienceId: config.audienceId,
    targetUri: config.targetUri,
    method,
    route: config.route ?? null,
  };
  return serializeBindings(providers, context);
}
