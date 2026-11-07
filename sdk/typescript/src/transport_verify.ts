// SPDX-License-Identifier: Apache-2.0
/**
 * Handing the native core a received reply to verify, with the trust anchor from the
 * configuration.
 *
 * The core is only correct about the request it is GIVEN, so both entry points take the
 * `signed` value the transport POSTed and pass its method, target, headers and body on
 * unchanged — nothing is re-derived or re-serialized for the verifier.
 */
import {
  verifyAccepted202,
  verifyResponse,
  type AcceptedResultJs,
  type SignedRequestJs,
  type VerifyResultJs,
} from "../native/binding.js";
import type { HttpReply, McpReConfig } from "./transport_config.js";

/**
 * The trust inputs the core's verifiers take after the exchange's bytes: the root issuer
 * anchor, the audience scope, the accepted trust epochs, the skew, the client's static
 * denylist, and the instant the verdict is judged at.
 */
function trustInputs(
  config: McpReConfig,
  now: number,
): [string, string, string, string, string, string[], string, string[], number, string[], number] {
  return [
    config.issuerKeyId,
    config.issuerPubkeyB64Url,
    config.issuerRole ?? "server",
    config.issuerTrustDomain,
    config.issuerSubject,
    [...config.verifierAudiences],
    config.expectedAudienceHash,
    [...config.acceptedEpochs],
    config.maxClockSkew ?? 60,
    [...(config.revokedIdentifiers ?? [])],
    now,
  ];
}

/** Verify a bodied reply against the request that earned it. */
export function verifyReply(
  config: McpReConfig,
  reply: HttpReply,
  signed: SignedRequestJs,
  now: number,
): VerifyResultJs {
  return verifyResponse(
    reply.status,
    reply.headers,
    reply.body,
    signed.method,
    signed.targetUri,
    signed.headers,
    signed.body,
    ...trustInputs(config, now),
  );
}

/** Verify the signed bodyless 202 a notification earns against the notification sent. */
export function verifyAcknowledgement(
  config: McpReConfig,
  reply: HttpReply,
  signed: SignedRequestJs,
  now: number,
): AcceptedResultJs {
  return verifyAccepted202(
    reply.status,
    reply.headers,
    reply.body,
    signed.method,
    signed.targetUri,
    signed.headers,
    signed.body,
    ...trustInputs(config, now),
  );
}
