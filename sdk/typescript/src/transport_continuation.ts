// SPDX-License-Identifier: Apache-2.0
/**
 * The answer step of an ADR-MCPS-047 continuation: whether an elicitation may be answered
 * at all, what the application's handler said, and the id and params of the leg that
 * carries the answer.
 *
 * Signing, posting and verifying the leg stay with the transport; this module decides only
 * what the answer is, and refuses with {@link ContinuationNotAnswered} whenever no honest
 * answer leg can be built.
 */
import type { RequestId } from "@modelcontextprotocol/client";

import type { ContinuationHandles } from "./correlation.js";
import type { InputRequired, McpReConfig } from "./transport_config.js";
import { ContinuationNotAnswered } from "./transport_errors.js";

type AnswerHandler = NonNullable<McpReConfig["answerInputRequired"]>;

/**
 * The JSON-RPC id for an answer leg.
 *
 * SEP-2322 makes the retry an INDEPENDENT request with a new id, so the chain must not
 * re-use the one the client issued. Derived from it rather than drawn at random, so a
 * capture or log shows which call the leg belongs to.
 */
export const answerLegId = (requestId: RequestId, round: number): string =>
  `${requestId}/mrt-${round}`;

/**
 * The handler that may answer elicitation number `round` of `method`, or a refusal.
 *
 * Checked BEFORE the handler runs: a call that has already used up its continuation budget
 * must not prompt for an answer it cannot send, and a pause with no handler installed is an
 * error rather than a result.
 */
export function answerHandlerFor(config: McpReConfig, method: string, round: number): AnswerHandler {
  const ceiling = config.maxContinuationRounds ?? 4;
  if (round > ceiling) {
    throw new ContinuationNotAnswered(
      `'${method}' elicited ${round} times, past the maxContinuationRounds ceiling ` +
        `of ${ceiling}`,
    );
  }
  if (!config.answerInputRequired) {
    throw new ContinuationNotAnswered(
      `'${method}' returned an ADR-MCPS-047 elicitation and no answerInputRequired ` +
        `handler is installed, so no answer leg can be signed`,
    );
  }
  return config.answerInputRequired;
}

/** Ask `handler` for the `inputResponses` of an answer leg, refusing a decline or a non-object. */
export async function collectAnswer(
  handler: AnswerHandler,
  prompt: InputRequired,
): Promise<Record<string, unknown>> {
  const responses = await handler(prompt);
  if (responses === null || responses === undefined) {
    throw new ContinuationNotAnswered(
      `the elicitation from '${prompt.method}' was declined by answerInputRequired`,
    );
  }
  if (typeof responses !== "object" || Array.isArray(responses)) {
    throw new ContinuationNotAnswered(
      `answerInputRequired returned ${Array.isArray(responses) ? "an array" : typeof responses}; ` +
        `the MRTR answer leg carries \`inputResponses\` as a JSON object`,
    );
  }
  return responses;
}

/**
 * The params of the next leg: the same call, carrying the answers and echoing the opaque
 * state back, bound to the handles of the exchange that asked for them.
 */
export const answerLegParams = (
  params: Record<string, unknown>,
  responses: Record<string, unknown>,
  handles: ContinuationHandles,
): Record<string, unknown> => ({
  ...params,
  inputResponses: responses,
  requestState: handles.requestState,
});
