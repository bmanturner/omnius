import { describe, expect, it } from "vitest";

import {
  LlmStreamProtocolError,
  parseLlmEventStream,
  type ValidatedLlmStreamItem,
} from "../src/llm/index.js";

const REQUEST_ID = "request-1";
const SCHEMA_VERSION = "1.0.0";

function streamOf(events: readonly unknown[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const event of events) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      }
      controller.close();
    },
  });
}

function canonicalEvent(sequence: number): unknown {
  return {
    schema_version: SCHEMA_VERSION,
    request_id: REQUEST_ID,
    sequence,
    payload: {
      event: "event",
      data: { event: "response_start", data: { response_id: "response-1" } },
    },
  };
}

function terminalEvent(
  sequence: number,
  state:
    | "completed"
    | "provider_refused"
    | "safety_refused"
    | "invalid_structured_data"
    | "tool_execution_failed"
    | "budget_exhausted"
    | "cancelled"
    | "failed"
    | "partial_interrupted" = "completed",
): unknown {
  return {
    schema_version: SCHEMA_VERSION,
    request_id: REQUEST_ID,
    sequence,
    payload: {
      event: "terminal",
      data: {
        state: { state },
        accepted_public_content: [],
      },
    },
  };
}

async function collect(body: ReadableStream<Uint8Array>): Promise<ValidatedLlmStreamItem[]> {
  const items: ValidatedLlmStreamItem[] = [];
  for await (const item of parseLlmEventStream(body)) {
    items.push(item);
  }
  return items;
}

describe("canonical LLM SSE", () => {
  it("distinguishes the explicit terminal outcome", async () => {
    const items = await collect(streamOf([canonicalEvent(0), terminalEvent(1, "provider_refused")]));

    expect(items).toEqual([
      expect.objectContaining({ kind: "event" }),
      expect.objectContaining({ kind: "terminal", outcome: "provider_refused" }),
    ]);
  });

  it("rejects a stream that ends without a terminal event", async () => {
    const result = collect(streamOf([canonicalEvent(0)]));

    await expect(result).rejects.toBeInstanceOf(LlmStreamProtocolError);
  });

  it("rejects a sequence gap", async () => {
    const result = collect(streamOf([canonicalEvent(0), terminalEvent(2)]));

    await expect(result).rejects.toBeInstanceOf(LlmStreamProtocolError);
  });

  it("rejects an event after the sole terminal event", async () => {
    const result = collect(streamOf([terminalEvent(0), canonicalEvent(1)]));

    await expect(result).rejects.toBeInstanceOf(LlmStreamProtocolError);
  });

  it("rejects an unknown terminal state", async () => {
    const malformed = terminalEvent(0) as {
      payload: { data: { state: { state: string } } };
    };
    malformed.payload.data.state.state = "future_terminal";

    await expect(collect(streamOf([malformed]))).rejects.toBeInstanceOf(
      LlmStreamProtocolError,
    );
  });
});
