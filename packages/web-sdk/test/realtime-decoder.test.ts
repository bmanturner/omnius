import { describe, expect, it } from "vitest";

import { decodeRealtimeWireMessage } from "../src/internal/generated/realtime.js";

const EVENT_ID = "01890f47-7e7a-7c8a-9abc-1234567890ab";
const SUBSCRIPTION_ID = "01890f47-7e7a-7c8a-9abc-1234567890ac";
const KNOWN_DOMAIN_EVENTS: ReadonlySet<string> = new Set([
  "organization.updated.v1",
]);

function validDomainEvent(): Record<string, unknown> {
  return {
    v: 1,
    id: EVENT_ID,
    type: "organization.updated.v1",
    correlation_id: null,
    payload: {
      subscription_id: SUBSCRIPTION_ID,
      topic: "organizations/organization-1",
      cursor: "cursor-2",
      data: { organization_id: "organization-1", revision: 2 },
    },
  };
}

describe("generated realtime decoder", () => {
  it("decodes the exact AsyncAPI domain-event envelope without coercion", () => {
    const input = validDomainEvent();

    expect(decodeRealtimeWireMessage(input, KNOWN_DOMAIN_EVENTS)).toEqual({
      ok: true,
      value: input,
    });
  });

  it.each([
    ["null", null],
    ["array", []],
    ["missing required property", { v: 1, id: EVENT_ID, type: "ping", payload: {} }],
    [
      "non-v7 identifier",
      {
        v: 1,
        id: "01890f47-7e7a-4c8a-9abc-1234567890ab",
        type: "ping",
        correlation_id: null,
        payload: {},
      },
    ],
    [
      "identifier with a trailing newline",
      {
        v: 1,
        id: `${EVENT_ID}\n`,
        type: "ping",
        correlation_id: null,
        payload: {},
      },
    ],
    [
      "unexpected envelope property",
      {
        v: 1,
        id: EVENT_ID,
        type: "ping",
        correlation_id: null,
        payload: {},
        credentials: "must-not-be-accepted",
      },
    ],
    [
      "unexpected payload property",
      {
        v: 1,
        id: EVENT_ID,
        type: "ping",
        correlation_id: null,
        payload: { extra: true },
      },
    ],
    [
      "nonportable cursor",
      {
        ...validDomainEvent(),
        payload: {
          subscription_id: SUBSCRIPTION_ID,
          topic: "organizations/organization-1",
          cursor: "cursor with spaces",
          data: {},
        },
      },
    ],
  ])("rejects %s with exact trust-boundary validation", (_name, input) => {
    expect(decodeRealtimeWireMessage(input, KNOWN_DOMAIN_EVENTS)).toEqual({
      ok: false,
      reason: "invalid",
    });
  });

  it("distinguishes an unknown protocol version from an invalid envelope", () => {
    expect(
      decodeRealtimeWireMessage({
        v: 2,
        id: EVENT_ID,
        type: "ping",
        correlation_id: null,
        payload: {},
      }, KNOWN_DOMAIN_EVENTS),
    ).toEqual({ ok: false, reason: "unknown-version" });
  });

  it("distinguishes an unknown reserved wire type without treating it as a domain event", () => {
    expect(
      decodeRealtimeWireMessage({
        v: 1,
        id: EVENT_ID,
        type: "reconnect",
        correlation_id: null,
        payload: {},
      }, KNOWN_DOMAIN_EVENTS),
    ).toEqual({ ok: false, reason: "unknown-type" });
  });

  it("reports an unselected domain event as unknown instead of coercing it", () => {
    expect(decodeRealtimeWireMessage(validDomainEvent())).toEqual({
      ok: false,
      reason: "unknown-type",
    });
  });
});
