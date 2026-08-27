import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const packageRootUrl = new URL("../", import.meta.url);
const contractUrl = new URL("../../contracts/asyncapi.json", packageRootUrl);
const outputUrl = new URL("./src/internal/generated/realtime.ts", packageRootUrl);

const arguments_ = process.argv.slice(2);
const check = arguments_.length === 1 && arguments_[0] === "--check";
if (arguments_.length > 0 && !check) {
  throw new TypeError("Usage: node scripts/generate-realtime.mjs [--check]");
}

const UUID_V7_PATTERN =
  "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const DOMAIN_TYPE_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$";
const TOPIC_PATTERN = "^[A-Za-z0-9._:/-]+$";
const CURSOR_PATTERN = "^[!-~]+$";
const JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";
const CORRELATION_LOCATION = "$message.payload#/correlation_id";

const UUID_SCHEMA = Object.freeze({
  format: "uuid",
  pattern: UUID_V7_PATTERN,
  type: "string",
});
const NULL_SCHEMA = Object.freeze({ type: "null" });
const CURSOR_SCHEMA = Object.freeze({
  maxLength: 256,
  minLength: 1,
  pattern: CURSOR_PATTERN,
  type: "string",
});
const TOPIC_SCHEMA = Object.freeze({
  maxLength: 128,
  minLength: 1,
  pattern: TOPIC_PATTERN,
  type: "string",
});
const ENVELOPE_REQUIRED = Object.freeze(["v", "id", "type", "correlation_id", "payload"]);
const RESERVED_WIRE_NAMES = Object.freeze([
  "subscription.create",
  "subscription.delete",
  "ping",
  "subscription.created",
  "subscription.deleted",
  "command.rejected",
  "pong",
  "subscription.revoked",
  "reconnect",
]);
const COMMAND_REJECTION_CODES = Object.freeze([
  "unauthorized",
  "connection_not_active",
  "not_found",
  "conflict",
  "capacity_exceeded",
  "unavailable",
]);
const REVOCATION_REASONS = Object.freeze([
  "authorization_changed",
  "membership_changed",
  "identity_revoked",
  "resource_removed",
]);
const SSE_RECONNECT_REASONS = Object.freeze(["slow-consumer", "server-draining"]);

function nullable(schema) {
  return { oneOf: [schema, NULL_SCHEMA] };
}

function objectSchema(properties, required) {
  return {
    additionalProperties: false,
    properties,
    required,
    type: "object",
  };
}

function envelopeSchema(type, correlation, payload) {
  return {
    $schema: JSON_SCHEMA_DIALECT,
    additionalProperties: false,
    properties: {
      correlation_id: correlation,
      id: UUID_SCHEMA,
      payload,
      type,
      v: { const: 1 },
    },
    required: ENVELOPE_REQUIRED,
    type: "object",
  };
}

const EMPTY_PAYLOAD_SCHEMA = objectSchema({}, []);
const SUBSCRIPTION_ID_PAYLOAD_SCHEMA = objectSchema(
  { subscription_id: UUID_SCHEMA },
  ["subscription_id"],
);
const SUBSCRIPTION_AND_TOPIC_PAYLOAD_SCHEMA = objectSchema(
  { subscription_id: UUID_SCHEMA, topic: TOPIC_SCHEMA },
  ["subscription_id", "topic"],
);

const MESSAGE_MODELS = Object.freeze({
  BrowserDomainEventV1: {
    contentType: "application/json",
    correlation: nullable(UUID_SCHEMA),
    direction: "server-to-client",
    payload: objectSchema(
      {
        cursor: nullable(CURSOR_SCHEMA),
        data: { maxProperties: 1024, type: "object" },
        subscription_id: UUID_SCHEMA,
        topic: TOPIC_SCHEMA,
      },
      ["subscription_id", "topic", "cursor", "data"],
    ),
    typeSchema: {
      not: { enum: RESERVED_WIRE_NAMES },
      pattern: DOMAIN_TYPE_PATTERN,
      type: "string",
    },
    wireName: null,
  },
  CommandRejectedV1: {
    contentType: "application/json",
    correlation: UUID_SCHEMA,
    direction: "server-to-client",
    payload: objectSchema(
      {
        code: { enum: COMMAND_REJECTION_CODES },
        message: { maxLength: 64, minLength: 1, type: "string" },
      },
      ["code", "message"],
    ),
    typeSchema: { const: "command.rejected" },
    wireName: "command.rejected",
  },
  PingV1: {
    contentType: "application/json",
    correlation: nullable(UUID_SCHEMA),
    direction: "client-to-server",
    payload: EMPTY_PAYLOAD_SCHEMA,
    typeSchema: { const: "ping" },
    wireName: "ping",
  },
  PongV1: {
    contentType: "application/json",
    correlation: UUID_SCHEMA,
    direction: "server-to-client",
    payload: EMPTY_PAYLOAD_SCHEMA,
    typeSchema: { const: "pong" },
    wireName: "pong",
  },
  SseReconnectV1: {
    contentType: "text/plain",
    direction: "server-to-client",
    reconnectReasons: SSE_RECONNECT_REASONS,
  },
  SubscriptionCreateV1: {
    contentType: "application/json",
    correlation: nullable(UUID_SCHEMA),
    direction: "client-to-server",
    payload: objectSchema(
      { cursor: CURSOR_SCHEMA, subscription_id: UUID_SCHEMA, topic: TOPIC_SCHEMA },
      ["subscription_id", "topic"],
    ),
    typeSchema: { const: "subscription.create" },
    wireName: "subscription.create",
  },
  SubscriptionCreatedV1: {
    contentType: "application/json",
    correlation: UUID_SCHEMA,
    direction: "server-to-client",
    payload: SUBSCRIPTION_AND_TOPIC_PAYLOAD_SCHEMA,
    typeSchema: { const: "subscription.created" },
    wireName: "subscription.created",
  },
  SubscriptionDeleteV1: {
    contentType: "application/json",
    correlation: nullable(UUID_SCHEMA),
    direction: "client-to-server",
    payload: SUBSCRIPTION_ID_PAYLOAD_SCHEMA,
    typeSchema: { const: "subscription.delete" },
    wireName: "subscription.delete",
  },
  SubscriptionDeletedV1: {
    contentType: "application/json",
    correlation: UUID_SCHEMA,
    direction: "server-to-client",
    payload: SUBSCRIPTION_ID_PAYLOAD_SCHEMA,
    typeSchema: { const: "subscription.deleted" },
    wireName: "subscription.deleted",
  },
  SubscriptionRevokedV1: {
    contentType: "application/json",
    correlation: NULL_SCHEMA,
    direction: "server-to-client",
    payload: objectSchema(
      {
        reason: { enum: REVOCATION_REASONS },
        subscription_id: UUID_SCHEMA,
      },
      ["subscription_id", "reason"],
    ),
    typeSchema: { const: "subscription.revoked" },
    wireName: "subscription.revoked",
  },
});

const contractText = await readFile(contractUrl, "utf8");
let contract;
try {
  contract = JSON.parse(contractText);
} catch {
  throw new TypeError(
    `Canonical AsyncAPI contract is not valid JSON: ${fileURLToPath(contractUrl)}`,
  );
}

function invalidContract(context) {
  throw new TypeError(
    `Canonical AsyncAPI contract is invalid at ${context}: ${fileURLToPath(contractUrl)}`,
  );
}

function assert(condition, context) {
  if (!condition) {
    invalidContract(context);
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expectRecord(value, context) {
  assert(isRecord(value), context);
  return value;
}

function assertExactKeys(value, expected, context) {
  const record = expectRecord(value, context);
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  assert(
    actual.length === wanted.length && actual.every((key, index) => key === wanted[index]),
    context,
  );
  return record;
}

function deepEqual(left, right) {
  if (Object.is(left, right)) {
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => deepEqual(value, right[index]))
    );
  }
  if (!isRecord(left) || !isRecord(right)) {
    return false;
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && deepEqual(left[key], right[key]),
    )
  );
}

function assertDeepEqual(actual, expected, context) {
  assert(deepEqual(actual, expected), context);
}

function assertNonEmptyString(value, context) {
  assert(typeof value === "string" && value.length > 0, context);
}

function assertMembers(actual, expected, context) {
  assert(Array.isArray(actual), context);
  assert(actual.every((value) => typeof value === "string"), context);
  const actualSorted = [...actual].sort();
  const expectedSorted = [...expected].sort();
  assert(
    actualSorted.length === expectedSorted.length &&
      actualSorted.every((value, index) => value === expectedSorted[index]),
    context,
  );
}

function decodePointerSegment(segment, context) {
  assert(!/~(?:[^01]|$)/u.test(segment), context);
  return segment.replaceAll("~1", "/").replaceAll("~0", "~");
}

function resolveLocalReference(reference, context) {
  assert(typeof reference === "string" && reference.startsWith("#/"), context);
  let current = contract;
  for (const encodedSegment of reference.slice(2).split("/")) {
    const segment = decodePointerSegment(encodedSegment, context);
    const record = expectRecord(current, context);
    assert(Object.hasOwn(record, segment), context);
    current = record[segment];
  }
  return current;
}

function assertReferenceObject(value, expectedReference, context) {
  const reference = assertExactKeys(value, ["$ref"], context);
  assert(reference.$ref === expectedReference, context);
  return reference;
}

function dereference(value, context) {
  let current = value;
  const seen = new Set();
  while (isRecord(current) && Object.hasOwn(current, "$ref")) {
    const reference = assertExactKeys(current, ["$ref"], context).$ref;
    assert(typeof reference === "string" && !seen.has(reference), context);
    seen.add(reference);
    current = resolveLocalReference(reference, context);
  }
  return current;
}

function validateAllReferences(value, context) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => validateAllReferences(entry, `${context}/${index}`));
    return;
  }
  if (!isRecord(value)) {
    return;
  }
  if (Object.hasOwn(value, "$ref")) {
    const reference = assertExactKeys(value, ["$ref"], context).$ref;
    resolveLocalReference(reference, context);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    validateAllReferences(child, `${context}/${key}`);
  }
}

assertExactKeys(
  contract,
  ["asyncapi", "channels", "components", "defaultContentType", "info", "operations", "servers"],
  "#/",
);
assert(contract.asyncapi === "3.1.0", "#/asyncapi");
assert(contract.defaultContentType === "application/json", "#/defaultContentType");
validateAllReferences(contract, "#");

const info = assertExactKeys(contract.info, ["description", "title", "version"], "#/info");
assertNonEmptyString(info.description, "#/info/description");
assert(info.title === "Omnius browser realtime contract", "#/info/title");
assert(info.version === "0.1.0", "#/info/version");

const components = assertExactKeys(
  contract.components,
  ["messages", "schemas", "securitySchemes"],
  "#/components",
);
const messages = expectRecord(components.messages, "#/components/messages");
assertMembers(Object.keys(messages), Object.keys(MESSAGE_MODELS), "#/components/messages");

for (const [name, model] of Object.entries(MESSAGE_MODELS)) {
  const context = `#/components/messages/${name}`;
  const message = expectRecord(messages[name], context);
  if (name === "SseReconnectV1") {
    assertExactKeys(
      message,
      [
        "contentType",
        "name",
        "payload",
        "summary",
        "title",
        "x-direction",
        "x-message-version",
        "x-sse-event",
      ],
      context,
    );
    assert(message.contentType === model.contentType, `${context}/contentType`);
    assert(message.name === name && message.title === name, `${context}/name`);
    assertNonEmptyString(message.summary, `${context}/summary`);
    assert(message["x-direction"] === model.direction, `${context}/x-direction`);
    assert(message["x-message-version"] === 1, `${context}/x-message-version`);
    assert(message["x-sse-event"] === "reconnect", `${context}/x-sse-event`);
    assertDeepEqual(
      message.payload,
      {
        $schema: JSON_SCHEMA_DIALECT,
        enum: model.reconnectReasons,
        type: "string",
      },
      `${context}/payload`,
    );
    continue;
  }

  assertExactKeys(
    message,
    [
      "contentType",
      "correlationId",
      "name",
      "payload",
      "summary",
      "title",
      "x-direction",
      "x-message-version",
      "x-wire-name",
    ],
    context,
  );
  assert(message.contentType === model.contentType, `${context}/contentType`);
  assert(message.name === name && message.title === name, `${context}/name`);
  assertNonEmptyString(message.summary, `${context}/summary`);
  assert(message["x-direction"] === model.direction, `${context}/x-direction`);
  assert(message["x-message-version"] === 1, `${context}/x-message-version`);
  const correlationId = assertExactKeys(
    message.correlationId,
    ["description", "location"],
    `${context}/correlationId`,
  );
  assertNonEmptyString(correlationId.description, `${context}/correlationId/description`);
  assert(correlationId.location === CORRELATION_LOCATION, `${context}/correlationId/location`);
  assertDeepEqual(
    message.payload,
    envelopeSchema(model.typeSchema, model.correlation, model.payload),
    `${context}/payload`,
  );
  if (name === "BrowserDomainEventV1") {
    assertDeepEqual(
      message["x-wire-name"],
      { pattern: DOMAIN_TYPE_PATTERN, reservedNamesExcluded: true },
      `${context}/x-wire-name`,
    );
  } else {
    assert(message["x-wire-name"] === model.wireName, `${context}/x-wire-name`);
  }
}

assertDeepEqual(
  components.schemas,
  {
    OpaqueCursor: CURSOR_SCHEMA,
    PortableTopic: TOPIC_SCHEMA,
    UuidV7: UUID_SCHEMA,
  },
  "#/components/schemas",
);
const securitySchemes = assertExactKeys(
  components.securitySchemes,
  ["sessionCookie"],
  "#/components/securitySchemes",
);
const sessionCookie = assertExactKeys(
  securitySchemes.sessionCookie,
  ["description", "in", "name", "type"],
  "#/components/securitySchemes/sessionCookie",
);
assertNonEmptyString(sessionCookie.description, "#/components/securitySchemes/sessionCookie/description");
assertDeepEqual(
  { in: sessionCookie.in, name: sessionCookie.name, type: sessionCookie.type },
  { in: "cookie", name: "__Host-omnius-session", type: "httpApiKey" },
  "#/components/securitySchemes/sessionCookie",
);

const servers = assertExactKeys(
  contract.servers,
  ["sameOriginHttp", "sameOriginWebSocket"],
  "#/servers",
);
function validateServer(name, expected) {
  const context = `#/servers/${name}`;
  const server = assertExactKeys(
    servers[name],
    ["bindings", "description", "host", "pathname", "protocol", "security", "variables"],
    context,
  );
  assertDeepEqual(server.bindings, expected.bindings, `${context}/bindings`);
  assertNonEmptyString(server.description, `${context}/description`);
  assert(server.host === "{host}", `${context}/host`);
  assert(server.pathname === expected.pathname, `${context}/pathname`);
  assert(server.protocol === expected.protocol, `${context}/protocol`);
  assertDeepEqual(server.variables, { host: { default: "localhost" } }, `${context}/variables`);
  assert(Array.isArray(server.security) && server.security.length === 1, `${context}/security`);
  const security = assertReferenceObject(
    server.security[0],
    "#/components/securitySchemes/sessionCookie",
    `${context}/security/0`,
  );
  assert(dereference(security, `${context}/security/0`) === sessionCookie, `${context}/security/0`);
}
validateServer("sameOriginHttp", {
  bindings: { http: { bindingVersion: "0.3.0" } },
  pathname: "/",
  protocol: "https",
});
validateServer("sameOriginWebSocket", {
  bindings: { ws: { bindingVersion: "0.1.0" } },
  pathname: "/realtime/ws",
  protocol: "wss",
});

const channels = assertExactKeys(
  contract.channels,
  ["realtimeEvents", "realtimeWebSocket"],
  "#/channels",
);
function validateChannelMessages(channelName, channelMessages, expectedNames) {
  const context = `#/channels/${channelName}/messages`;
  const messageMap = expectRecord(channelMessages, context);
  assertMembers(Object.keys(messageMap), expectedNames, context);
  for (const name of expectedNames) {
    const reference = assertReferenceObject(
      messageMap[name],
      `#/components/messages/${name}`,
      `${context}/${name}`,
    );
    assert(dereference(reference, `${context}/${name}`) === messages[name], `${context}/${name}`);
  }
}
function validateChannelServer(channelName, channelServers, serverName) {
  const context = `#/channels/${channelName}/servers`;
  assert(Array.isArray(channelServers) && channelServers.length === 1, context);
  const reference = assertReferenceObject(
    channelServers[0],
    `#/servers/${serverName}`,
    `${context}/0`,
  );
  assert(dereference(reference, `${context}/0`) === servers[serverName], `${context}/0`);
}

const realtimeEvents = assertExactKeys(
  channels.realtimeEvents,
  ["address", "bindings", "description", "messages", "servers", "title", "x-resume"],
  "#/channels/realtimeEvents",
);
assert(realtimeEvents.address === "/events", "#/channels/realtimeEvents/address");
assertDeepEqual(
  realtimeEvents.bindings,
  { http: { bindingVersion: "0.3.0" } },
  "#/channels/realtimeEvents/bindings",
);
assertNonEmptyString(realtimeEvents.description, "#/channels/realtimeEvents/description");
assertNonEmptyString(realtimeEvents.title, "#/channels/realtimeEvents/title");
assertDeepEqual(
  realtimeEvents["x-resume"],
  {
    cursorField: "$message.payload#/payload/cursor",
    duplicates: "at-least-once delivery; consumers must tolerate duplicates",
    lastEventIdHeader: "rejected to prevent ambiguous cursors",
    requestQuery: "cursor",
  },
  "#/channels/realtimeEvents/x-resume",
);
validateChannelMessages("realtimeEvents", realtimeEvents.messages, [
  "BrowserDomainEventV1",
  "SseReconnectV1",
  "SubscriptionRevokedV1",
]);
validateChannelServer("realtimeEvents", realtimeEvents.servers, "sameOriginHttp");

const realtimeWebSocket = assertExactKeys(
  channels.realtimeWebSocket,
  ["address", "bindings", "description", "messages", "servers", "title"],
  "#/channels/realtimeWebSocket",
);
assert(realtimeWebSocket.address === "/realtime/ws", "#/channels/realtimeWebSocket/address");
assertDeepEqual(
  realtimeWebSocket.bindings,
  {
    ws: {
      bindingVersion: "0.1.0",
      headers: {
        properties: { "Sec-WebSocket-Protocol": { const: "omnius.realtime.v1" } },
        required: ["Sec-WebSocket-Protocol"],
        type: "object",
      },
      method: "GET",
    },
  },
  "#/channels/realtimeWebSocket/bindings",
);
assertNonEmptyString(realtimeWebSocket.description, "#/channels/realtimeWebSocket/description");
assertNonEmptyString(realtimeWebSocket.title, "#/channels/realtimeWebSocket/title");
validateChannelMessages("realtimeWebSocket", realtimeWebSocket.messages, [
  "BrowserDomainEventV1",
  "CommandRejectedV1",
  "PingV1",
  "PongV1",
  "SubscriptionCreateV1",
  "SubscriptionCreatedV1",
  "SubscriptionDeleteV1",
  "SubscriptionDeletedV1",
  "SubscriptionRevokedV1",
]);
validateChannelServer("realtimeWebSocket", realtimeWebSocket.servers, "sameOriginWebSocket");

const operations = assertExactKeys(
  contract.operations,
  ["receiveWebSocketCommands", "sendServerSentEvents", "sendWebSocketMessages"],
  "#/operations",
);
function validateOperation(name, expected) {
  const context = `#/operations/${name}`;
  const expectedKeys = ["action", "channel", "messages", "security", "summary"];
  if (expected.bindings !== undefined) {
    expectedKeys.push("bindings");
  }
  const operation = assertExactKeys(operations[name], expectedKeys, context);
  assert(operation.action === expected.action, `${context}/action`);
  assertNonEmptyString(operation.summary, `${context}/summary`);
  if (expected.bindings !== undefined) {
    assertDeepEqual(operation.bindings, expected.bindings, `${context}/bindings`);
  }
  const channelReference = assertReferenceObject(
    operation.channel,
    `#/channels/${expected.channel}`,
    `${context}/channel`,
  );
  assert(
    dereference(channelReference, `${context}/channel`) === channels[expected.channel],
    `${context}/channel`,
  );
  assert(Array.isArray(operation.messages), `${context}/messages`);
  const operationReferences = operation.messages.map((message, index) => {
    const reference = assertExactKeys(message, ["$ref"], `${context}/messages/${index}`);
    assert(typeof reference.$ref === "string", `${context}/messages/${index}/$ref`);
    assert(
      dereference(reference, `${context}/messages/${index}`) ===
        messages[reference.$ref.slice(reference.$ref.lastIndexOf("/") + 1)],
      `${context}/messages/${index}`,
    );
    return reference.$ref;
  });
  assertMembers(
    operationReferences,
    expected.messages.map((message) => `#/channels/${expected.channel}/messages/${message}`),
    `${context}/messages`,
  );
  assert(Array.isArray(operation.security) && operation.security.length === 1, `${context}/security`);
  const securityReference = assertReferenceObject(
    operation.security[0],
    "#/components/securitySchemes/sessionCookie",
    `${context}/security/0`,
  );
  assert(
    dereference(securityReference, `${context}/security/0`) === sessionCookie,
    `${context}/security/0`,
  );
}
validateOperation("receiveWebSocketCommands", {
  action: "receive",
  channel: "realtimeWebSocket",
  messages: ["SubscriptionCreateV1", "SubscriptionDeleteV1", "PingV1"],
});
validateOperation("sendWebSocketMessages", {
  action: "send",
  channel: "realtimeWebSocket",
  messages: [
    "SubscriptionCreatedV1",
    "SubscriptionDeletedV1",
    "CommandRejectedV1",
    "PongV1",
    "SubscriptionRevokedV1",
    "BrowserDomainEventV1",
  ],
});
validateOperation("sendServerSentEvents", {
  action: "send",
  bindings: {
    http: {
      bindingVersion: "0.3.0",
      method: "GET",
      query: objectSchema(
        { cursor: CURSOR_SCHEMA, subscription_id: UUID_SCHEMA, topic: TOPIC_SCHEMA },
        ["subscription_id", "topic"],
      ),
    },
  },
  channel: "realtimeEvents",
  messages: ["SubscriptionRevokedV1", "BrowserDomainEventV1", "SseReconnectV1"],
});

const stringUnion = (values) => values.map((value) => JSON.stringify(value)).join(" | ");
const stringArray = (values) => values.map((value) => JSON.stringify(value)).join(", ");
const generated = `/* @generated by scripts/generate-realtime.mjs from contracts/asyncapi.json. Do not edit manually. */

export interface SubscriptionCreateV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "subscription.create";
  readonly correlation_id: string | null;
  readonly payload: {
    readonly subscription_id: string;
    readonly topic: string;
    readonly cursor?: string;
  };
}

export interface SubscriptionDeleteV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "subscription.delete";
  readonly correlation_id: string | null;
  readonly payload: {
    readonly subscription_id: string;
  };
}

export interface PingV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "ping";
  readonly correlation_id: string | null;
  readonly payload: Readonly<Record<never, never>>;
}

export interface SubscriptionCreatedV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "subscription.created";
  readonly correlation_id: string;
  readonly payload: {
    readonly subscription_id: string;
    readonly topic: string;
  };
}

export interface SubscriptionDeletedV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "subscription.deleted";
  readonly correlation_id: string;
  readonly payload: {
    readonly subscription_id: string;
  };
}

export type CommandRejectionCode = ${stringUnion(COMMAND_REJECTION_CODES)};

export interface CommandRejectedV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "command.rejected";
  readonly correlation_id: string;
  readonly payload: {
    readonly code: CommandRejectionCode;
    readonly message: string;
  };
}

export interface PongV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "pong";
  readonly correlation_id: string;
  readonly payload: Readonly<Record<never, never>>;
}

export type SubscriptionRevocationReason = ${stringUnion(REVOCATION_REASONS)};

export interface SubscriptionRevokedV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: "subscription.revoked";
  readonly correlation_id: null;
  readonly payload: {
    readonly subscription_id: string;
    readonly reason: SubscriptionRevocationReason;
  };
}

export interface DomainEventV1 {
  readonly v: 1;
  readonly id: string;
  readonly type: string;
  readonly correlation_id: string | null;
  readonly payload: {
    readonly subscription_id: string;
    readonly topic: string;
    readonly cursor: string | null;
    readonly data: Readonly<Record<string, unknown>>;
  };
}

export type SseReconnectReason = ${stringUnion(SSE_RECONNECT_REASONS)};

export type ClientRealtimeWireMessage =
  | SubscriptionCreateV1
  | SubscriptionDeleteV1
  | PingV1;

export type ServerRealtimeWireMessage =
  | SubscriptionCreatedV1
  | SubscriptionDeletedV1
  | CommandRejectedV1
  | PongV1
  | SubscriptionRevokedV1
  | DomainEventV1;

export type RealtimeWireMessage = ClientRealtimeWireMessage | ServerRealtimeWireMessage;

export type DecodeResult =
  | { readonly ok: true; readonly value: RealtimeWireMessage }
  | {
      readonly ok: false;
      readonly reason: "unknown-type" | "unknown-version" | "invalid";
    };

type UnknownRecord = Record<string, unknown>;
type KnownProtocolWireType = Exclude<RealtimeWireMessage, DomainEventV1>["type"];
type EnvelopeValidator = (message: UnknownRecord) => boolean;

const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])/u;
const DOMAIN_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\\s\\S])/u;
const TOPIC_PATTERN = /^[A-Za-z0-9._:/-]+(?![\\s\\S])/u;
const CURSOR_PATTERN = /^[!-~]+(?![\\s\\S])/u;
const ENVELOPE_PROPERTIES = Object.freeze([
  "v",
  "id",
  "type",
  "correlation_id",
  "payload",
] as const);
const RESERVED_WIRE_NAMES = Object.freeze([${stringArray(RESERVED_WIRE_NAMES)}] as const);
const COMMAND_REJECTION_CODES = Object.freeze([${stringArray(COMMAND_REJECTION_CODES)}] as const);
const REVOCATION_REASONS = Object.freeze([${stringArray(REVOCATION_REASONS)}] as const);

const INVALID_RESULT: DecodeResult = Object.freeze({ ok: false, reason: "invalid" });
const UNKNOWN_TYPE_RESULT: DecodeResult = Object.freeze({
  ok: false,
  reason: "unknown-type",
});
const UNKNOWN_VERSION_RESULT: DecodeResult = Object.freeze({
  ok: false,
  reason: "unknown-version",
});

function isRecord(value: unknown): value is UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactOwnProperties(
  value: unknown,
  expected: readonly string[],
): value is UnknownRecord {
  if (!isRecord(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => {
      if (typeof key !== "string" || !expected.includes(key)) {
        return false;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && "value" in descriptor;
    })
  );
}

function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && UUID_V7_PATTERN.test(value);
}

function isNullableUuidV7(value: unknown): value is string | null {
  return value === null || isUuidV7(value);
}

function isPortableTopic(value: unknown): value is string {
  return typeof value === "string" && TOPIC_PATTERN.test(value) && value.length <= 128;
}

function isOpaqueCursor(value: unknown): value is string {
  return typeof value === "string" && CURSOR_PATTERN.test(value) && value.length <= 256;
}

function hasCodePointLengthBetween(value: string, minimum: number, maximum: number): boolean {
  let length = 0;
  for (const _codePoint of value) {
    length += 1;
    if (length > maximum) {
      return false;
    }
  }
  return length >= minimum;
}

function isOneOf(value: unknown, values: readonly string[]): value is string {
  return typeof value === "string" && values.includes(value);
}

function isBoundedDataObject(value: unknown): value is Readonly<Record<string, unknown>> {
  if (!isRecord(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length <= 1024 &&
    keys.every((key) => {
      if (typeof key !== "string") {
        return false;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && "value" in descriptor;
    })
  );
}

function isEmptyPayload(value: unknown): boolean {
  return hasExactOwnProperties(value, []);
}

function hasValidSubscriptionId(value: unknown): value is UnknownRecord {
  return (
    hasExactOwnProperties(value, ["subscription_id"]) && isUuidV7(value.subscription_id)
  );
}

function validateSubscriptionCreate(message: UnknownRecord): boolean {
  const payload = message.payload;
  if (
    !hasExactOwnProperties(payload, [
      "subscription_id",
      "topic",
      ...(isRecord(payload) && Object.hasOwn(payload, "cursor") ? ["cursor"] : []),
    ])
  ) {
    return false;
  }
  return (
    isNullableUuidV7(message.correlation_id) &&
    isUuidV7(payload.subscription_id) &&
    isPortableTopic(payload.topic) &&
    (!Object.hasOwn(payload, "cursor") || isOpaqueCursor(payload.cursor))
  );
}

function validateSubscriptionDelete(message: UnknownRecord): boolean {
  return isNullableUuidV7(message.correlation_id) && hasValidSubscriptionId(message.payload);
}

function validatePing(message: UnknownRecord): boolean {
  return isNullableUuidV7(message.correlation_id) && isEmptyPayload(message.payload);
}

function validateSubscriptionCreated(message: UnknownRecord): boolean {
  const payload = message.payload;
  return (
    isUuidV7(message.correlation_id) &&
    hasExactOwnProperties(payload, ["subscription_id", "topic"]) &&
    isUuidV7(payload.subscription_id) &&
    isPortableTopic(payload.topic)
  );
}

function validateSubscriptionDeleted(message: UnknownRecord): boolean {
  return isUuidV7(message.correlation_id) && hasValidSubscriptionId(message.payload);
}

function validateCommandRejected(message: UnknownRecord): boolean {
  const payload = message.payload;
  return (
    isUuidV7(message.correlation_id) &&
    hasExactOwnProperties(payload, ["code", "message"]) &&
    isOneOf(payload.code, COMMAND_REJECTION_CODES) &&
    typeof payload.message === "string" &&
    hasCodePointLengthBetween(payload.message, 1, 64)
  );
}

function validatePong(message: UnknownRecord): boolean {
  return isUuidV7(message.correlation_id) && isEmptyPayload(message.payload);
}

function validateSubscriptionRevoked(message: UnknownRecord): boolean {
  const payload = message.payload;
  return (
    message.correlation_id === null &&
    hasExactOwnProperties(payload, ["subscription_id", "reason"]) &&
    isUuidV7(payload.subscription_id) &&
    isOneOf(payload.reason, REVOCATION_REASONS)
  );
}

function validateDomainEvent(message: UnknownRecord): boolean {
  const payload = message.payload;
  return (
    isNullableUuidV7(message.correlation_id) &&
    hasExactOwnProperties(payload, ["subscription_id", "topic", "cursor", "data"]) &&
    isUuidV7(payload.subscription_id) &&
    isPortableTopic(payload.topic) &&
    (payload.cursor === null || isOpaqueCursor(payload.cursor)) &&
    isBoundedDataObject(payload.data)
  );
}

const ENVELOPE_VALIDATORS = Object.freeze({
  "subscription.create": validateSubscriptionCreate,
  "subscription.delete": validateSubscriptionDelete,
  ping: validatePing,
  "subscription.created": validateSubscriptionCreated,
  "subscription.deleted": validateSubscriptionDeleted,
  "command.rejected": validateCommandRejected,
  pong: validatePong,
  "subscription.revoked": validateSubscriptionRevoked,
} satisfies Readonly<Record<KnownProtocolWireType, EnvelopeValidator>>);

function isKnownProtocolWireType(value: string): value is KnownProtocolWireType {
  return Object.hasOwn(ENVELOPE_VALIDATORS, value);
}

const NO_DOMAIN_EVENT_TYPES: ReadonlySet<string> = new Set();

function decodeRealtimeWireMessageUnsafe(
  input: unknown,
  knownDomainEventTypes: ReadonlySet<string>,
): DecodeResult {
  if (!hasExactOwnProperties(input, ENVELOPE_PROPERTIES)) {
    return INVALID_RESULT;
  }
  if (
    typeof input.v !== "number" ||
    !Number.isSafeInteger(input.v) ||
    input.v < 1
  ) {
    return INVALID_RESULT;
  }
  if (input.v !== 1) {
    return UNKNOWN_VERSION_RESULT;
  }
  if (
    typeof input.type !== "string" ||
    !isUuidV7(input.id) ||
    !isNullableUuidV7(input.correlation_id)
  ) {
    return INVALID_RESULT;
  }
  if (isKnownProtocolWireType(input.type)) {
    return ENVELOPE_VALIDATORS[input.type](input)
      ? { ok: true, value: input as unknown as RealtimeWireMessage }
      : INVALID_RESULT;
  }
  if (
    RESERVED_WIRE_NAMES.includes(
      input.type as (typeof RESERVED_WIRE_NAMES)[number],
    ) ||
    !DOMAIN_TYPE_PATTERN.test(input.type)
  ) {
    return UNKNOWN_TYPE_RESULT;
  }
  if (!knownDomainEventTypes.has(input.type)) {
    return UNKNOWN_TYPE_RESULT;
  }
  return validateDomainEvent(input)
    ? { ok: true, value: input as unknown as DomainEventV1 }
    : INVALID_RESULT;
}

export function decodeRealtimeWireMessage(
  input: unknown,
  knownDomainEventTypes: ReadonlySet<string> = NO_DOMAIN_EVENT_TYPES,
): DecodeResult {
  try {
    return decodeRealtimeWireMessageUnsafe(input, knownDomainEventTypes);
  } catch {
    return INVALID_RESULT;
  }
}
`;

if (check) {
  const current = await readFile(outputUrl, "utf8").catch(() => "");
  if (current !== generated) {
    throw new Error(
      `Generated realtime contract is stale. Run the package generate:realtime script: ${fileURLToPath(outputUrl)}`,
    );
  }
  console.log("Generated realtime contract is current.");
} else {
  const current = await readFile(outputUrl, "utf8").catch(() => "");
  if (current !== generated) {
    await writeFile(outputUrl, generated, "utf8");
  }
  console.log("Generated src/internal/generated/realtime.ts from contracts/asyncapi.json.");
}
