use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, ensure};
use omnius_realtime_core::{
    BrowserCorrelation, BrowserMessageDirection, BrowserMessageIdentity, BrowserPayload,
    browser_message_contracts,
};
use omnius_realtime_sse::SSE_EVENTS_PATH;
use omnius_realtime_websocket::{WEBSOCKET_PATH, WEBSOCKET_PROTOCOL};
use serde_json::{Map, Value, json};

const DOCUMENT_PATH: &str = "contracts/asyncapi.json";
const UUID_V7_PATTERN: &str =
    "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const DOMAIN_EVENT_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$";

pub(crate) fn generate(workspace: &Path) -> Result<()> {
    let path = workspace.join(DOCUMENT_PATH);
    let parent = path
        .parent()
        .context("AsyncAPI document path has no parent")?;
    fs::create_dir_all(parent).context("create AsyncAPI document directory")?;
    fs::write(path, generated_document()?).context("write AsyncAPI document")
}

pub(crate) fn verify(workspace: &Path) -> Result<()> {
    let committed = fs::read(workspace.join(DOCUMENT_PATH))
        .context("read committed AsyncAPI document; run `cargo xtask asyncapi generate`")?;
    let generated = generated_document()?;
    ensure!(
        committed == generated,
        "public AsyncAPI document is stale; run `cargo xtask asyncapi generate`"
    );
    validate_document(&serde_json::from_slice(&committed).context("parse AsyncAPI document")?)
}

pub(crate) fn generated_document() -> Result<Vec<u8>> {
    let document = build_document();
    validate_document(&document)?;
    let mut bytes = serde_json::to_vec_pretty(&document).context("serialize AsyncAPI document")?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[allow(clippy::too_many_lines)] // Keeping the canonical document shape together makes review safer.
fn build_document() -> Value {
    let mut messages = Map::new();
    let mut websocket_messages = Map::new();
    let mut sse_messages = Map::new();
    let mut client_refs = Vec::new();
    let mut server_refs = Vec::new();
    let mut sse_refs = Vec::new();

    for declaration in browser_message_contracts() {
        let component = declaration.component_name();
        messages.insert(component.into(), message_component(declaration));
        let component_ref = json!({"$ref": format!("#/components/messages/{component}")});
        if declaration.websocket() {
            websocket_messages.insert(component.into(), component_ref.clone());
            let channel_ref = json!({
                "$ref": format!("#/channels/realtimeWebSocket/messages/{component}")
            });
            match declaration.direction() {
                BrowserMessageDirection::ClientToServer => client_refs.push(channel_ref),
                BrowserMessageDirection::ServerToClient => server_refs.push(channel_ref),
            }
        }
        if declaration.sse() {
            sse_messages.insert(component.into(), component_ref);
            sse_refs.push(json!({
                "$ref": format!("#/channels/realtimeEvents/messages/{component}")
            }));
        }
    }

    json!({
        "asyncapi": "3.1.0",
        "info": {
            "title": "Omnius browser realtime contract",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Typed browser-facing WebSocket, SSE, and module-owned domain-event envelopes. HTTP remains authoritative for state reconstruction."
        },
        "defaultContentType": "application/json",
        "servers": {
            "sameOriginWebSocket": {
                "host": "{host}",
                "protocol": "wss",
                "pathname": WEBSOCKET_PATH,
                "description": "Same-origin WebSocket endpoint; use ws in non-TLS development only.",
                "variables": {"host": {"default": "localhost"}},
                "security": [{"$ref": "#/components/securitySchemes/sessionCookie"}],
                "bindings": {"ws": {"bindingVersion": "0.1.0"}}
            },
            "sameOriginHttp": {
                "host": "{host}",
                "protocol": "https",
                "pathname": "/",
                "description": "Same-origin HTTP endpoint carrying an SSE stream.",
                "variables": {"host": {"default": "localhost"}},
                "security": [{"$ref": "#/components/securitySchemes/sessionCookie"}],
                "bindings": {"http": {"bindingVersion": "0.3.0"}}
            }
        },
        "channels": {
            "realtimeEvents": {
                "address": SSE_EVENTS_PATH,
                "title": "Resumable server-sent events",
                "description": "Named SSE events. Clients resume with the bounded `cursor` query parameter when the selected provider supplies a genuine cursor; heartbeat comments carry no event.",
                "servers": [{"$ref": "#/servers/sameOriginHttp"}],
                "messages": sse_messages,
                "bindings": {"http": {"bindingVersion": "0.3.0"}},
                "x-resume": {
                    "requestQuery": "cursor",
                    "lastEventIdHeader": "rejected to prevent ambiguous cursors",
                    "cursorField": "$message.payload#/payload/cursor",
                    "duplicates": "at-least-once delivery; consumers must tolerate duplicates"
                }
            },
            "realtimeWebSocket": {
                "address": WEBSOCKET_PATH,
                "title": "Authenticated realtime WebSocket",
                "description": "Versioned bidirectional JSON envelopes using the required negotiated subprotocol.",
                "servers": [{"$ref": "#/servers/sameOriginWebSocket"}],
                "messages": websocket_messages,
                "bindings": {
                    "ws": {
                        "method": "GET",
                        "headers": {"type": "object", "properties": {"Sec-WebSocket-Protocol": {"const": WEBSOCKET_PROTOCOL}}, "required": ["Sec-WebSocket-Protocol"]},
                        "bindingVersion": "0.1.0"
                    }
                }
            }
        },
        "operations": {
            "receiveWebSocketCommands": {
                "action": "receive",
                "summary": "Receive authorized browser commands",
                "channel": {"$ref": "#/channels/realtimeWebSocket"},
                "messages": client_refs,
                "security": [{"$ref": "#/components/securitySchemes/sessionCookie"}]
            },
            "sendServerSentEvents": {
                "action": "send",
                "summary": "Send named resumable SSE events",
                "channel": {"$ref": "#/channels/realtimeEvents"},
                "messages": sse_refs,
                "security": [{"$ref": "#/components/securitySchemes/sessionCookie"}],
                "bindings": {"http": {
                    "method": "GET",
                    "query": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["subscription_id", "topic"],
                        "properties": {
                            "subscription_id": uuid_v7_schema(),
                            "topic": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._:/-]+$"},
                            "cursor": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!-~]+$"}
                        }
                    },
                    "bindingVersion": "0.3.0"
                }}
            },
            "sendWebSocketMessages": {
                "action": "send",
                "summary": "Send command results, controls, and domain events",
                "channel": {"$ref": "#/channels/realtimeWebSocket"},
                "messages": server_refs,
                "security": [{"$ref": "#/components/securitySchemes/sessionCookie"}]
            }
        },
        "components": {
            "messages": messages,
            "schemas": common_schemas(),
            "securitySchemes": {
                "sessionCookie": {
                    "type": "httpApiKey",
                    "description": "Secure HttpOnly same-origin session cookie. The credential is never exposed to JavaScript.",
                    "name": "__Host-omnius-session",
                    "in": "cookie"
                }
            }
        }
    })
}

fn message_component(declaration: &omnius_realtime_core::BrowserMessageContract) -> Value {
    let component = declaration.component_name();
    if declaration.payload() == BrowserPayload::SseReconnect {
        return json!({
            "name": component,
            "title": component,
            "summary": "Version 1 SSE terminal reconnect hint emitted before a slow-consumer or server-drain close.",
            "contentType": "text/plain",
            "payload": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "string",
                "enum": ["slow-consumer", "server-draining"]
            },
            "x-sse-event": "reconnect",
            "x-message-version": declaration.version(),
            "x-direction": "server-to-client"
        });
    }
    let (wire_name, summary) = match declaration.identity() {
        BrowserMessageIdentity::Static(name) => (Value::String(name.into()), format!("Version 1 `{name}` envelope.")),
        BrowserMessageIdentity::DomainEventV1 => (
            json!({"pattern": DOMAIN_EVENT_PATTERN, "reservedNamesExcluded": true}),
            "Version 1 module-owned domain-event envelope; the wire `type` is the stable module-owned event name and `v` is the envelope version.".into(),
        ),
    };
    json!({
        "name": component,
        "title": component,
        "summary": summary,
        "contentType": "application/json",
        "payload": envelope_schema(declaration),
        "correlationId": {
            "description": "UUIDv7 command/event correlation identifier when the message contract permits one.",
            "location": "$message.payload#/correlation_id"
        },
        "x-wire-name": wire_name,
        "x-message-version": declaration.version(),
        "x-direction": match declaration.direction() {
            BrowserMessageDirection::ClientToServer => "client-to-server",
            BrowserMessageDirection::ServerToClient => "server-to-client",
        }
    })
}

fn envelope_schema(declaration: &omnius_realtime_core::BrowserMessageContract) -> Value {
    let message_type = match declaration.identity() {
        BrowserMessageIdentity::Static(name) => json!({"const": name}),
        BrowserMessageIdentity::DomainEventV1 => json!({
            "type": "string",
            "pattern": DOMAIN_EVENT_PATTERN,
            "not": {"enum": [
                "subscription.create", "subscription.delete", "ping", "subscription.created",
                "subscription.deleted", "command.rejected", "pong", "subscription.revoked", "reconnect"
            ]}
        }),
    };
    let correlation = match declaration.correlation() {
        BrowserCorrelation::Nullable => json!({"oneOf": [uuid_v7_schema(), {"type": "null"}]}),
        BrowserCorrelation::Required => uuid_v7_schema(),
        BrowserCorrelation::Null => json!({"type": "null"}),
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["v", "id", "type", "correlation_id", "payload"],
        "properties": {
            "v": {"const": declaration.version()},
            "id": uuid_v7_schema(),
            "type": message_type,
            "correlation_id": correlation,
            "payload": payload_schema(declaration.payload())
        }
    })
}

fn payload_schema(payload: BrowserPayload) -> Value {
    let subscription_id = uuid_v7_schema();
    let topic = json!({"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._:/-]+$"});
    let cursor = json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!-~]+$"});
    match payload {
        BrowserPayload::SubscriptionCreate => closed_object(
            ["subscription_id", "topic"],
            json!({"subscription_id": subscription_id, "topic": topic, "cursor": cursor}),
        ),
        BrowserPayload::SubscriptionDelete | BrowserPayload::SubscriptionDeleted => closed_object(
            ["subscription_id"],
            json!({"subscription_id": subscription_id}),
        ),
        BrowserPayload::Empty => closed_object::<0>([], json!({})),
        BrowserPayload::SubscriptionCreated => closed_object(
            ["subscription_id", "topic"],
            json!({"subscription_id": subscription_id, "topic": topic}),
        ),
        BrowserPayload::CommandRejected => closed_object(
            ["code", "message"],
            json!({
                "code": {"enum": ["unauthorized", "connection_not_active", "not_found", "conflict", "capacity_exceeded", "unavailable"]},
                "message": {"type": "string", "minLength": 1, "maxLength": 64}
            }),
        ),
        BrowserPayload::SubscriptionRevoked => closed_object(
            ["subscription_id", "reason"],
            json!({
                "subscription_id": subscription_id,
                "reason": {"enum": ["authorization_changed", "membership_changed", "identity_revoked", "resource_removed"]}
            }),
        ),
        BrowserPayload::DomainEvent => closed_object(
            ["subscription_id", "topic", "cursor", "data"],
            json!({
                "subscription_id": subscription_id,
                "topic": topic,
                "cursor": {"oneOf": [cursor, {"type": "null"}]},
                "data": {"type": "object", "maxProperties": 1024}
            }),
        ),
        BrowserPayload::SseReconnect => {
            json!({"type": "string", "enum": ["slow-consumer", "server-draining"]})
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // Callers transfer freshly constructed JSON values.
fn closed_object<const N: usize>(required: [&str; N], properties: Value) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required.as_slice(),
        "properties": properties
    })
}

fn uuid_v7_schema() -> Value {
    json!({"type": "string", "format": "uuid", "pattern": UUID_V7_PATTERN})
}

fn common_schemas() -> Value {
    json!({
        "UuidV7": uuid_v7_schema(),
        "OpaqueCursor": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!-~]+$"},
        "PortableTopic": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._:/-]+$"}
    })
}

#[allow(clippy::too_many_lines)] // The structural schema and coverage assertions are one gate.
fn validate_document(document: &Value) -> Result<()> {
    ensure!(
        document.get("asyncapi") == Some(&Value::String("3.1.0".into())),
        "AsyncAPI version must be 3.1.0"
    );
    let components = document
        .pointer("/components/messages")
        .and_then(Value::as_object)
        .context("AsyncAPI components.messages missing")?;
    let expected: BTreeSet<_> = browser_message_contracts()
        .iter()
        .map(omnius_realtime_core::BrowserMessageContract::component_name)
        .collect();
    let actual: BTreeSet<_> = components.keys().map(String::as_str).collect();
    ensure!(
        actual == expected,
        "AsyncAPI message registry coverage mismatch"
    );

    let websocket = channel_message_names(document, "realtimeWebSocket")?;
    let sse = channel_message_names(document, "realtimeEvents")?;
    let document_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["asyncapi", "info", "defaultContentType", "servers", "channels", "operations", "components"],
        "properties": {
            "asyncapi": {"const": "3.1.0"},
            "info": {
                "type": "object",
                "required": ["title", "version"],
                "properties": {"title": {"type": "string", "minLength": 1}, "version": {"type": "string", "minLength": 1}, "description": {"type": "string"}},
                "additionalProperties": false
            },
            "defaultContentType": {"const": "application/json"},
            "servers": {"type": "object", "minProperties": 2},
            "channels": {
                "type": "object",
                "required": ["realtimeEvents", "realtimeWebSocket"],
                "additionalProperties": {
                    "type": "object",
                    "required": ["address", "messages"],
                    "properties": {"address": {"type": "string", "minLength": 1}, "messages": {"type": "object", "minProperties": 1}}
                }
            },
            "operations": {
                "type": "object",
                "minProperties": 3,
                "additionalProperties": {
                    "type": "object",
                    "required": ["action", "channel", "messages"],
                    "properties": {
                        "action": {"enum": ["send", "receive"]},
                        "channel": {"type": "object", "required": ["$ref"]},
                        "messages": {"type": "array", "minItems": 1}
                    }
                }
            },
            "components": {
                "type": "object",
                "required": ["messages", "schemas", "securitySchemes"],
                "properties": {
                    "messages": {"type": "object", "minProperties": 1},
                    "schemas": {"type": "object"},
                    "securitySchemes": {"type": "object", "minProperties": 1}
                }
            }
        }
    });
    let validator = jsonschema::validator_for(&document_schema)
        .context("compile AsyncAPI 3.1 browser document schema")?;
    ensure!(
        validator.is_valid(document),
        "AsyncAPI document does not satisfy its 3.1 browser schema"
    );
    for (name, message) in components {
        let payload = message
            .get("payload")
            .context("AsyncAPI message payload schema missing")?;
        jsonschema::validator_for(payload).with_context(|| {
            format!("compile JSON Schema payload for AsyncAPI message `{name}`")
        })?;
    }

    for message in browser_message_contracts() {
        ensure!(
            websocket.contains(message.component_name()) == message.websocket(),
            "AsyncAPI WebSocket coverage mismatch for {}",
            message.component_name()
        );
        ensure!(
            sse.contains(message.component_name()) == message.sse(),
            "AsyncAPI SSE coverage mismatch for {}",
            message.component_name()
        );
        ensure!(
            components[message.component_name()].get("x-message-version")
                == Some(&json!(message.version())),
            "AsyncAPI version mismatch for {}",
            message.component_name()
        );
    }
    ensure!(
        document.pointer("/channels/realtimeWebSocket/address")
            == Some(&Value::String(WEBSOCKET_PATH.into())),
        "AsyncAPI WebSocket address drifted from router"
    );
    ensure!(
        document.pointer("/channels/realtimeEvents/address")
            == Some(&Value::String(SSE_EVENTS_PATH.into())),
        "AsyncAPI SSE address drifted from router"
    );
    validate_local_references(document)
}

fn channel_message_names<'a>(document: &'a Value, channel: &str) -> Result<BTreeSet<&'a str>> {
    document
        .pointer(&format!("/channels/{channel}/messages"))
        .and_then(Value::as_object)
        .context("AsyncAPI channel messages missing")
        .map(|messages| messages.keys().map(String::as_str).collect())
}

fn validate_local_references(document: &Value) -> Result<()> {
    fn visit<'a>(root: &'a Value, value: &'a Value) -> Result<()> {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    let pointer = reference
                        .strip_prefix('#')
                        .context("AsyncAPI contains a non-local reference")?;
                    ensure!(
                        root.pointer(pointer).is_some(),
                        "unresolved AsyncAPI reference `{reference}`"
                    );
                }
                for child in object.values() {
                    visit(root, child)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    visit(root, child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(document, document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_document_is_deterministic_and_covers_registry() -> Result<()> {
        let first = generated_document()?;
        let second = generated_document()?;
        assert_eq!(first, second);
        let document: Value = serde_json::from_slice(&first)?;
        validate_document(&document)
    }
}
