use omnius_mcp_server_core::McpRequestContext;
use serde_json::Value;

use crate::model::{BindingDigest, ConfigError, InvocationBinding, StateBinding};

pub(crate) fn canonical_arguments_digest(
    arguments: &Value,
    max_bytes: usize,
) -> Result<BindingDigest, ConfigError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
    write_canonical_json(arguments, &mut bytes, max_bytes)?;
    Ok(BindingDigest::of(b"omnius/mrtr/arguments/v1", &bytes))
}

pub(crate) fn state_binding(
    context: &McpRequestContext,
    binding: &InvocationBinding,
    arguments_digest: BindingDigest,
    idempotency_key: Option<&str>,
) -> StateBinding {
    let invocation = context.canonical().invocation();
    let principal_id = invocation.principal().subject_id.as_uuid();
    let principal_digest = BindingDigest::of(b"omnius/mrtr/principal/v1", principal_id.as_bytes());
    let tenant_digest = invocation.tenant_id().map_or_else(
        || BindingDigest::of(b"omnius/mrtr/tenant/v1", &[]),
        |tenant_id| {
            let tenant_id = tenant_id.as_uuid();
            BindingDigest::of(b"omnius/mrtr/tenant/v1", tenant_id.as_bytes())
        },
    );
    let idempotency_digest = match idempotency_key {
        Some(value) => BindingDigest::of(b"omnius/mrtr/idempotency/some/v1", value.as_bytes()),
        None => BindingDigest::of(b"omnius/mrtr/idempotency/none/v1", &[]),
    };

    let method = binding.method().as_str().as_bytes();
    let capability_key = binding.capability_key().as_bytes();
    let capability_revision = binding.capability_revision().as_bytes();
    let mut framed = Vec::with_capacity(
        7 * std::mem::size_of::<u64>()
            + principal_digest.as_bytes().len()
            + tenant_digest.as_bytes().len()
            + method.len()
            + capability_key.len()
            + capability_revision.len()
            + arguments_digest.as_bytes().len()
            + idempotency_digest.as_bytes().len(),
    );
    append_framed(&mut framed, principal_digest.as_bytes());
    append_framed(&mut framed, tenant_digest.as_bytes());
    append_framed(&mut framed, method);
    append_framed(&mut framed, capability_key);
    append_framed(&mut framed, capability_revision);
    append_framed(&mut framed, arguments_digest.as_bytes());
    append_framed(&mut framed, idempotency_digest.as_bytes());
    let associated_digest = BindingDigest::of(b"omnius/mrtr/associated/v1", &framed);

    StateBinding {
        principal_digest,
        tenant_digest,
        method: binding.method(),
        capability_key: binding.capability_key().to_owned(),
        capability_revision: binding.capability_revision().to_owned(),
        arguments_digest,
        idempotency_digest,
        associated_digest,
    }
}

fn write_canonical_json(
    value: &Value,
    output: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<(), ConfigError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(&mut *output, value).map_err(|_| ConfigError::InvalidBounds)?;
            check_bound(output, max_bytes)
        }
        Value::Array(values) => {
            push_byte(output, b'[', max_bytes)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    push_byte(output, b',', max_bytes)?;
                }
                write_canonical_json(value, output, max_bytes)?;
            }
            push_byte(output, b']', max_bytes)
        }
        Value::Object(values) => {
            push_byte(output, b'{', max_bytes)?;
            let mut keys = values.keys().map(String::as_str).collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    push_byte(output, b',', max_bytes)?;
                }
                serde_json::to_writer(&mut *output, key).map_err(|_| ConfigError::InvalidBounds)?;
                push_byte(output, b':', max_bytes)?;
                write_canonical_json(&values[key], output, max_bytes)?;
            }
            push_byte(output, b'}', max_bytes)
        }
    }
}

fn push_byte(output: &mut Vec<u8>, byte: u8, max_bytes: usize) -> Result<(), ConfigError> {
    output.push(byte);
    check_bound(output, max_bytes)
}

fn check_bound(output: &[u8], max_bytes: usize) -> Result<(), ConfigError> {
    if output.len() > max_bytes {
        Err(ConfigError::InvalidBounds)
    } else {
        Ok(())
    }
}

fn append_framed(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value);
}
