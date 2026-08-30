use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use omnius_agent_capability_registry::TenantMode;
use omnius_mcp_server_core::McpRequestContext;
use sha2::Sha256;
use zeroize::Zeroize as _;

use crate::{AuthorizationRevision, DiscoveryFilter};

const CURSOR_MAGIC: &[u8; 4] = b"OMPD";
const CURSOR_VERSION: u8 = 2;
const CURSOR_BODY_BYTES: usize = 4 + 1 + 4 + 8 + 32 + 32;
const CURSOR_SIGNATURE_BYTES: usize = 32;
const CURSOR_BYTES: usize = CURSOR_BODY_BYTES + CURSOR_SIGNATURE_BYTES;
pub(crate) const MAX_CURSOR_TEXT_BYTES: usize = 192;
const SIGNING_DOMAIN: &[u8] = b"omnius.progressive-discovery.cursor.v2";
const BINDING_DOMAIN: &[u8] = b"omnius.progressive-discovery.binding.v2";
const SNAPSHOT_DOMAIN: &[u8] = b"omnius.progressive-discovery.snapshot-binding.v2";

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct CursorCodec {
    key: [u8; 32],
}

impl CursorCodec {
    pub(crate) const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "every cursor-bound request dimension remains explicit at this security boundary"
    )]
    pub(crate) fn issue(
        &self,
        offset: u32,
        expires_unix: u64,
        request: &McpRequestContext,
        normalized_query: &str,
        filter: &DiscoveryFilter,
        page_size: u16,
        authorization_revision: &AuthorizationRevision,
        snapshot_fingerprint: &[u8; 32],
    ) -> Result<String, CursorFailure> {
        let mut body = Vec::with_capacity(CURSOR_BODY_BYTES + CURSOR_SIGNATURE_BYTES);
        body.extend_from_slice(CURSOR_MAGIC);
        body.push(CURSOR_VERSION);
        body.extend_from_slice(&offset.to_be_bytes());
        body.extend_from_slice(&expires_unix.to_be_bytes());
        let binding = self
            .binding_mac(
                request,
                normalized_query,
                filter,
                page_size,
                authorization_revision,
            )?
            .finalize()
            .into_bytes();
        body.extend_from_slice(&binding);
        let snapshot = self
            .snapshot_mac(snapshot_fingerprint)?
            .finalize()
            .into_bytes();
        body.extend_from_slice(&snapshot);
        if body.len() != CURSOR_BODY_BYTES {
            return Err(CursorFailure::Internal);
        }
        let signature = self.sign(&body)?;
        body.extend_from_slice(&signature);
        Ok(URL_SAFE_NO_PAD.encode(body))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "every cursor-bound request dimension remains explicit at this security boundary"
    )]
    pub(crate) fn verify(
        &self,
        cursor: &str,
        now_unix: u64,
        request: &McpRequestContext,
        normalized_query: &str,
        filter: &DiscoveryFilter,
        page_size: u16,
        authorization_revision: &AuthorizationRevision,
        snapshot_fingerprint: &[u8; 32],
    ) -> Result<usize, CursorFailure> {
        if cursor.is_empty()
            || cursor.len() > MAX_CURSOR_TEXT_BYTES
            || !cursor
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CursorFailure::Malformed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| CursorFailure::Malformed)?;
        if decoded.len() != CURSOR_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != cursor {
            return Err(CursorFailure::Malformed);
        }
        let (body, signature) = decoded.split_at(CURSOR_BODY_BYTES);
        self.verify_signature(body, signature)?;
        if &body[..4] != CURSOR_MAGIC || body[4] != CURSOR_VERSION {
            return Err(CursorFailure::Malformed);
        }
        let offset = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
        let expires_unix = u64::from_be_bytes([
            body[9], body[10], body[11], body[12], body[13], body[14], body[15], body[16],
        ]);
        if now_unix >= expires_unix {
            return Err(CursorFailure::Expired);
        }
        self.binding_mac(
            request,
            normalized_query,
            filter,
            page_size,
            authorization_revision,
        )?
        .verify_slice(&body[17..49])
        .map_err(|_| CursorFailure::BindingMismatch)?;
        self.snapshot_mac(snapshot_fingerprint)?
            .verify_slice(&body[49..81])
            .map_err(|_| CursorFailure::SnapshotMismatch)?;
        usize::try_from(offset).map_err(|_| CursorFailure::Malformed)
    }

    fn binding_mac(
        &self,
        request: &McpRequestContext,
        normalized_query: &str,
        filter: &DiscoveryFilter,
        page_size: u16,
        authorization_revision: &AuthorizationRevision,
    ) -> Result<HmacSha256, CursorFailure> {
        let mut mac = self.mac()?;
        mac.update(BINDING_DOMAIN);
        let canonical = request.canonical();
        let invocation = canonical.invocation();
        let principal = invocation.principal();
        update_component(&mut mac, b"principal")?;
        update_component(&mut mac, principal.subject_id.as_uuid().as_bytes())?;
        update_component(&mut mac, b"tenant")?;
        match invocation.tenant_id() {
            Some(tenant_id) => {
                mac.update(&[1]);
                update_component(&mut mac, tenant_id.as_uuid().as_bytes())?;
            }
            None => mac.update(&[0]),
        }
        update_component(&mut mac, b"tenant-mode")?;
        mac.update(&[match canonical.tenant_mode() {
            TenantMode::Global => 1,
            TenantMode::Tenant => 2,
            TenantMode::Principal => 3,
        }]);
        update_component(&mut mac, b"scopes")?;
        update_count(&mut mac, principal.scopes.len())?;
        for scope in &principal.scopes {
            update_component(&mut mac, scope.as_str().as_bytes())?;
        }
        update_component(&mut mac, b"data-policy")?;
        update_component(&mut mac, invocation.data_policy().as_str().as_bytes())?;
        update_component(&mut mac, b"authorization-revision")?;
        update_component(&mut mac, authorization_revision.as_str().as_bytes())?;
        update_component(&mut mac, b"query")?;
        update_component(&mut mac, normalized_query.as_bytes())?;
        update_component(&mut mac, b"page-size")?;
        mac.update(&page_size.to_be_bytes());
        let (partitions, tags, kinds) = filter.binding_parts();
        update_component(&mut mac, b"partitions")?;
        update_count(&mut mac, partitions.len())?;
        for partition in partitions {
            update_component(&mut mac, partition.as_bytes())?;
        }
        update_component(&mut mac, b"tags")?;
        update_count(&mut mac, tags.len())?;
        for tag in tags {
            update_component(&mut mac, tag.as_bytes())?;
        }
        update_component(&mut mac, b"kinds")?;
        update_count(&mut mac, kinds.len())?;
        for kind in kinds {
            mac.update(&[kind.binding_tag()]);
        }
        Ok(mac)
    }

    fn snapshot_mac(&self, snapshot_fingerprint: &[u8; 32]) -> Result<HmacSha256, CursorFailure> {
        let mut mac = self.mac()?;
        mac.update(SNAPSHOT_DOMAIN);
        mac.update(snapshot_fingerprint);
        Ok(mac)
    }

    fn sign(&self, body: &[u8]) -> Result<[u8; 32], CursorFailure> {
        let mut mac = self.mac()?;
        mac.update(SIGNING_DOMAIN);
        mac.update(body);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_signature(&self, body: &[u8], signature: &[u8]) -> Result<(), CursorFailure> {
        let mut mac = self.mac()?;
        mac.update(SIGNING_DOMAIN);
        mac.update(body);
        mac.verify_slice(signature)
            .map_err(|_| CursorFailure::Integrity)
    }

    fn mac(&self) -> Result<HmacSha256, CursorFailure> {
        <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&self.key)
            .map_err(|_| CursorFailure::Internal)
    }
}

impl Drop for CursorCodec {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CursorFailure {
    Malformed,
    Integrity,
    Expired,
    BindingMismatch,
    SnapshotMismatch,
    Position,
    Internal,
}

fn update_component(mac: &mut HmacSha256, value: &[u8]) -> Result<(), CursorFailure> {
    let length = u32::try_from(value.len()).map_err(|_| CursorFailure::Internal)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn update_count(mac: &mut HmacSha256, value: usize) -> Result<(), CursorFailure> {
    let count = u32::try_from(value).map_err(|_| CursorFailure::Internal)?;
    mac.update(&count.to_be_bytes());
    Ok(())
}
