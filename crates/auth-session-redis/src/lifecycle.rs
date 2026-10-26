use std::{cmp::Reverse, str::FromStr as _};

use crate::{
    FeatureStableRedisStore,
    keys::{
        DEVICE_CATALOG, DEVICE_EPOCH_PREFIX, DEVICE_INDEX_PREFIX, GLOBAL_INDEX, LIFECYCLE_KEY,
        LINEAGE_CATALOG, LINEAGE_EPOCH_PREFIX, LINEAGE_INDEX_PREFIX, SUBJECT_CATALOG,
        SUBJECT_EPOCH_PREFIX, SUBJECT_INDEX_PREFIX, device_epoch, index_keys, lineage_epoch,
        subject_epoch, subject_index,
    },
    scripts::{
        PERMISSION_PROBE_SCRIPT, PRUNE_MEMBER_SCRIPT, REGISTER_SCRIPT, REMOVE_INDEX_SCRIPT,
        REVOKE_ALL_SCRIPT, REVOKE_CURRENT_SCRIPT, REVOKE_DEVICE_SCRIPT, ROTATION_CLAIM_SCRIPT,
        VALIDATE_SCRIPT,
    },
};
use fred::prelude::{Client, KeysInterface as _, LuaInterface as _, SetsInterface as _};
use omnius_auth_core::{
    SessionCleanup, SessionConfig, SessionMetadata, SessionRegistration, SessionValidation,
    SubjectId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tower_sessions::{
    Session, SessionStore as _,
    session::{Expiry, Id, Record},
};
use uuid::Uuid;

/// Hard limits keep every Redis set read and cleanup pass bounded. Registration
/// rejects capacity instead of allowing an index to grow beyond these limits.
const MAX_SUBJECT_SESSIONS: i64 = 256;
const MAX_DEVICE_SESSIONS: i64 = 64;
const MAX_LINEAGE_SESSIONS: i64 = 64;
const MAX_TRACKED_SESSIONS: i64 = 16_384;
const MAX_TRACKED_SUBJECTS: i64 = 4_096;
const MAX_TRACKED_DEVICES: i64 = 16_384;
const MAX_TRACKED_LINEAGES: i64 = 16_384;
/// Revocation generations outlive delayed saves/registrations without turning
/// attacker-chosen device or lineage identifiers into permanent Redis keys.
const GENERATION_TOMBSTONE_TTL_SECONDS: i64 = 300;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LifecycleRecord {
    subject_id: SubjectId,
    device_id: Uuid,
    lineage_id: Uuid,
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    user_agent_hash: Option<[u8; 32]>,
    ip_prefix: Option<String>,
    subject_epoch: i64,
    device_epoch: i64,
    lineage_epoch: i64,
}

impl LifecycleRecord {
    const fn public(&self, current: bool) -> SessionMetadata {
        SessionMetadata {
            device_id: self.device_id,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
            absolute_expires_at: self.absolute_expires_at,
            current,
        }
    }
}

#[derive(Clone, Copy)]
struct Generations {
    subject: i64,
    device: i64,
    lineage: i64,
}

/// Redis-backed absolute-expiry, rotation, revocation, and cleanup operations.
#[derive(Clone)]
pub struct RedisSessionLifecycle {
    client: Client,
    config: SessionConfig,
}

impl std::fmt::Debug for RedisSessionLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisSessionLifecycle")
            .finish_non_exhaustive()
    }
}

impl RedisSessionLifecycle {
    pub(crate) fn new(client: Client, config: SessionConfig) -> Self {
        Self { client, config }
    }

    /// Saves a rotated login with owned lifecycle metadata and a fresh logical
    /// lineage, atomically indexing it only if no revocation crossed registration.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error and flushes the provider session on failure.
    pub async fn register_after_login(
        &self,
        session: &Session,
        registration: &SessionRegistration<'_>,
    ) -> Result<(), RedisSessionLifecycleError> {
        let lineage_id = Uuid::now_v7();
        let generations = match self
            .generations(registration.subject_id, registration.device_id, lineage_id)
            .await
        {
            Ok(generations) => generations,
            Err(error) => return Err(fail_closed(session, error).await),
        };
        self.register_with_generations(session, registration, lineage_id, generations)
            .await
    }

    async fn register_with_generations(
        &self,
        session: &Session,
        registration: &SessionRegistration<'_>,
        lineage_id: Uuid,
        generations: Generations,
    ) -> Result<(), RedisSessionLifecycleError> {
        let absolute_timeout = time::Duration::try_from(self.config.absolute_timeout)
            .map_err(|_| RedisSessionLifecycleError::InvalidInput)?;
        let absolute_expires_at = registration
            .created_at
            .checked_add(absolute_timeout)
            .ok_or(RedisSessionLifecycleError::InvalidInput)?;
        let metadata = LifecycleRecord {
            subject_id: registration.subject_id,
            device_id: registration.device_id,
            lineage_id,
            created_at: registration.created_at,
            last_seen_at: registration.created_at,
            absolute_expires_at,
            user_agent_hash: registration.user_agent_hash,
            ip_prefix: registration.ip_prefix.map(str::to_owned),
            subject_epoch: generations.subject,
            device_epoch: generations.device,
            lineage_epoch: generations.lineage,
        };
        if session.insert(LIFECYCLE_KEY, &metadata).await.is_err() {
            return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
        }
        let expiry = self.deadline(registration.created_at, absolute_expires_at)?;
        session.set_expiry(Some(Expiry::AtDateTime(expiry)));
        if session.save().await.is_err() {
            return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
        }
        let raw = current_session_id(session)?;
        let keys = index_keys(
            registration.subject_id,
            registration.device_id,
            lineage_id,
            &raw,
        );
        let result = self
            .client
            .eval::<i64, _, _, _>(
                REGISTER_SCRIPT,
                vec![
                    raw.clone(),
                    keys.subject_epoch.clone(),
                    keys.device_epoch.clone(),
                    keys.lineage_epoch.clone(),
                    GLOBAL_INDEX.to_owned(),
                    keys.subject.clone(),
                    keys.device.clone(),
                    keys.lineage.clone(),
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                ],
                vec![
                    generations.subject.to_string(),
                    generations.device.to_string(),
                    generations.lineage.to_string(),
                    keys.subject_member.clone(),
                    keys.global_member.clone(),
                    keys.device_member.clone(),
                    keys.lineage_member.clone(),
                    raw,
                    keys.subject_token,
                    keys.device_token,
                    keys.lineage_token,
                    MAX_TRACKED_SESSIONS.to_string(),
                    MAX_SUBJECT_SESSIONS.to_string(),
                    MAX_DEVICE_SESSIONS.to_string(),
                    MAX_LINEAGE_SESSIONS.to_string(),
                    MAX_TRACKED_SUBJECTS.to_string(),
                    MAX_TRACKED_DEVICES.to_string(),
                    MAX_TRACKED_LINEAGES.to_string(),
                ],
            )
            .await;
        match result {
            Ok(1) => Ok(()),
            Ok(-1) => Err(fail_closed(session, RedisSessionLifecycleError::Conflict).await),
            Ok(-2) => Err(fail_closed(session, RedisSessionLifecycleError::Inactive).await),
            Ok(-3) => Err(fail_closed(session, RedisSessionLifecycleError::CapacityExceeded).await),
            Ok(_) => Err(fail_closed(session, RedisSessionLifecycleError::CorruptData).await),
            Err(_) => Err(fail_closed(session, RedisSessionLifecycleError::Unavailable).await),
        }
    }

    /// Validates ownership, idle/absolute expiry, indexes, and revocation epochs,
    /// then saves a touch capped by absolute expiry.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error and flushes the provider session on failure.
    pub async fn validate_and_touch(
        &self,
        session: &Session,
        subject_id: SubjectId,
        now: OffsetDateTime,
    ) -> Result<SessionValidation, RedisSessionLifecycleError> {
        let Some(raw) = session.id().map(|id| id.to_string()) else {
            return Ok(SessionValidation::Rejected);
        };
        let metadata = match session.get::<LifecycleRecord>(LIFECYCLE_KEY).await {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return reject_session(session).await,
            Err(_) => {
                return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
            }
        };
        if metadata.subject_id != subject_id || !self.active(&metadata, now)? {
            return reject_session(session).await;
        }
        match self.indexed(&raw, &metadata).await {
            Ok(true) => {}
            Ok(false) => return reject_session(session).await,
            Err(error) => return Err(fail_closed(session, error).await),
        }
        let mut touched = metadata;
        touched.last_seen_at = now;
        if session.insert(LIFECYCLE_KEY, &touched).await.is_err() {
            return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
        }
        session.set_expiry(Some(Expiry::AtDateTime(
            self.deadline(now, touched.absolute_expires_at)?,
        )));
        if session.save().await.is_err() {
            return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
        }
        match self.indexed(&raw, &touched).await {
            Ok(true) => {}
            Ok(false) => {
                let _ = session.flush().await;
                return Ok(SessionValidation::Rejected);
            }
            Err(error) => return Err(fail_closed(session, error).await),
        }
        Ok(SessionValidation::Active(touched.public(true)))
    }

    /// Lists active sessions without returning their Redis bearer keys.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error and flushes the current session on failure.
    pub async fn list_active(
        &self,
        subject_id: SubjectId,
        current: &Session,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionMetadata>, RedisSessionLifecycleError> {
        let subject_key = subject_index(subject_id);
        let members = match self
            .bounded_members(&subject_key, MAX_SUBJECT_SESSIONS)
            .await
        {
            Ok(members) => members,
            Err(error) => return Err(fail_closed(current, error).await),
        };
        let current_id = current.id().map(|id| id.to_string());
        let store = FeatureStableRedisStore::new(self.client.clone());
        let mut active = Vec::with_capacity(members.len());
        for member in members {
            let Some((device_id, lineage_id, raw)) = parse_subject_member(&member) else {
                return Err(fail_closed(current, RedisSessionLifecycleError::CorruptData).await);
            };
            let id = Id::from_str(raw).map_err(|_| RedisSessionLifecycleError::CorruptData)?;
            let record = match store.load(&id).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    self.remove_indexes(subject_id, device_id, lineage_id, raw)
                        .await?;
                    continue;
                }
                Err(_) => {
                    return Err(
                        fail_closed(current, RedisSessionLifecycleError::Unavailable).await,
                    );
                }
            };
            let Some(metadata) = record_metadata(&record) else {
                return Err(fail_closed(current, RedisSessionLifecycleError::CorruptData).await);
            };
            if metadata.subject_id != subject_id
                || metadata.device_id != device_id
                || metadata.lineage_id != lineage_id
            {
                self.remove_indexes(subject_id, device_id, lineage_id, raw)
                    .await?;
                continue;
            }
            if record.expiry_date <= now
                || !self.active(&metadata, now)?
                || !self.indexed(raw, &metadata).await?
            {
                self.delete_record_and_indexes(subject_id, device_id, lineage_id, raw)
                    .await?;
                continue;
            }
            active.push(metadata.public(current_id.as_deref() == Some(raw)));
        }
        active.sort_unstable_by_key(|metadata| (Reverse(metadata.created_at), metadata.device_id));
        Ok(active)
    }

    /// Atomically consumes the old provider/index identity and advances its
    /// lineage generation before cycling and registering the sole successor.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error and flushes the session on failure.
    pub async fn rotate_after_security_change(
        &self,
        session: &Session,
        subject_id: SubjectId,
        registration: &SessionRegistration<'_>,
        now: OffsetDateTime,
    ) -> Result<bool, RedisSessionLifecycleError> {
        if registration.subject_id != subject_id {
            return Err(RedisSessionLifecycleError::InvalidInput);
        }
        let validation = self.validate_and_touch(session, subject_id, now).await?;
        if validation == SessionValidation::Rejected {
            return Err(fail_closed(session, RedisSessionLifecycleError::Inactive).await);
        }
        let old_raw = current_session_id(session)?;
        let metadata = match session.get::<LifecycleRecord>(LIFECYCLE_KEY).await {
            Ok(Some(metadata)) => metadata,
            Ok(None) => {
                return Err(fail_closed(session, RedisSessionLifecycleError::Inactive).await);
            }
            Err(_) => {
                return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
            }
        };
        if registration.device_id != metadata.device_id {
            return Err(fail_closed(session, RedisSessionLifecycleError::InvalidInput).await);
        }
        let claimed_lineage = match self.claim_rotation(&old_raw, &metadata).await {
            Ok(generation) => generation,
            Err(error) => return Err(fail_closed(session, error).await),
        };
        let generations = Generations {
            subject: metadata.subject_epoch,
            device: metadata.device_epoch,
            lineage: claimed_lineage,
        };
        if session.cycle_id().await.is_err() {
            return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
        }
        self.register_with_generations(session, registration, metadata.lineage_id, generations)
            .await?;
        Ok(true)
    }

    /// Revokes the current logical lineage after validating subject ownership.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error and flushes the session on failure.
    pub async fn revoke_current(
        &self,
        session: &Session,
        subject_id: SubjectId,
    ) -> Result<bool, RedisSessionLifecycleError> {
        let Some(raw) = session.id().map(|id| id.to_string()) else {
            return Ok(false);
        };
        let metadata = match session.get::<LifecycleRecord>(LIFECYCLE_KEY).await {
            Ok(Some(metadata)) if metadata.subject_id == subject_id => metadata,
            Ok(_) => return Ok(false),
            Err(_) => {
                return Err(fail_closed(session, RedisSessionLifecycleError::SessionData).await);
            }
        };
        let keys = index_keys(subject_id, metadata.device_id, metadata.lineage_id, &raw);
        let result = self
            .client
            .eval::<i64, _, _, _>(
                REVOKE_CURRENT_SCRIPT,
                vec![
                    keys.lineage_epoch,
                    raw,
                    keys.lineage,
                    GLOBAL_INDEX.to_owned(),
                    keys.subject,
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                    keys.subject_epoch,
                ],
                vec![
                    keys.subject_token,
                    metadata.lineage_id.to_string(),
                    keys.lineage_token,
                    DEVICE_INDEX_PREFIX.to_owned(),
                    MAX_LINEAGE_SESSIONS.to_string(),
                    MAX_TRACKED_LINEAGES.to_string(),
                    DEVICE_EPOCH_PREFIX.to_owned(),
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable);
        match result {
            Ok(count) if count > 0 => Ok(true),
            Ok(-3) => Err(fail_closed(session, RedisSessionLifecycleError::CapacityExceeded).await),
            Ok(_) => Err(fail_closed(session, RedisSessionLifecycleError::CorruptData).await),
            Err(error) => Err(fail_closed(session, error).await),
        }
    }

    /// Increments the device generation before atomically deleting every indexed
    /// provider key for that device.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error when Redis is unavailable or persisted indexes are invalid.
    pub async fn revoke_device(
        &self,
        subject_id: SubjectId,
        device_id: Uuid,
    ) -> Result<u64, RedisSessionLifecycleError> {
        let subject_token = subject_id.as_uuid().to_string();
        let device_token = format!("{subject_token}:{device_id}");
        let result = self
            .client
            .eval::<i64, _, _, _>(
                REVOKE_DEVICE_SCRIPT,
                vec![
                    device_epoch(subject_id, device_id),
                    format!("{DEVICE_INDEX_PREFIX}{device_token}"),
                    subject_index(subject_id),
                    GLOBAL_INDEX.to_owned(),
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                    subject_epoch(subject_id),
                ],
                vec![
                    device_id.to_string(),
                    subject_token,
                    device_token,
                    LINEAGE_INDEX_PREFIX.to_owned(),
                    MAX_DEVICE_SESSIONS.to_string(),
                    MAX_SUBJECT_SESSIONS.to_string(),
                    MAX_TRACKED_DEVICES.to_string(),
                    LINEAGE_EPOCH_PREFIX.to_owned(),
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        script_count(result)
    }

    /// Increments the subject generation before atomically deleting every
    /// indexed provider key for that subject.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error when Redis is unavailable or persisted indexes are invalid.
    pub async fn revoke_all(
        &self,
        subject_id: SubjectId,
    ) -> Result<u64, RedisSessionLifecycleError> {
        let subject_token = subject_id.as_uuid().to_string();
        let result = self
            .client
            .eval::<i64, _, _, _>(
                REVOKE_ALL_SCRIPT,
                vec![
                    subject_epoch(subject_id),
                    subject_index(subject_id),
                    GLOBAL_INDEX.to_owned(),
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                ],
                vec![
                    subject_token,
                    DEVICE_INDEX_PREFIX.to_owned(),
                    LINEAGE_INDEX_PREFIX.to_owned(),
                    MAX_SUBJECT_SESSIONS.to_string(),
                    MAX_TRACKED_SUBJECTS.to_string(),
                    MAX_TRACKED_DEVICES.to_string(),
                    MAX_TRACKED_LINEAGES.to_string(),
                    DEVICE_EPOCH_PREFIX.to_owned(),
                    LINEAGE_EPOCH_PREFIX.to_owned(),
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        script_count(result)
    }

    /// Performs one bounded cleanup pass across the global, subject, device, and
    /// logical-lineage catalogs, removing expired records and stale index members.
    ///
    /// # Errors
    ///
    /// Returns a value-free lifecycle error when Redis is unavailable or persisted indexes are invalid.
    pub async fn cleanup(
        &self,
        now: OffsetDateTime,
    ) -> Result<SessionCleanup, RedisSessionLifecycleError> {
        let global = self
            .bounded_members(GLOBAL_INDEX, MAX_TRACKED_SESSIONS)
            .await?;
        let store = FeatureStableRedisStore::new(self.client.clone());
        let mut provider_rows = 0_u64;
        let mut metadata_rows = 0_u64;
        for member in global {
            let Some((subject_id, device_id, lineage_id, raw)) = parse_global_member(&member)
            else {
                self.client
                    .srem::<i64, _, _>(GLOBAL_INDEX, member)
                    .await
                    .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
                metadata_rows = metadata_rows.saturating_add(1);
                continue;
            };
            let id = Id::from_str(raw).map_err(|_| RedisSessionLifecycleError::CorruptData)?;
            let loaded = store
                .load(&id)
                .await
                .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
            let (stale_index, delete_provider) = match loaded.as_ref() {
                None => (true, false),
                Some(record) => match record_metadata(record) {
                    Some(metadata)
                        if metadata.subject_id == subject_id
                            && metadata.device_id == device_id
                            && metadata.lineage_id == lineage_id =>
                    {
                        let inactive = record.expiry_date <= now
                            || !self.active(&metadata, now)?
                            || !self.indexed(raw, &metadata).await?;
                        (inactive, inactive)
                    }
                    Some(_) | None => (true, false),
                },
            };
            if stale_index {
                if delete_provider {
                    store
                        .delete(&id)
                        .await
                        .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
                    provider_rows = provider_rows.saturating_add(1);
                }
                self.remove_indexes(subject_id, device_id, lineage_id, raw)
                    .await?;
                metadata_rows = metadata_rows.saturating_add(1);
            }
        }
        metadata_rows = metadata_rows.saturating_add(self.cleanup_subject_catalog().await?);
        metadata_rows = metadata_rows.saturating_add(self.cleanup_device_catalog().await?);
        metadata_rows = metadata_rows.saturating_add(self.cleanup_lineage_catalog().await?);
        Ok(SessionCleanup {
            provider_rows,
            metadata_rows,
        })
    }

    async fn claim_rotation(
        &self,
        raw: &str,
        metadata: &LifecycleRecord,
    ) -> Result<i64, RedisSessionLifecycleError> {
        let keys = index_keys(
            metadata.subject_id,
            metadata.device_id,
            metadata.lineage_id,
            raw,
        );
        let result = self
            .client
            .eval::<i64, _, _, _>(
                ROTATION_CLAIM_SCRIPT,
                vec![
                    raw.to_owned(),
                    keys.subject_epoch,
                    keys.device_epoch,
                    keys.lineage_epoch,
                    GLOBAL_INDEX.to_owned(),
                    keys.subject,
                    keys.device,
                    keys.lineage,
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                ],
                vec![
                    metadata.subject_epoch.to_string(),
                    metadata.device_epoch.to_string(),
                    metadata.lineage_epoch.to_string(),
                    keys.subject_member,
                    keys.global_member,
                    keys.device_member,
                    keys.lineage_member,
                    keys.subject_token,
                    keys.device_token,
                    keys.lineage_token,
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        let expected = metadata
            .lineage_epoch
            .checked_add(1)
            .ok_or(RedisSessionLifecycleError::CorruptData)?;
        match result {
            claimed if claimed == expected => Ok(claimed),
            -1 => Err(RedisSessionLifecycleError::Conflict),
            _ => Err(RedisSessionLifecycleError::CorruptData),
        }
    }

    async fn generations(
        &self,
        subject_id: SubjectId,
        device_id: Uuid,
        lineage_id: Uuid,
    ) -> Result<Generations, RedisSessionLifecycleError> {
        let subject = self.read_generation(subject_epoch(subject_id)).await?;
        let device = self
            .read_generation(device_epoch(subject_id, device_id))
            .await?;
        let lineage = self
            .read_generation(lineage_epoch(subject_id, lineage_id))
            .await?;
        Ok(Generations {
            subject,
            device,
            lineage,
        })
    }

    async fn read_generation(&self, key: String) -> Result<i64, RedisSessionLifecycleError> {
        let value = self
            .client
            .get::<Option<String>, _>(key)
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        match value {
            None => Ok(0),
            Some(value) => value
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(RedisSessionLifecycleError::CorruptData),
        }
    }

    fn deadline(
        &self,
        now: OffsetDateTime,
        absolute: OffsetDateTime,
    ) -> Result<OffsetDateTime, RedisSessionLifecycleError> {
        let idle = time::Duration::try_from(self.config.idle_timeout)
            .map_err(|_| RedisSessionLifecycleError::InvalidInput)?;
        let idle_deadline = now
            .checked_add(idle)
            .ok_or(RedisSessionLifecycleError::InvalidInput)?;
        Ok(idle_deadline.min(absolute))
    }

    fn active(
        &self,
        metadata: &LifecycleRecord,
        now: OffsetDateTime,
    ) -> Result<bool, RedisSessionLifecycleError> {
        let idle_deadline = self.deadline(metadata.last_seen_at, metadata.absolute_expires_at)?;
        Ok(now < idle_deadline && now < metadata.absolute_expires_at)
    }

    async fn indexed(
        &self,
        raw: &str,
        metadata: &LifecycleRecord,
    ) -> Result<bool, RedisSessionLifecycleError> {
        let keys = index_keys(
            metadata.subject_id,
            metadata.device_id,
            metadata.lineage_id,
            raw,
        );
        let result = self
            .client
            .eval::<i64, _, _, _>(
                VALIDATE_SCRIPT,
                vec![
                    raw.to_owned(),
                    keys.subject_epoch,
                    keys.device_epoch,
                    keys.lineage_epoch,
                    GLOBAL_INDEX.to_owned(),
                    keys.subject,
                    keys.device,
                    keys.lineage,
                ],
                vec![
                    metadata.subject_epoch.to_string(),
                    metadata.device_epoch.to_string(),
                    metadata.lineage_epoch.to_string(),
                    keys.subject_member,
                    keys.global_member,
                    keys.device_member,
                    keys.lineage_member,
                ],
            )
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        match result {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(RedisSessionLifecycleError::CorruptData),
        }
    }

    async fn bounded_members(
        &self,
        key: &str,
        maximum: i64,
    ) -> Result<Vec<String>, RedisSessionLifecycleError> {
        let count = self
            .client
            .scard::<i64, _>(key)
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        if count < 0 {
            return Err(RedisSessionLifecycleError::CorruptData);
        }
        if count > maximum {
            return Err(RedisSessionLifecycleError::CapacityExceeded);
        }
        let members = self
            .client
            .smembers::<Vec<String>, _>(key)
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        if i64::try_from(members.len()).map_or(true, |length| length > maximum) {
            return Err(RedisSessionLifecycleError::CapacityExceeded);
        }
        Ok(members)
    }

    async fn remove_indexes(
        &self,
        subject_id: SubjectId,
        device_id: Uuid,
        lineage_id: Uuid,
        raw: &str,
    ) -> Result<(), RedisSessionLifecycleError> {
        let keys = index_keys(subject_id, device_id, lineage_id, raw);
        self.client
            .eval::<i64, _, _, _>(
                REMOVE_INDEX_SCRIPT,
                vec![
                    GLOBAL_INDEX.to_owned(),
                    keys.subject,
                    keys.device,
                    keys.lineage,
                    SUBJECT_CATALOG.to_owned(),
                    DEVICE_CATALOG.to_owned(),
                    LINEAGE_CATALOG.to_owned(),
                    keys.subject_epoch,
                    keys.device_epoch,
                    keys.lineage_epoch,
                ],
                vec![
                    keys.global_member,
                    keys.subject_member,
                    keys.device_member,
                    keys.lineage_member,
                    keys.subject_token,
                    keys.device_token,
                    keys.lineage_token,
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map(|_| ())
            .map_err(|_| RedisSessionLifecycleError::Unavailable)
    }

    async fn delete_record_and_indexes(
        &self,
        subject_id: SubjectId,
        device_id: Uuid,
        lineage_id: Uuid,
        raw: &str,
    ) -> Result<(), RedisSessionLifecycleError> {
        self.client
            .del::<i64, _>(raw)
            .await
            .map_err(|_| RedisSessionLifecycleError::Unavailable)?;
        self.remove_indexes(subject_id, device_id, lineage_id, raw)
            .await
    }

    async fn cleanup_subject_catalog(&self) -> Result<u64, RedisSessionLifecycleError> {
        let subjects = self
            .bounded_members(SUBJECT_CATALOG, MAX_TRACKED_SUBJECTS)
            .await?;
        let mut removed = 0_u64;
        for subject in subjects {
            let key = format!("{SUBJECT_INDEX_PREFIX}{subject}");
            let members = self.bounded_members(&key, MAX_SUBJECT_SESSIONS).await?;
            for member in members {
                let stale = match parse_subject_member(&member) {
                    Some((_, _, raw)) => {
                        self.client
                            .exists::<i64, _>(raw)
                            .await
                            .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                            == 0
                    }
                    None => true,
                };
                if stale {
                    self.prune_catalog_member(
                        &key,
                        SUBJECT_CATALOG,
                        &format!("{SUBJECT_EPOCH_PREFIX}{subject}"),
                        &member,
                        &subject,
                    )
                    .await?;
                    removed = removed.saturating_add(1);
                }
            }
            if self
                .client
                .scard::<i64, _>(&key)
                .await
                .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                == 0
            {
                self.prune_catalog_member(
                    &key,
                    SUBJECT_CATALOG,
                    &format!("{SUBJECT_EPOCH_PREFIX}{subject}"),
                    "",
                    &subject,
                )
                .await?;
            }
        }
        Ok(removed)
    }

    async fn cleanup_device_catalog(&self) -> Result<u64, RedisSessionLifecycleError> {
        let devices = self
            .bounded_members(DEVICE_CATALOG, MAX_TRACKED_DEVICES)
            .await?;
        let mut removed = 0_u64;
        for device in devices {
            let key = format!("{DEVICE_INDEX_PREFIX}{device}");
            let members = self.bounded_members(&key, MAX_DEVICE_SESSIONS).await?;
            for member in members {
                let stale = match parse_device_member(&member) {
                    Some((_, raw)) => {
                        self.client
                            .exists::<i64, _>(raw)
                            .await
                            .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                            == 0
                    }
                    None => true,
                };
                if stale {
                    self.prune_catalog_member(
                        &key,
                        DEVICE_CATALOG,
                        &format!("{DEVICE_EPOCH_PREFIX}{device}"),
                        &member,
                        &device,
                    )
                    .await?;
                    removed = removed.saturating_add(1);
                }
            }
            if self
                .client
                .scard::<i64, _>(&key)
                .await
                .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                == 0
            {
                self.prune_catalog_member(
                    &key,
                    DEVICE_CATALOG,
                    &format!("{DEVICE_EPOCH_PREFIX}{device}"),
                    "",
                    &device,
                )
                .await?;
            }
        }
        Ok(removed)
    }

    async fn cleanup_lineage_catalog(&self) -> Result<u64, RedisSessionLifecycleError> {
        let lineages = self
            .bounded_members(LINEAGE_CATALOG, MAX_TRACKED_LINEAGES)
            .await?;
        let mut removed = 0_u64;
        for lineage in lineages {
            let key = format!("{LINEAGE_INDEX_PREFIX}{lineage}");
            let members = self.bounded_members(&key, MAX_LINEAGE_SESSIONS).await?;
            let valid_token = parse_lineage_token(&lineage).is_some();
            for member in members {
                let stale = if valid_token {
                    match parse_lineage_member(&member) {
                        Some((_, raw)) => {
                            self.client
                                .exists::<i64, _>(raw)
                                .await
                                .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                                == 0
                        }
                        None => true,
                    }
                } else {
                    true
                };
                if stale {
                    self.prune_catalog_member(
                        &key,
                        LINEAGE_CATALOG,
                        &format!("{LINEAGE_EPOCH_PREFIX}{lineage}"),
                        &member,
                        &lineage,
                    )
                    .await?;
                    removed = removed.saturating_add(1);
                }
            }
            if self
                .client
                .scard::<i64, _>(&key)
                .await
                .map_err(|_| RedisSessionLifecycleError::Unavailable)?
                == 0
            {
                self.prune_catalog_member(
                    &key,
                    LINEAGE_CATALOG,
                    &format!("{LINEAGE_EPOCH_PREFIX}{lineage}"),
                    "",
                    &lineage,
                )
                .await?;
            }
        }
        Ok(removed)
    }

    async fn prune_catalog_member(
        &self,
        index: &str,
        catalog: &str,
        epoch: &str,
        member: &str,
        token: &str,
    ) -> Result<(), RedisSessionLifecycleError> {
        self.client
            .eval::<i64, _, _, _>(
                PRUNE_MEMBER_SCRIPT,
                vec![index.to_owned(), catalog.to_owned(), epoch.to_owned()],
                vec![
                    member.to_owned(),
                    token.to_owned(),
                    GENERATION_TOMBSTONE_TTL_SECONDS.to_string(),
                ],
            )
            .await
            .map(|_| ())
            .map_err(|_| RedisSessionLifecycleError::Unavailable)
    }
}

fn parse_subject_member(member: &str) -> Option<(Uuid, Uuid, &str)> {
    let mut parts = member.splitn(3, ':');
    let device = Uuid::parse_str(parts.next()?).ok()?;
    let lineage = Uuid::parse_str(parts.next()?).ok()?;
    let raw = parts.next()?;
    Id::from_str(raw).ok()?;
    Some((device, lineage, raw))
}

fn parse_device_member(member: &str) -> Option<(Uuid, &str)> {
    let (lineage, raw) = member.split_once(':')?;
    let lineage = Uuid::parse_str(lineage).ok()?;
    Id::from_str(raw).ok()?;
    Some((lineage, raw))
}

fn parse_lineage_member(member: &str) -> Option<(Uuid, &str)> {
    let (device, raw) = member.split_once(':')?;
    let device = Uuid::parse_str(device).ok()?;
    Id::from_str(raw).ok()?;
    Some((device, raw))
}

fn parse_lineage_token(token: &str) -> Option<(SubjectId, Uuid)> {
    let (subject, lineage) = token.split_once(':')?;
    let subject = SubjectId::from_uuid(Uuid::parse_str(subject).ok()?).ok()?;
    let lineage = Uuid::parse_str(lineage).ok()?;
    Some((subject, lineage))
}

fn parse_global_member(member: &str) -> Option<(SubjectId, Uuid, Uuid, &str)> {
    let mut parts = member.splitn(4, ':');
    let subject = Uuid::parse_str(parts.next()?).ok()?;
    let device = Uuid::parse_str(parts.next()?).ok()?;
    let lineage = Uuid::parse_str(parts.next()?).ok()?;
    let raw = parts.next()?;
    Id::from_str(raw).ok()?;
    let subject = SubjectId::from_uuid(subject).ok()?;
    Some((subject, device, lineage, raw))
}

fn record_metadata(record: &Record) -> Option<LifecycleRecord> {
    record
        .data
        .get(LIFECYCLE_KEY)
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

fn current_session_id(session: &Session) -> Result<String, RedisSessionLifecycleError> {
    session
        .id()
        .map(|id| id.to_string())
        .ok_or(RedisSessionLifecycleError::MissingSessionId)
}

fn script_count(result: i64) -> Result<u64, RedisSessionLifecycleError> {
    match result {
        -3 => Err(RedisSessionLifecycleError::CapacityExceeded),
        -4 => Err(RedisSessionLifecycleError::CorruptData),
        count if count >= 0 => {
            u64::try_from(count).map_err(|_| RedisSessionLifecycleError::CorruptData)
        }
        _ => Err(RedisSessionLifecycleError::CorruptData),
    }
}

async fn reject_session(
    session: &Session,
) -> Result<SessionValidation, RedisSessionLifecycleError> {
    session
        .flush()
        .await
        .map(|()| SessionValidation::Rejected)
        .map_err(|_| RedisSessionLifecycleError::SessionData)
}

async fn fail_closed(
    session: &Session,
    failure: RedisSessionLifecycleError,
) -> RedisSessionLifecycleError {
    if session.flush().await.is_err() {
        RedisSessionLifecycleError::SessionData
    } else {
        failure
    }
}

pub(crate) async fn probe_permissions(client: &Client, nonce: &str) -> Result<(), ()> {
    let epoch = format!("__omnius:lifecycle:probe:epoch:{nonce}");
    let index = format!("__omnius:lifecycle:probe:index:{nonce}");
    let result = client
        .eval::<i64, _, _, _>(
            PERMISSION_PROBE_SCRIPT,
            vec![nonce.to_owned(), epoch.clone(), index.clone()],
            vec!["probe"],
        )
        .await;
    let _cleanup = client.del::<i64, _>(vec![epoch, index]).await;
    match result {
        Ok(1) => Ok(()),
        Ok(_) | Err(_) => Err(()),
    }
}

/// Stable, value-free Redis lifecycle failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RedisSessionLifecycleError {
    /// Tower session data could not be loaded, encoded, saved, or flushed.
    #[error("session data operation failed")]
    SessionData,
    /// Registration or rotation did not produce a provider identifier.
    #[error("session identifier is unavailable")]
    MissingSessionId,
    /// Registration metadata or timeout arithmetic was invalid.
    #[error("session metadata input is invalid")]
    InvalidInput,
    /// A revocation generation changed while registration was in flight.
    #[error("session metadata conflicts with persisted state")]
    Conflict,
    /// The provider session is missing, revoked, or expired.
    #[error("session is inactive")]
    Inactive,
    /// A required Redis command failed.
    #[error("session persistence is unavailable")]
    Unavailable,
    /// Provider metadata or lifecycle indexes violated their contract.
    #[error("session persistence contains invalid state")]
    CorruptData,
    /// A bounded lifecycle index reached its hard maximum.
    #[error("session lifecycle capacity was exceeded")]
    CapacityExceeded,
}

#[cfg(test)]
mod tests {
    use omnius_config::ExposeSecret as _;
    use omnius_test_support::RedisFixture;

    use super::*;

    #[derive(Clone)]
    struct TestIdentity {
        subject_id: SubjectId,
        device_id: Uuid,
        lineage_id: Uuid,
        raw: String,
    }

    impl TestIdentity {
        fn new(subject_id: SubjectId) -> Self {
            Self {
                subject_id,
                device_id: Uuid::now_v7(),
                lineage_id: Uuid::now_v7(),
                raw: Uuid::now_v7().to_string(),
            }
        }

        fn successor(&self) -> Self {
            Self {
                subject_id: self.subject_id,
                device_id: self.device_id,
                lineage_id: self.lineage_id,
                raw: Uuid::now_v7().to_string(),
            }
        }
    }

    async fn save_provider(
        connection: &mut redis::aio::MultiplexedConnection,
        raw: &str,
    ) -> Result<(), redis::RedisError> {
        redis::cmd("SET")
            .arg(raw)
            .arg("provider-record")
            .query_async::<String>(connection)
            .await
            .map(|_| ())
    }

    async fn register_member(
        connection: &mut redis::aio::MultiplexedConnection,
        identity: &TestIdentity,
        generations: Generations,
    ) -> Result<i64, redis::RedisError> {
        let keys = index_keys(
            identity.subject_id,
            identity.device_id,
            identity.lineage_id,
            &identity.raw,
        );
        redis::cmd("EVAL")
            .arg(REGISTER_SCRIPT)
            .arg(11)
            .arg(&identity.raw)
            .arg(&keys.subject_epoch)
            .arg(&keys.device_epoch)
            .arg(&keys.lineage_epoch)
            .arg(GLOBAL_INDEX)
            .arg(&keys.subject)
            .arg(&keys.device)
            .arg(&keys.lineage)
            .arg(SUBJECT_CATALOG)
            .arg(DEVICE_CATALOG)
            .arg(LINEAGE_CATALOG)
            .arg(generations.subject)
            .arg(generations.device)
            .arg(generations.lineage)
            .arg(&keys.subject_member)
            .arg(&keys.global_member)
            .arg(&keys.device_member)
            .arg(&keys.lineage_member)
            .arg(&identity.raw)
            .arg(&keys.subject_token)
            .arg(&keys.device_token)
            .arg(&keys.lineage_token)
            .arg(MAX_TRACKED_SESSIONS)
            .arg(MAX_SUBJECT_SESSIONS)
            .arg(MAX_DEVICE_SESSIONS)
            .arg(MAX_LINEAGE_SESSIONS)
            .arg(MAX_TRACKED_SUBJECTS)
            .arg(MAX_TRACKED_DEVICES)
            .arg(MAX_TRACKED_LINEAGES)
            .query_async::<i64>(connection)
            .await
    }

    async fn prepare_registered(
        connection: &mut redis::aio::MultiplexedConnection,
        identity: &TestIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        save_provider(connection, &identity.raw).await?;
        assert_eq!(
            register_member(
                connection,
                identity,
                Generations {
                    subject: 0,
                    device: 0,
                    lineage: 0,
                },
            )
            .await?,
            1
        );
        Ok(())
    }

    async fn claim_rotation(
        connection: &mut redis::aio::MultiplexedConnection,
        identity: &TestIdentity,
        generations: Generations,
    ) -> Result<i64, redis::RedisError> {
        let keys = index_keys(
            identity.subject_id,
            identity.device_id,
            identity.lineage_id,
            &identity.raw,
        );
        redis::cmd("EVAL")
            .arg(ROTATION_CLAIM_SCRIPT)
            .arg(11)
            .arg(&identity.raw)
            .arg(&keys.subject_epoch)
            .arg(&keys.device_epoch)
            .arg(&keys.lineage_epoch)
            .arg(GLOBAL_INDEX)
            .arg(&keys.subject)
            .arg(&keys.device)
            .arg(&keys.lineage)
            .arg(SUBJECT_CATALOG)
            .arg(DEVICE_CATALOG)
            .arg(LINEAGE_CATALOG)
            .arg(generations.subject)
            .arg(generations.device)
            .arg(generations.lineage)
            .arg(&keys.subject_member)
            .arg(&keys.global_member)
            .arg(&keys.device_member)
            .arg(&keys.lineage_member)
            .arg(&keys.subject_token)
            .arg(&keys.device_token)
            .arg(&keys.lineage_token)
            .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
            .query_async::<i64>(connection)
            .await
    }

    async fn revoke_lineage(
        connection: &mut redis::aio::MultiplexedConnection,
        identity: &TestIdentity,
    ) -> Result<i64, redis::RedisError> {
        let keys = index_keys(
            identity.subject_id,
            identity.device_id,
            identity.lineage_id,
            &identity.raw,
        );
        redis::cmd("EVAL")
            .arg(REVOKE_CURRENT_SCRIPT)
            .arg(9)
            .arg(&keys.lineage_epoch)
            .arg(&identity.raw)
            .arg(&keys.lineage)
            .arg(GLOBAL_INDEX)
            .arg(&keys.subject)
            .arg(SUBJECT_CATALOG)
            .arg(DEVICE_CATALOG)
            .arg(LINEAGE_CATALOG)
            .arg(&keys.subject_epoch)
            .arg(&keys.subject_token)
            .arg(identity.lineage_id.to_string())
            .arg(&keys.lineage_token)
            .arg(DEVICE_INDEX_PREFIX)
            .arg(MAX_LINEAGE_SESSIONS)
            .arg(MAX_TRACKED_LINEAGES)
            .arg(DEVICE_EPOCH_PREFIX)
            .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
            .query_async::<i64>(connection)
            .await
    }

    async fn revoke_device_with_capacity(
        connection: &mut redis::aio::MultiplexedConnection,
        subject_id: SubjectId,
        device_id: Uuid,
        capacity: i64,
    ) -> Result<i64, redis::RedisError> {
        let subject_token = subject_id.as_uuid().to_string();
        let device_token = format!("{subject_token}:{device_id}");
        redis::cmd("EVAL")
            .arg(REVOKE_DEVICE_SCRIPT)
            .arg(8)
            .arg(device_epoch(subject_id, device_id))
            .arg(format!("{DEVICE_INDEX_PREFIX}{device_token}"))
            .arg(subject_index(subject_id))
            .arg(GLOBAL_INDEX)
            .arg(SUBJECT_CATALOG)
            .arg(DEVICE_CATALOG)
            .arg(LINEAGE_CATALOG)
            .arg(subject_epoch(subject_id))
            .arg(device_id.to_string())
            .arg(&subject_token)
            .arg(&device_token)
            .arg(LINEAGE_INDEX_PREFIX)
            .arg(MAX_DEVICE_SESSIONS)
            .arg(MAX_SUBJECT_SESSIONS)
            .arg(capacity)
            .arg(LINEAGE_EPOCH_PREFIX)
            .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
            .query_async::<i64>(connection)
            .await
    }

    async fn revoke_subject(
        connection: &mut redis::aio::MultiplexedConnection,
        subject_id: SubjectId,
    ) -> Result<i64, redis::RedisError> {
        let subject_token = subject_id.as_uuid().to_string();
        redis::cmd("EVAL")
            .arg(REVOKE_ALL_SCRIPT)
            .arg(6)
            .arg(subject_epoch(subject_id))
            .arg(subject_index(subject_id))
            .arg(GLOBAL_INDEX)
            .arg(SUBJECT_CATALOG)
            .arg(DEVICE_CATALOG)
            .arg(LINEAGE_CATALOG)
            .arg(&subject_token)
            .arg(DEVICE_INDEX_PREFIX)
            .arg(LINEAGE_INDEX_PREFIX)
            .arg(MAX_SUBJECT_SESSIONS)
            .arg(MAX_TRACKED_SUBJECTS)
            .arg(MAX_TRACKED_DEVICES)
            .arg(MAX_TRACKED_LINEAGES)
            .arg(DEVICE_EPOCH_PREFIX)
            .arg(LINEAGE_EPOCH_PREFIX)
            .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
            .query_async::<i64>(connection)
            .await
    }

    async fn assert_short_tombstone(
        connection: &mut redis::aio::MultiplexedConnection,
        epoch: &str,
    ) -> Result<(), redis::RedisError> {
        let ttl = redis::cmd("TTL")
            .arg(epoch)
            .query_async::<i64>(connection)
            .await?;
        assert!((1..=GENERATION_TOMBSTONE_TTL_SECONDS).contains(&ttl));
        Ok(())
    }

    async fn assert_rejected_and_deleted(
        connection: &mut redis::aio::MultiplexedConnection,
        identity: &TestIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            register_member(
                connection,
                identity,
                Generations {
                    subject: 0,
                    device: 0,
                    lineage: 0,
                },
            )
            .await?,
            -1
        );
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(&identity.raw)
                .query_async::<i64>(connection)
                .await?,
            0
        );
        Ok(())
    }

    async fn assert_current_tombstone_order(
        connection: &mut redis::aio::MultiplexedConnection,
        save_before_revoke: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let old = TestIdentity::new(SubjectId::new());
        let delayed = old.successor();
        prepare_registered(connection, &old).await?;
        if save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert!(revoke_lineage(connection, &old).await? > 0);
        assert_short_tombstone(connection, &lineage_epoch(old.subject_id, old.lineage_id)).await?;
        if !save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert_rejected_and_deleted(connection, &delayed).await
    }

    async fn assert_device_tombstone_order(
        connection: &mut redis::aio::MultiplexedConnection,
        save_before_revoke: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let delayed = TestIdentity::new(SubjectId::new());
        if save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert_eq!(
            revoke_device_with_capacity(
                connection,
                delayed.subject_id,
                delayed.device_id,
                MAX_TRACKED_DEVICES,
            )
            .await?,
            0
        );
        assert_short_tombstone(
            connection,
            &device_epoch(delayed.subject_id, delayed.device_id),
        )
        .await?;
        if !save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert_rejected_and_deleted(connection, &delayed).await
    }

    async fn assert_subject_tombstone_order(
        connection: &mut redis::aio::MultiplexedConnection,
        save_before_revoke: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let delayed = TestIdentity::new(SubjectId::new());
        if save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert_eq!(revoke_subject(connection, delayed.subject_id).await?, 0);
        assert_short_tombstone(connection, &subject_epoch(delayed.subject_id)).await?;
        if !save_before_revoke {
            save_provider(connection, &delayed.raw).await?;
        }
        assert_rejected_and_deleted(connection, &delayed).await
    }

    async fn assert_single_rotation_winner(
        connection: &mut redis::aio::MultiplexedConnection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let old = TestIdentity::new(SubjectId::new());
        prepare_registered(connection, &old).await?;
        let mut first = connection.clone();
        let mut second = connection.clone();
        let generations = Generations {
            subject: 0,
            device: 0,
            lineage: 0,
        };
        let (first_result, second_result) = tokio::join!(
            claim_rotation(&mut first, &old, generations),
            claim_rotation(&mut second, &old, generations),
        );
        let mut claims = [first_result?, second_result?];
        claims.sort_unstable();
        assert_eq!(claims, [-1, 1]);
        let successor = old.successor();
        save_provider(connection, &successor.raw).await?;
        assert_eq!(
            register_member(
                connection,
                &successor,
                Generations {
                    lineage: 1,
                    ..generations
                },
            )
            .await?,
            1
        );
        let keys = index_keys(
            successor.subject_id,
            successor.device_id,
            successor.lineage_id,
            &successor.raw,
        );
        assert_eq!(
            redis::cmd("SCARD")
                .arg(keys.lineage)
                .query_async::<i64>(connection)
                .await?,
            1
        );
        Ok(())
    }

    async fn assert_current_revoke_rotation_boundaries(
        connection: &mut redis::aio::MultiplexedConnection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let generations = Generations {
            subject: 0,
            device: 0,
            lineage: 0,
        };
        let revoked_before = TestIdentity::new(SubjectId::new());
        prepare_registered(connection, &revoked_before).await?;
        assert!(revoke_lineage(connection, &revoked_before).await? > 0);
        assert_eq!(
            claim_rotation(connection, &revoked_before, generations).await?,
            -1
        );

        let revoked_during_gap = TestIdentity::new(SubjectId::new());
        prepare_registered(connection, &revoked_during_gap).await?;
        assert_eq!(
            claim_rotation(connection, &revoked_during_gap, generations).await?,
            1
        );
        assert!(revoke_lineage(connection, &revoked_during_gap).await? > 0);
        let delayed = revoked_during_gap.successor();
        save_provider(connection, &delayed.raw).await?;
        assert_eq!(
            register_member(
                connection,
                &delayed,
                Generations {
                    lineage: 1,
                    ..generations
                },
            )
            .await?,
            -1
        );

        let revoked_after = TestIdentity::new(SubjectId::new());
        prepare_registered(connection, &revoked_after).await?;
        assert_eq!(
            claim_rotation(connection, &revoked_after, generations).await?,
            1
        );
        let registered = revoked_after.successor();
        save_provider(connection, &registered.raw).await?;
        assert_eq!(
            register_member(
                connection,
                &registered,
                Generations {
                    lineage: 1,
                    ..generations
                },
            )
            .await?,
            1
        );
        assert!(revoke_lineage(connection, &revoked_after).await? > 0);
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(&registered.raw)
                .query_async::<i64>(connection)
                .await?,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn rotation_claim_has_one_winner_and_current_revoke_covers_each_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = RedisFixture::start().await?;
        let client = redis::Client::open(fixture.redis_url().expose_secret())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        assert_single_rotation_winner(&mut connection).await?;
        assert_current_revoke_rotation_boundaries(&mut connection).await?;
        fixture.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn bounded_tombstones_reject_delayed_registration_and_active_epochs_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = RedisFixture::start().await?;
        let client = redis::Client::open(fixture.redis_url().expose_secret())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        for save_before_revoke in [true, false] {
            assert_current_tombstone_order(&mut connection, save_before_revoke).await?;
            assert_device_tombstone_order(&mut connection, save_before_revoke).await?;
            assert_subject_tombstone_order(&mut connection, save_before_revoke).await?;
        }

        let active = TestIdentity::new(SubjectId::new());
        let active_keys = index_keys(
            active.subject_id,
            active.device_id,
            active.lineage_id,
            &active.raw,
        );
        for (epoch, generation) in [
            (&active_keys.subject_epoch, 3),
            (&active_keys.device_epoch, 4),
            (&active_keys.lineage_epoch, 5),
        ] {
            redis::cmd("SET")
                .arg(epoch)
                .arg(generation)
                .arg("EX")
                .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
                .query_async::<String>(&mut connection)
                .await?;
        }
        save_provider(&mut connection, &active.raw).await?;
        assert_eq!(
            register_member(
                &mut connection,
                &active,
                Generations {
                    subject: 3,
                    device: 4,
                    lineage: 5,
                },
            )
            .await?,
            1
        );
        for epoch in [
            &active_keys.subject_epoch,
            &active_keys.device_epoch,
            &active_keys.lineage_epoch,
        ] {
            assert_eq!(
                redis::cmd("TTL")
                    .arg(epoch)
                    .query_async::<i64>(&mut connection)
                    .await?,
                -1
            );
        }
        assert!(revoke_subject(&mut connection, active.subject_id).await? > 0);
        assert_short_tombstone(&mut connection, &active_keys.subject_epoch).await?;
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(&active_keys.device_epoch)
                .arg(&active_keys.lineage_epoch)
                .query_async::<i64>(&mut connection)
                .await?,
            0
        );

        fixture.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn arbitrary_device_tombstones_stop_at_capacity_and_cleanup_after_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = RedisFixture::start().await?;
        let client = redis::Client::open(fixture.redis_url().expose_secret())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let subject_id = SubjectId::new();
        let devices = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
        for device_id in &devices[..2] {
            assert_eq!(
                revoke_device_with_capacity(&mut connection, subject_id, *device_id, 2).await?,
                0
            );
        }
        assert_eq!(
            revoke_device_with_capacity(&mut connection, subject_id, devices[2], 2).await?,
            -3
        );
        assert_eq!(
            redis::cmd("SCARD")
                .arg(DEVICE_CATALOG)
                .query_async::<i64>(&mut connection)
                .await?,
            2
        );

        let subject_token = subject_id.as_uuid().to_string();
        for device_id in &devices[..2] {
            let token = format!("{subject_token}:{device_id}");
            let epoch = device_epoch(subject_id, *device_id);
            let index = format!("{DEVICE_INDEX_PREFIX}{token}");
            assert_short_tombstone(&mut connection, &epoch).await?;
            redis::cmd("PEXPIREAT")
                .arg(&epoch)
                .arg(0)
                .query_async::<i64>(&mut connection)
                .await?;
            redis::cmd("EVAL")
                .arg(PRUNE_MEMBER_SCRIPT)
                .arg(3)
                .arg(&index)
                .arg(DEVICE_CATALOG)
                .arg(&epoch)
                .arg("")
                .arg(&token)
                .arg(GENERATION_TOMBSTONE_TTL_SECONDS)
                .query_async::<i64>(&mut connection)
                .await?;
        }
        assert_eq!(
            redis::cmd("SCARD")
                .arg(DEVICE_CATALOG)
                .query_async::<i64>(&mut connection)
                .await?,
            0
        );

        fixture.cleanup().await?;
        Ok(())
    }
}
