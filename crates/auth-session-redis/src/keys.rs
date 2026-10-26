//! Redis key schema for the session lifecycle indexes.

use omnius_auth_core::SubjectId;
use uuid::Uuid;

pub(crate) const LIFECYCLE_KEY: &str = "__omnius_session_lifecycle_v1";
pub(crate) const GLOBAL_INDEX: &str = "__omnius:lifecycle:v1:sessions";
pub(crate) const SUBJECT_CATALOG: &str = "__omnius:lifecycle:v1:subjects";
pub(crate) const DEVICE_CATALOG: &str = "__omnius:lifecycle:v1:devices";
pub(crate) const LINEAGE_CATALOG: &str = "__omnius:lifecycle:v1:lineages";
pub(crate) const SUBJECT_INDEX_PREFIX: &str = "__omnius:lifecycle:v1:subject:";
pub(crate) const DEVICE_INDEX_PREFIX: &str = "__omnius:lifecycle:v1:device:";
pub(crate) const LINEAGE_INDEX_PREFIX: &str = "__omnius:lifecycle:v1:lineage:";
pub(crate) const SUBJECT_EPOCH_PREFIX: &str = "__omnius:lifecycle:v1:subject-epoch:";
pub(crate) const DEVICE_EPOCH_PREFIX: &str = "__omnius:lifecycle:v1:device-epoch:";
pub(crate) const LINEAGE_EPOCH_PREFIX: &str = "__omnius:lifecycle:v1:lineage-epoch:";

pub(crate) struct IndexKeys {
    pub(crate) subject_epoch: String,
    pub(crate) device_epoch: String,
    pub(crate) lineage_epoch: String,
    pub(crate) subject: String,
    pub(crate) device: String,
    pub(crate) lineage: String,
    pub(crate) subject_member: String,
    pub(crate) device_member: String,
    pub(crate) lineage_member: String,
    pub(crate) global_member: String,
    pub(crate) subject_token: String,
    pub(crate) device_token: String,
    pub(crate) lineage_token: String,
}

pub(crate) fn index_keys(
    subject_id: SubjectId,
    device_id: Uuid,
    lineage_id: Uuid,
    raw: &str,
) -> IndexKeys {
    let subject_token = subject_id.as_uuid().to_string();
    let device = device_id.to_string();
    let lineage = lineage_id.to_string();
    let device_token = format!("{subject_token}:{device}");
    let lineage_token = format!("{subject_token}:{lineage}");
    IndexKeys {
        subject_epoch: subject_epoch(subject_id),
        device_epoch: device_epoch(subject_id, device_id),
        lineage_epoch: lineage_epoch(subject_id, lineage_id),
        subject: format!("{SUBJECT_INDEX_PREFIX}{subject_token}"),
        device: format!("{DEVICE_INDEX_PREFIX}{device_token}"),
        lineage: format!("{LINEAGE_INDEX_PREFIX}{lineage_token}"),
        subject_member: format!("{device}:{lineage}:{raw}"),
        device_member: format!("{lineage}:{raw}"),
        lineage_member: format!("{device}:{raw}"),
        global_member: format!("{subject_token}:{device}:{lineage}:{raw}"),
        subject_token,
        device_token,
        lineage_token,
    }
}

pub(crate) fn subject_epoch(subject_id: SubjectId) -> String {
    format!("{SUBJECT_EPOCH_PREFIX}{}", subject_id.as_uuid())
}

pub(crate) fn device_epoch(subject_id: SubjectId, device_id: Uuid) -> String {
    format!("{DEVICE_EPOCH_PREFIX}{}:{device_id}", subject_id.as_uuid())
}

pub(crate) fn lineage_epoch(subject_id: SubjectId, lineage_id: Uuid) -> String {
    format!(
        "{LINEAGE_EPOCH_PREFIX}{}:{lineage_id}",
        subject_id.as_uuid()
    )
}

pub(crate) fn subject_index(subject_id: SubjectId) -> String {
    format!("{SUBJECT_INDEX_PREFIX}{}", subject_id.as_uuid())
}
