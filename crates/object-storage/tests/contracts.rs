//! Shared memory, local filesystem, and provider-independent object storage contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::PathBuf,
    time::Duration,
};

use bytes::Bytes;
use futures::{TryStreamExt as _, stream};
use omnius_auth_core::TenantId;
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_object_storage::{
    AttributePersistence, BeginMultipartRequest, BlobStore, BlobStoreError, ByteRange, ByteStream,
    GetCondition, GetRequest, ListRequest, ObjectKey, ObjectStorageConfig, ObjectStorageLimits,
    OperationContext, PresignMethod, PresignRequest, PresignedUrl, ProviderConfig,
    ProviderLifecycle, PutRequest, TransferRequest, WriteCondition,
};
use omnius_outbound_http::{OutboundUrlPolicy, OutboundUrlPolicyConfig};
use omnius_test_support::MinioFixture;
use proptest::prelude::*;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const MIB: usize = 1024 * 1024;
type TestResult = Result<(), Box<dyn Error>>;

fn outbound_policy() -> Result<OutboundUrlPolicy, omnius_outbound_http::ConfigError> {
    OutboundUrlPolicy::new(OutboundUrlPolicyConfig {
        allow_development_loopback_http: true,
        ..OutboundUrlPolicyConfig::default()
    })
}

#[tokio::test]
async fn memory_provider_satisfies_shared_streaming_contract() -> TestResult {
    let policy = outbound_policy()?;
    let store = BlobStore::build(
        ObjectStorageConfig {
            provider: ProviderConfig::Memory,
            limits: test_limits(),
        },
        DeploymentEnvironment::Test,
        &policy,
    )
    .await?;
    shared_contract(store).await
}

#[tokio::test]
async fn local_provider_satisfies_shared_streaming_contract() -> TestResult {
    let policy = outbound_policy()?;
    let root = local_root();
    fs::create_dir_all(&root)?;
    let store = BlobStore::build(
        ObjectStorageConfig {
            provider: ProviderConfig::Local { root: root.clone() },
            limits: test_limits(),
        },
        DeploymentEnvironment::Test,
        &policy,
    )
    .await?;
    let result = shared_contract(store).await;
    fs::remove_dir_all(root)?;
    result
}

#[tokio::test]
async fn minio_provider_satisfies_shared_streaming_and_presign_contract() -> TestResult {
    let policy = outbound_policy()?;
    let fixture = MinioFixture::start().await?;
    let endpoint = Url::parse(fixture.endpoint())?;
    let store = BlobStore::build(
        ObjectStorageConfig {
            provider: ProviderConfig::S3Compatible {
                endpoint,
                region: "us-east-1".to_owned(),
                bucket: fixture.bucket().to_owned(),
                access_key_id: SecretString::from(fixture.access_key().to_owned()),
                secret_access_key: SecretString::from(
                    fixture.secret_key().expose_secret().to_owned(),
                ),
                session_token: None,
                allow_http: true,
            },
            limits: test_limits(),
        },
        DeploymentEnvironment::Test,
        &policy,
    )
    .await?;
    let result = shared_contract(store).await;
    fixture.cleanup().await?;
    result
}

#[allow(clippy::too_many_lines)]
async fn shared_contract(store: BlobStore) -> TestResult {
    let context = OperationContext::uncancelled();
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();

    let large_key = ObjectKey::new();
    let large = Bytes::from(vec![0x5a; 8 * MIB + 4_097]);
    let large_sha = sha256(&large);
    let put = store
        .put_stream(
            &context,
            PutRequest {
                tenant_id: tenant,
                key: large_key.clone(),
                declared_length: byte_len(&large),
                expected_sha256: large_sha,
                content_type: Some("application/octet-stream".to_owned()),
                metadata: BTreeMap::from([("purpose".to_owned(), "contract".to_owned())]),
                condition: WriteCondition::Overwrite,
                stream: chunked(large.clone(), MIB),
            },
        )
        .await?;
    assert_eq!(put.sha256, large_sha);

    let downloaded = store
        .get_stream(
            &context,
            GetRequest {
                tenant_id: tenant,
                key: large_key.clone(),
                range: None,
                condition: GetCondition::default(),
                expected_sha256: Some(large_sha),
            },
        )
        .await?;
    let (downloaded_bytes, downloaded_sha) = downloaded
        .stream
        .try_fold(
            (0_u64, Sha256::new()),
            |(size, mut hasher), bytes| async move {
                hasher.update(&bytes);
                Ok((size + byte_len(&bytes), hasher))
            },
        )
        .await?;
    assert_eq!(
        (
            downloaded_bytes,
            <[u8; 32]>::from(downloaded_sha.finalize())
        ),
        (byte_len(&large), large_sha)
    );

    let range = store
        .get_stream(
            &context,
            GetRequest {
                tenant_id: tenant,
                key: large_key.clone(),
                range: Some(ByteRange::new(17, 113)?),
                condition: GetCondition::default(),
                expected_sha256: None,
            },
        )
        .await?
        .stream
        .try_fold(Vec::new(), |mut collected, bytes| async move {
            collected.extend_from_slice(&bytes);
            Ok(collected)
        })
        .await?;
    assert_eq!(range, vec![0x5a; 96]);

    let head = store.head(&context, tenant, &large_key).await?;
    assert_eq!(head.size, byte_len(&large));
    match put.attributes {
        AttributePersistence::Native => {
            assert_eq!(
                head.attributes.content_type.as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(
                head.attributes.metadata.get("purpose").map(String::as_str),
                Some("contract")
            );
        }
        AttributePersistence::Unsupported => {
            assert!(head.attributes.content_type.is_none() && head.attributes.metadata.is_empty());
        }
        other => panic!("unexpected attribute persistence result: {other:?}"),
    }

    assert_eq!(
        store.head(&context, other_tenant, &large_key).await,
        Err(BlobStoreError::NotFound)
    );

    let conditional_key = ObjectKey::new();
    let first = Bytes::from_static(b"first-object");
    let first_put = put_bytes(
        &store,
        &context,
        tenant,
        conditional_key.clone(),
        first.clone(),
        WriteCondition::Create,
    )
    .await?;
    assert_eq!(
        put_bytes(
            &store,
            &context,
            tenant,
            conditional_key.clone(),
            first.clone(),
            WriteCondition::Create,
        )
        .await,
        Err(BlobStoreError::AlreadyExists)
    );
    if store.status().capabilities.conditional_update {
        let updated = Bytes::from_static(b"updated-object");
        put_bytes(
            &store,
            &context,
            tenant,
            conditional_key.clone(),
            updated,
            WriteCondition::Update {
                e_tag: first_put.version.e_tag,
                version: first_put.version.version,
            },
        )
        .await?;
    }

    let copy_key = ObjectKey::new();
    let conditional_copy = store.status().capabilities.conditional_copy;
    if !conditional_copy {
        assert_eq!(
            store
                .copy(
                    &context,
                    TransferRequest {
                        tenant_id: tenant,
                        source: conditional_key.clone(),
                        destination: copy_key.clone(),
                        create_only: true,
                    },
                )
                .await,
            Err(BlobStoreError::Unsupported)
        );
    }
    store
        .copy(
            &context,
            TransferRequest {
                tenant_id: tenant,
                source: conditional_key.clone(),
                destination: copy_key.clone(),
                create_only: conditional_copy,
            },
        )
        .await?;
    if conditional_copy {
        assert!(matches!(
            store
                .copy(
                    &context,
                    TransferRequest {
                        tenant_id: tenant,
                        source: conditional_key.clone(),
                        destination: copy_key.clone(),
                        create_only: true,
                    },
                )
                .await,
            Err(BlobStoreError::AlreadyExists | BlobStoreError::Precondition)
        ));
    }

    let moved_key = ObjectKey::new();
    store
        .move_object(
            &context,
            TransferRequest {
                tenant_id: tenant,
                source: copy_key.clone(),
                destination: moved_key.clone(),
                create_only: conditional_copy,
            },
        )
        .await?;
    assert_eq!(
        store.head(&context, tenant, &copy_key).await,
        Err(BlobStoreError::NotFound)
    );

    let expected_keys = BTreeSet::from([
        large_key.clone(),
        conditional_key.clone(),
        moved_key.clone(),
    ]);
    let mut listed_keys = BTreeSet::new();
    let mut cursor = None;
    let mut pagination_terminated = false;
    for page_number in 0..=expected_keys.len() {
        let page = store
            .list(
                &context,
                ListRequest {
                    tenant_id: tenant,
                    limit: 1,
                    cursor,
                },
            )
            .await?;
        for item in page.items {
            assert!(
                listed_keys.insert(item.key),
                "cursor pagination returned a duplicate key"
            );
        }
        let Some(next_cursor) = page.next_cursor else {
            pagination_terminated = true;
            break;
        };
        assert!(
            page_number < expected_keys.len(),
            "cursor pagination did not terminate"
        );
        cursor = Some(next_cursor);
    }
    assert!(pagination_terminated, "cursor pagination did not terminate");
    assert_eq!(listed_keys, expected_keys);
    assert!(
        store
            .list(
                &context,
                ListRequest {
                    tenant_id: other_tenant,
                    limit: 10,
                    cursor: None,
                },
            )
            .await?
            .items
            .is_empty()
    );

    let fragmented_key = ObjectKey::new();
    let fragmented_bytes = Bytes::from(vec![0x3c; 16 * 1024]);
    let fragmented_put = store
        .put_stream(
            &context,
            PutRequest {
                tenant_id: tenant,
                key: fragmented_key,
                declared_length: byte_len(&fragmented_bytes),
                expected_sha256: sha256(&fragmented_bytes),
                content_type: None,
                metadata: BTreeMap::new(),
                condition: WriteCondition::Overwrite,
                stream: chunked(fragmented_bytes.clone(), 1),
            },
        )
        .await?;
    assert_eq!(fragmented_put.sha256, sha256(&fragmented_bytes));

    let explicit_key = ObjectKey::new();
    let explicit_bytes = Bytes::from_static(b"explicit-multipart");
    let explicit_sha = sha256(&explicit_bytes);
    let upload = store
        .begin_multipart(
            &context,
            BeginMultipartRequest {
                tenant_id: tenant,
                key: explicit_key.clone(),
                declared_length: byte_len(&explicit_bytes),
                expected_sha256: explicit_sha,
                content_type: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
    upload
        .upload_part(&context, 1, explicit_bytes.clone(), true)
        .await?;
    upload.complete(&context).await?;
    let (explicit_downloaded, explicit_downloaded_sha) = store
        .get_stream(
            &context,
            GetRequest {
                tenant_id: tenant,
                key: explicit_key.clone(),
                range: None,
                condition: GetCondition::default(),
                expected_sha256: Some(explicit_sha),
            },
        )
        .await?
        .stream
        .try_fold(
            (Vec::new(), Sha256::new()),
            |(mut collected, mut hasher), bytes| async move {
                collected.extend_from_slice(&bytes);
                hasher.update(&bytes);
                Ok((collected, hasher))
            },
        )
        .await?;
    assert_eq!(
        (
            Bytes::from(explicit_downloaded),
            <[u8; 32]>::from(explicit_downloaded_sha.finalize())
        ),
        (explicit_bytes.clone(), explicit_sha)
    );

    let aborted = store
        .begin_multipart(
            &context,
            BeginMultipartRequest {
                tenant_id: tenant,
                key: ObjectKey::new(),
                declared_length: 1,
                expected_sha256: sha256(&Bytes::from_static(b"x")),
                content_type: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
    aborted.abort().await?;

    let bad_size = Bytes::from_static(b"short");
    assert_eq!(
        store
            .put_stream(
                &context,
                PutRequest {
                    tenant_id: tenant,
                    key: ObjectKey::new(),
                    declared_length: byte_len(&bad_size) + 1,
                    expected_sha256: sha256(&bad_size),
                    content_type: None,
                    metadata: BTreeMap::new(),
                    condition: WriteCondition::Overwrite,
                    stream: one_chunk(bad_size),
                },
            )
            .await,
        Err(BlobStoreError::Size)
    );
    assert_eq!(
        store
            .put_stream(
                &context,
                PutRequest {
                    tenant_id: tenant,
                    key: ObjectKey::new(),
                    declared_length: 1,
                    expected_sha256: [0; 32],
                    content_type: None,
                    metadata: BTreeMap::new(),
                    condition: WriteCondition::Overwrite,
                    stream: one_chunk(Bytes::from_static(b"x")),
                },
            )
            .await,
        Err(BlobStoreError::Checksum)
    );

    let oversized_metadata = "x".repeat(1_025);
    assert_eq!(
        store
            .put_stream(
                &context,
                PutRequest {
                    tenant_id: tenant,
                    key: ObjectKey::new(),
                    declared_length: 1,
                    expected_sha256: sha256(&Bytes::from_static(b"x")),
                    content_type: None,
                    metadata: BTreeMap::from([("field".to_owned(), oversized_metadata)]),
                    condition: WriteCondition::Overwrite,
                    stream: one_chunk(Bytes::from_static(b"x")),
                },
            )
            .await,
        Err(BlobStoreError::Metadata)
    );

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        store
            .head(&OperationContext::new(cancelled), tenant, &large_key)
            .await,
        Err(BlobStoreError::Cancelled)
    );

    assert_eq!(
        store
            .put_stream(
                &context,
                PutRequest {
                    tenant_id: tenant,
                    key: ObjectKey::new(),
                    declared_length: 1,
                    expected_sha256: sha256(&Bytes::from_static(b"x")),
                    content_type: None,
                    metadata: BTreeMap::new(),
                    condition: WriteCondition::Overwrite,
                    stream: Box::pin(stream::pending()),
                },
            )
            .await,
        Err(BlobStoreError::Timeout)
    );

    let presigned_key = ObjectKey::new();
    let signed_bytes = Bytes::from_static(b"signed-roundtrip");
    let signed_sha = sha256(&signed_bytes);
    assert_eq!(
        store
            .presign(
                &context,
                PresignRequest {
                    tenant_id: tenant,
                    key: presigned_key.clone(),
                    method: PresignMethod::Get,
                    expires_in: Duration::from_millis(999),
                },
            )
            .await,
        Err(BlobStoreError::Invalid)
    );
    assert_eq!(
        store
            .presign(
                &context,
                PresignRequest {
                    tenant_id: tenant,
                    key: presigned_key.clone(),
                    method: PresignMethod::Put {
                        declared_length: byte_len(&signed_bytes),
                        expected_sha256: signed_sha,
                    },
                    expires_in: Duration::from_millis(999),
                },
            )
            .await,
        Err(BlobStoreError::Invalid)
    );
    assert_eq!(
        store
            .presign(
                &context,
                PresignRequest {
                    tenant_id: tenant,
                    key: presigned_key.clone(),
                    method: PresignMethod::Get,
                    expires_in: Duration::from_millis(1_500),
                },
            )
            .await,
        Err(BlobStoreError::Invalid)
    );
    let one_second_presign = store
        .presign(
            &context,
            PresignRequest {
                tenant_id: tenant,
                key: presigned_key.clone(),
                method: PresignMethod::Get,
                expires_in: Duration::from_secs(1),
            },
        )
        .await;
    if store.status().capabilities.presigned_get {
        assert!(one_second_presign.is_ok());
    } else {
        assert_eq!(one_second_presign, Err(BlobStoreError::Unsupported));
    }

    let client = reqwest::Client::new();
    if store.status().capabilities.presigned_put {
        let put_form = store
            .presign(
                &context,
                PresignRequest {
                    tenant_id: tenant,
                    key: presigned_key.clone(),
                    method: PresignMethod::Put {
                        declared_length: byte_len(&signed_bytes),
                        expected_sha256: signed_sha,
                    },
                    expires_in: Duration::from_secs(30),
                },
            )
            .await?;
        let response = submit_presigned_post(&client, &put_form, signed_bytes.clone()).await?;
        assert!(response.status().is_success());

        let wrong_checksum =
            submit_presigned_post(&client, &put_form, Bytes::from_static(b"tigned-roundtrip"))
                .await?;
        assert!(
            !wrong_checksum.status().is_success(),
            "provider accepted bytes that violated the signed SHA-256 condition"
        );
        let wrong_size =
            submit_presigned_post(&client, &put_form, Bytes::from_static(b"signed-roundtrip!"))
                .await?;
        assert!(
            !wrong_size.status().is_success(),
            "provider accepted bytes that violated the signed length condition"
        );
    } else {
        assert_eq!(
            store
                .presign(
                    &context,
                    PresignRequest {
                        tenant_id: tenant,
                        key: presigned_key.clone(),
                        method: PresignMethod::Put {
                            declared_length: byte_len(&signed_bytes),
                            expected_sha256: signed_sha,
                        },
                        expires_in: Duration::from_secs(30),
                    },
                )
                .await,
            Err(BlobStoreError::Unsupported)
        );
        if store.status().capabilities.presigned_get {
            put_bytes(
                &store,
                &context,
                tenant,
                presigned_key.clone(),
                signed_bytes.clone(),
                WriteCondition::Overwrite,
            )
            .await?;
        }
    }

    if store.status().capabilities.presigned_get {
        let get_url = store
            .presign(
                &context,
                PresignRequest {
                    tenant_id: tenant,
                    key: presigned_key,
                    method: PresignMethod::Get,
                    expires_in: Duration::from_secs(30),
                },
            )
            .await?;
        let response = client.get(get_url.expose().clone()).send().await?;
        assert_eq!(response.bytes().await?, signed_bytes);
    } else {
        assert_eq!(
            store
                .presign(
                    &context,
                    PresignRequest {
                        tenant_id: tenant,
                        key: presigned_key,
                        method: PresignMethod::Get,
                        expires_in: Duration::from_secs(30),
                    },
                )
                .await,
            Err(BlobStoreError::Unsupported)
        );
    }

    store.delete(&context, tenant, &moved_key).await?;
    store.delete(&context, tenant, &moved_key).await?;
    let admitted_download = store
        .get_stream(
            &context,
            GetRequest {
                tenant_id: tenant,
                key: explicit_key,
                range: None,
                condition: GetCondition::default(),
                expected_sha256: Some(explicit_sha),
            },
        )
        .await?;
    store.begin_drain();
    let admitted_bytes = admitted_download
        .stream
        .try_fold(
            0_u64,
            |size, bytes| async move { Ok(size + byte_len(&bytes)) },
        )
        .await?;
    assert_eq!(
        (admitted_bytes, store.status().lifecycle),
        (byte_len(&explicit_bytes), ProviderLifecycle::Draining)
    );
    assert_eq!(
        store.head(&context, tenant, &large_key).await,
        Err(BlobStoreError::Shutdown)
    );
    store.shutdown();
    store.begin_drain();
    assert_eq!(store.status().lifecycle, ProviderLifecycle::Shutdown);
    Ok(())
}

async fn submit_presigned_post(
    client: &reqwest::Client,
    signed: &PresignedUrl,
    bytes: Bytes,
) -> Result<reqwest::Response, reqwest::Error> {
    let boundary = format!("omnius-upload-{}", Uuid::now_v7());
    let mut body = Vec::new();
    for (name, value) in signed.expose_form_fields() {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    client
        .post(signed.expose().clone())
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
}

async fn put_bytes(
    store: &BlobStore,
    context: &OperationContext,
    tenant_id: TenantId,
    key: ObjectKey,
    bytes: Bytes,
    condition: WriteCondition,
) -> Result<omnius_object_storage::PutObjectResult, BlobStoreError> {
    store
        .put_stream(
            context,
            PutRequest {
                tenant_id,
                key,
                declared_length: byte_len(&bytes),
                expected_sha256: sha256(&bytes),
                content_type: None,
                metadata: BTreeMap::new(),
                condition,
                stream: one_chunk(bytes),
            },
        )
        .await
}

fn byte_len(bytes: &Bytes) -> u64 {
    let Ok(length) = u64::try_from(bytes.len()) else {
        panic!("test payload length must fit in u64");
    };
    length
}

fn one_chunk(bytes: Bytes) -> ByteStream {
    Box::pin(stream::once(async move { Ok(bytes) }))
}

fn chunked(bytes: Bytes, chunk_size: usize) -> ByteStream {
    let len = bytes.len();
    Box::pin(stream::iter((0..len).step_by(chunk_size).map(
        move |start| {
            let end = (start + chunk_size).min(len);
            Ok(bytes.slice(start..end))
        },
    )))
}

fn sha256(bytes: &Bytes) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn test_limits() -> ObjectStorageLimits {
    ObjectStorageLimits {
        operation_timeout: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(1),
        max_signed_url_expiry: Duration::from_secs(60),
        retry_timeout: Duration::from_secs(1),
        ..ObjectStorageLimits::default()
    }
}

fn local_root() -> PathBuf {
    std::env::temp_dir().join(format!("omnius-object-storage-{}", Uuid::now_v7()))
}

#[test]
fn public_diagnostics_redact_keys_endpoints_and_secrets() -> TestResult {
    let secret = "do-not-print-secret";
    let endpoint = "http://127.0.0.1:9000/";
    let config = ObjectStorageConfig {
        provider: ProviderConfig::S3Compatible {
            endpoint: Url::parse(endpoint)?,
            region: "us-east-1".to_owned(),
            bucket: "private-bucket".to_owned(),
            access_key_id: SecretString::from("private-access-key".to_owned()),
            secret_access_key: SecretString::from(secret.to_owned()),
            session_token: None,
            allow_http: true,
        },
        limits: test_limits(),
    };
    let diagnostic = format!("{config:?} {:?}", ObjectKey::new());
    assert!(
        !diagnostic.contains(secret)
            && !diagnostic.contains(endpoint)
            && !diagnostic.contains("private-bucket")
    );
    Ok(())
}

#[test]
fn production_rejects_memory_local_and_http_cloud() -> TestResult {
    let memory = ObjectStorageConfig {
        provider: ProviderConfig::Memory,
        limits: test_limits(),
    };
    assert_eq!(
        memory.validate(DeploymentEnvironment::Production),
        Err(BlobStoreError::Config)
    );

    let root = std::env::temp_dir();
    let local = ObjectStorageConfig {
        provider: ProviderConfig::Local { root },
        limits: test_limits(),
    };
    assert_eq!(
        local.validate(DeploymentEnvironment::Production),
        Err(BlobStoreError::Config)
    );

    let cloud = ObjectStorageConfig {
        provider: ProviderConfig::S3Compatible {
            endpoint: Url::parse("http://127.0.0.1:9000/")?,
            region: "us-east-1".to_owned(),
            bucket: "private-bucket".to_owned(),
            access_key_id: SecretString::from("access-key".to_owned()),
            secret_access_key: SecretString::from("secret-key".to_owned()),
            session_token: None,
            allow_http: true,
        },
        limits: test_limits(),
    };
    assert_eq!(
        cloud.validate(DeploymentEnvironment::Production),
        Err(BlobStoreError::Config)
    );
    Ok(())
}

#[tokio::test]
async fn provider_build_rejects_special_use_endpoint_before_sdk_construction() -> TestResult {
    let policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig::default())?;
    let config = ObjectStorageConfig {
        provider: ProviderConfig::S3Compatible {
            endpoint: Url::parse("https://169.254.169.254/")?,
            region: "us-east-1".to_owned(),
            bucket: "private-bucket".to_owned(),
            access_key_id: SecretString::from("access-key".to_owned()),
            secret_access_key: SecretString::from("secret-key".to_owned()),
            session_token: None,
            allow_http: false,
        },
        limits: test_limits(),
    };

    let Err(error) = BlobStore::build(config, DeploymentEnvironment::Production, &policy).await
    else {
        return Err("special-use endpoint was accepted".into());
    };
    assert_eq!(error, BlobStoreError::Config);
    Ok(())
}

#[test]
fn keys_and_endpoints_reject_escape_and_credential_routing_inputs() -> TestResult {
    for value in [
        "",
        ".",
        "..",
        "01900000-0000-7000-8000-000000000000/child",
        "01900000-0000-7000-8000-000000000000\\child",
        "01900000-0000-7000-8000-000000000000\n",
        "01900000-0000-4000-8000-000000000000",
    ] {
        assert_eq!(ObjectKey::parse(value), Err(BlobStoreError::Invalid));
    }
    assert_eq!(ByteRange::new(9, 9), Err(BlobStoreError::Invalid));

    for endpoint in [
        "https://user:password@example.com/",
        "https://example.com/path",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "http://example.com/",
    ] {
        let config = ObjectStorageConfig {
            provider: ProviderConfig::S3Compatible {
                endpoint: Url::parse(endpoint)?,
                region: "us-east-1".to_owned(),
                bucket: "private-bucket".to_owned(),
                access_key_id: SecretString::from("access-key".to_owned()),
                secret_access_key: SecretString::from("secret-key".to_owned()),
                session_token: None,
                allow_http: endpoint.starts_with("http://"),
            },
            limits: test_limits(),
        };
        assert_eq!(
            config.validate(DeploymentEnvironment::Test),
            Err(BlobStoreError::Config)
        );
    }
    Ok(())
}

#[test]
fn gcs_service_account_json_must_parse() {
    let config = ObjectStorageConfig {
        provider: ProviderConfig::Gcs {
            bucket: "private-bucket".to_owned(),
            service_account_json: SecretString::from("not-json".to_owned()),
            endpoint: None,
            allow_http: false,
        },
        limits: test_limits(),
    };
    assert_eq!(
        config.validate(DeploymentEnvironment::Test),
        Err(BlobStoreError::Config)
    );
}

#[test]
fn gcs_service_account_json_rejects_hidden_builder_overrides() {
    for credentials in [
        r#"{"private_key":"key","private_key_id":"id","client_email":"service@example.com","gcs_base_url":"https://example.com"}"#,
        r#"{"private_key":"key","private_key_id":"id","client_email":"service@example.com","disable_oauth":true}"#,
    ] {
        let config = ObjectStorageConfig {
            provider: ProviderConfig::Gcs {
                bucket: "private-bucket".to_owned(),
                service_account_json: SecretString::from(credentials.to_owned()),
                endpoint: None,
                allow_http: false,
            },
            limits: test_limits(),
        };
        assert_eq!(
            config.validate(DeploymentEnvironment::Test),
            Err(BlobStoreError::Config)
        );
    }
}

#[test]
fn strict_tagged_config_rejects_unknown_fields() {
    let parsed =
        serde_json::from_str::<ObjectStorageConfig>(r#"{"provider":"memory","unexpected":true}"#);
    assert!(parsed.is_err());
}

proptest! {
    #[test]
    fn arbitrary_text_never_creates_path_capable_key(value in ".{0,512}") {
        if let Ok(key) = ObjectKey::parse(value) {
            prop_assert_eq!(key.as_str().len(), 36);
            prop_assert!(!key.as_str().chars().any(|character| matches!(character, '/' | '\\' | '.')));
            prop_assert!(key.as_str().bytes().all(|byte| !byte.is_ascii_control()));
        }
    }

    #[test]
    fn local_root_and_metadata_bounds_fail_closed(extra in 1_usize..4096) {
        let mut limits = test_limits();
        limits.max_metadata_value_bytes = 1024;
        let metadata = "x".repeat(1024 + extra);
        prop_assert!(metadata.len() > usize::from(limits.max_metadata_value_bytes));

        let root = PathBuf::from("x".repeat(4096 + extra));
        let config = ObjectStorageConfig {
            provider: ProviderConfig::Local { root },
            limits,
        };
        prop_assert_eq!(config.validate(DeploymentEnvironment::Test), Err(BlobStoreError::Config));
    }
}
