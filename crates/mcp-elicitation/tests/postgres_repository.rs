//! Isolated PostgreSQL MRTR replay-ledger contract.

use std::error::Error;

use omnius_mcp_elicitation::{
    BindingDigest, ClaimResult, DeclineBehavior, ElicitationPlan, FieldPlan, FormElicitationPlan,
    FormProtection, InputRequestKey, MrtrAuditEvent, MrtrAuditKind, MrtrMethod,
    MrtrStateRepository, PendingMrtrState, PlannedElicitation, PostgresMrtrStateRepository,
    ReplacementReason, Sensitivity, StateBinding, StateClaim, TerminalStatus, UrlElicitationPlan,
};
use omnius_test_support::PostgresFixture;
use secrecy::ExposeSecret as _;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

fn binding(label: &[u8]) -> StateBinding {
    StateBinding {
        principal_digest: BindingDigest::of(b"test/principal", label),
        tenant_digest: BindingDigest::of(b"test/tenant", label),
        method: MrtrMethod::ToolCall,
        capability_key: "tool:publish-summary".to_owned(),
        capability_revision: "revision-7".to_owned(),
        arguments_digest: BindingDigest::of(b"test/arguments", label),
        idempotency_digest: BindingDigest::of(b"test/idempotency", label),
        associated_digest: BindingDigest::of(b"test/associated", label),
    }
}

fn plan(max_rounds: u16) -> Result<ElicitationPlan, Box<dyn Error>> {
    let field = FieldPlan::try_new("note", "/note", Sensitivity::Personal)?;
    let form = FormElicitationPlan::try_new(
        "Provide the publication note",
        json!({
            "type": "object",
            "required": ["note"],
            "properties": {"note": {"type": "string", "maxLength": 100}}
        }),
        vec![field],
        FormProtection::StrongConfirmation,
    )?;
    let url = UrlElicitationPlan::try_new(
        "Complete authorization in the trusted provider",
        "https://auth.example.test/elicitation/provider",
        "provider-auth-7",
        Sensitivity::Credential,
    )?;
    Ok(ElicitationPlan::try_new(
        vec![
            (
                InputRequestKey::try_new("publication_note")?,
                PlannedElicitation::Form(form),
            ),
            (
                InputRequestKey::try_new("provider_authorization")?,
                PlannedElicitation::Url(url),
            ),
        ],
        max_rounds,
        DeclineBehavior::InvokeWithoutInput,
    )?)
}

fn pending(
    state_id: Uuid,
    binding: StateBinding,
    plan: ElicitationPlan,
    round: u16,
    max_rounds: u16,
    now: OffsetDateTime,
) -> PendingMrtrState {
    PendingMrtrState {
        state_id,
        binding,
        plan,
        continuation: None,
        round,
        max_rounds,
        issued_at: now,
        expires_at: now + time::Duration::minutes(5),
    }
}

fn event(
    state_id: Uuid,
    binding: &StateBinding,
    kind: MrtrAuditKind,
    round: Option<u16>,
) -> MrtrAuditEvent {
    MrtrAuditEvent {
        state_id: Some(state_id),
        kind,
        method: Some(binding.method),
        capability_key: Some(binding.capability_key.clone()),
        capability_revision: Some(binding.capability_revision.clone()),
        arguments_digest: Some(binding.arguments_digest),
        round,
        sensitivity: Some(Sensitivity::Credential),
    }
}

fn untrusted_event() -> MrtrAuditEvent {
    MrtrAuditEvent {
        state_id: None,
        kind: MrtrAuditKind::StateRejected,
        method: None,
        capability_key: None,
        capability_revision: None,
        arguments_digest: None,
        round: None,
        sensitivity: None,
    }
}

fn is_claimed(result: &ClaimResult) -> bool {
    matches!(result, ClaimResult::Claimed(_))
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolated transaction contract keeps a single migrated database lifecycle"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_repository_preserves_atomic_replay_and_redacted_audit_contract()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(fixture.database_url().expose_secret())
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    let now = OffsetDateTime::now_utc() + time::Duration::minutes(5);
    let original_binding = binding(b"restart-visible");
    let original = pending(
        Uuid::now_v7(),
        original_binding.clone(),
        plan(10)?,
        1,
        10,
        now,
    );
    let repository = PostgresMrtrStateRepository::new(pool.clone());
    let original = repository
        .create_pending(
            &original,
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::Issued,
                Some(1),
            ),
        )
        .await?;
    assert!(original.issued_at < now);
    assert_eq!(
        original.expires_at - original.issued_at,
        time::Duration::minutes(5)
    );

    let duplicate = repository
        .create_pending(
            &original,
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::Issued,
                Some(1),
            ),
        )
        .await;
    assert!(duplicate.is_err());
    let issued_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_mrtr_audit_events \
         WHERE state_id = $1 AND kind = 'issued'",
    )
    .bind(original.state_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(issued_count, 1);

    drop(repository);
    let restarted = PostgresMrtrStateRepository::new(pool.clone());
    let claim = StateClaim {
        state_id: original.state_id,
        expected_binding: original.binding.clone(),
        now: OffsetDateTime::now_utc(),
    };
    let claimed = restarted
        .claim_pending(
            claim.clone(),
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::Claimed,
                None,
            ),
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::StateRejected,
                None,
            ),
        )
        .await?;
    match claimed {
        ClaimResult::Claimed(restored) => assert_eq!(*restored, original),
        ClaimResult::Rejected => panic!("restart-visible state should be claimed"),
    }

    let replay = restarted
        .claim_pending(
            claim,
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::Claimed,
                None,
            ),
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::StateRejected,
                None,
            ),
        )
        .await?;
    assert_eq!(replay, ClaimResult::Rejected);

    let fresh = pending(
        Uuid::now_v7(),
        original.binding.clone(),
        plan(2)?,
        2,
        2,
        OffsetDateTime::now_utc(),
    );
    let fresh = restarted
        .replace_claimed(
            original.state_id,
            &fresh,
            ReplacementReason::InvalidResponse,
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::ResponseRejected,
                Some(1),
            ),
        )
        .await?;

    let failed_finish = restarted
        .finish_claimed(
            original.state_id,
            TerminalStatus::Completed,
            event(
                original.state_id,
                &original.binding,
                MrtrAuditKind::Completed,
                Some(1),
            ),
        )
        .await;
    assert!(failed_finish.is_err());
    let old_status: String =
        sqlx::query_scalar("SELECT status FROM public.mcp_mrtr_states WHERE state_id = $1")
            .bind(original.state_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(old_status, "replaced_invalid_response");
    let impossible_finish_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_mrtr_audit_events \
         WHERE state_id = $1 AND kind = 'completed'",
    )
    .bind(original.state_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(impossible_finish_audits, 0);

    let fresh_claim = restarted
        .claim_pending(
            StateClaim {
                state_id: fresh.state_id,
                expected_binding: fresh.binding.clone(),
                now: OffsetDateTime::now_utc(),
            },
            event(fresh.state_id, &fresh.binding, MrtrAuditKind::Claimed, None),
            event(
                fresh.state_id,
                &fresh.binding,
                MrtrAuditKind::StateRejected,
                None,
            ),
        )
        .await?;
    match fresh_claim {
        ClaimResult::Claimed(restored) => assert_eq!(*restored, fresh),
        ClaimResult::Rejected => panic!("replacement state should be claimable"),
    }
    restarted
        .record_claimed(
            fresh.state_id,
            event(
                fresh.state_id,
                &fresh.binding,
                MrtrAuditKind::Accepted,
                Some(2),
            ),
        )
        .await?;
    restarted
        .finish_claimed(
            fresh.state_id,
            TerminalStatus::Completed,
            event(
                fresh.state_id,
                &fresh.binding,
                MrtrAuditKind::Completed,
                Some(2),
            ),
        )
        .await?;
    assert!(
        restarted
            .record_claimed(
                fresh.state_id,
                event(
                    fresh.state_id,
                    &fresh.binding,
                    MrtrAuditKind::Accepted,
                    Some(2),
                ),
            )
            .await
            .is_err()
    );

    let concurrent_binding = binding(b"concurrent-cas");
    let concurrent = pending(
        Uuid::now_v7(),
        concurrent_binding,
        plan(10)?,
        1,
        3,
        OffsetDateTime::now_utc(),
    );
    restarted
        .create_pending(
            &concurrent,
            event(
                concurrent.state_id,
                &concurrent.binding,
                MrtrAuditKind::Issued,
                Some(1),
            ),
        )
        .await?;
    let left_repository = restarted.clone();
    let right_repository = restarted.clone();
    let left_claim = StateClaim {
        state_id: concurrent.state_id,
        expected_binding: concurrent.binding.clone(),
        now: OffsetDateTime::now_utc(),
    };
    let right_claim = left_claim.clone();
    let left_claimed = event(
        concurrent.state_id,
        &concurrent.binding,
        MrtrAuditKind::Claimed,
        None,
    );
    let right_claimed = left_claimed.clone();
    let left_rejected = event(
        concurrent.state_id,
        &concurrent.binding,
        MrtrAuditKind::StateRejected,
        None,
    );
    let right_rejected = left_rejected.clone();
    let (left, right) = tokio::join!(
        left_repository.claim_pending(left_claim, left_claimed, left_rejected),
        right_repository.claim_pending(right_claim, right_claimed, right_rejected),
    );
    let left = left?;
    let right = right?;
    assert_ne!(is_claimed(&left), is_claimed(&right));
    let concurrent_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_mrtr_audit_events \
         WHERE state_id = $1 AND kind IN ('claimed', 'state_rejected')",
    )
    .bind(concurrent.state_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(concurrent_audits, 2);

    restarted
        .record_untrusted_rejection(untrusted_event())
        .await?;
    let untrusted_is_redacted: bool = sqlx::query_scalar(
        "SELECT state_id IS NULL AND method IS NULL AND capability_key IS NULL \
                AND capability_revision IS NULL AND arguments_digest IS NULL \
                AND round IS NULL AND sensitivity IS NULL \
         FROM public.mcp_mrtr_audit_events \
         WHERE kind = 'state_rejected' AND state_id IS NULL \
         ORDER BY audit_id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    assert!(untrusted_is_redacted);

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND table_name IN ('mcp_mrtr_states', 'mcp_mrtr_audit_events')",
    )
    .fetch_all(&pool)
    .await?;
    assert!(!columns.iter().any(|column| {
        let column = column.to_ascii_lowercase();
        column.contains("token")
            || column.contains("response")
            || column.contains("original_arguments")
            || column.contains("input_payload")
    }));

    pool.close().await;
    Ok(())
}
