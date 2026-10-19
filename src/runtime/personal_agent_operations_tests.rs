use std::collections::BTreeMap;

use super::*;
use crate::builtins::cluster_primitives::MemoryKv;
use crate::config::personal_agent::OperationsWithoutExtension;

fn tool(name: &str) -> OperationToolConfig {
    OperationToolConfig {
        tool: name.to_owned(),
        summary: "Refund order ${arguments.order_id} of ${arguments.amount} EUR.".to_owned(),
        action_key: Some("${arguments.order_id}".to_owned()),
        url: Some("https://shop.example/orders/${arguments.order_id}".to_owned()),
        expires_after_secs: 900,
        user_approval_required: false,
    }
}

fn service_with(tools: Vec<OperationToolConfig>) -> OperationsService {
    let config = OperationsConfig {
        endpoint: "https://shop.example/poppy/operations".to_owned(),
        tools,
        without_extension: OperationsWithoutExtension::Perform,
        confirm_wait_secs: 5,
        retain_final_secs: 86_400,
    };
    OperationsService::from_config(&config, Arc::new(MemoryKv::new())).expect("service builds")
}

fn service() -> OperationsService {
    service_with(vec![tool("refund")])
}

fn agent(session: &str) -> PersonalAgentCaller {
    PersonalAgentCaller {
        client_id: Some("https://agent.example/agent.json".to_owned()),
        session_id: Some(session.to_owned()),
        user_id: Some("u_1".to_owned()),
        account: None,
        signed_in: false,
        extensions: BTreeMap::new(),
    }
}

fn signed_in(session: &str, account: &str) -> PersonalAgentCaller {
    PersonalAgentCaller {
        account: Some(account.to_owned()),
        signed_in: true,
        ..agent(session)
    }
}

fn refund(order: &str, amount: u32) -> Value {
    json!({ "order_id": order, "amount": amount })
}

#[tokio::test]
async fn a_proposal_renders_its_summary_and_url_and_keeps_the_arguments_as_terms() {
    let service = service();
    let record = service
        .propose("refund", &refund("A-1", 20), &agent("ses_1"))
        .await
        .expect("proposed");

    assert!(record.operation_id.starts_with("op_"));
    assert_eq!(record.revision, 1);
    assert_eq!(record.state, OperationState::Proposed);
    assert_eq!(record.summary, "Refund order A-1 of 20 EUR.");
    assert_eq!(record.terms, refund("A-1", 20));
    assert_eq!(
        record.url.as_deref(),
        Some("https://shop.example/orders/A-1")
    );

    let wire = record.wire();
    assert_eq!(wire["state"], "proposed");
    assert!(wire["expires_at"].is_string(), "{wire}");
    assert_eq!(wire["url"], "https://shop.example/orders/A-1");
    assert!(wire["confirmation"].is_null());
    assert!(wire["result"].is_null());
    assert!(
        wire.get("owner").is_none(),
        "the owner is not shown: {wire}"
    );
}

#[tokio::test]
async fn the_same_action_key_returns_the_operation_or_its_next_revision() {
    let service = service();
    let caller = agent("ses_1");
    let first = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();

    let again = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    assert_eq!(again.operation_id, first.operation_id);
    assert_eq!(again.revision, 1, "equal terms leave the revision");

    let revised = service
        .propose("refund", &refund("A-1", 25), &caller)
        .await
        .unwrap();
    assert_eq!(revised.operation_id, first.operation_id);
    assert_eq!(revised.revision, 2);
    assert_eq!(revised.terms, refund("A-1", 25));
    assert_eq!(revised.summary, "Refund order A-1 of 25 EUR.");

    let other = service
        .propose("refund", &refund("B-2", 20), &caller)
        .await
        .unwrap();
    assert_ne!(other.operation_id, first.operation_id);
    assert_eq!(other.revision, 1);
}

#[tokio::test]
async fn without_an_action_key_every_call_proposes_a_new_operation() {
    let service = service_with(vec![OperationToolConfig {
        action_key: None,
        ..tool("refund")
    }]);
    let caller = agent("ses_1");
    let first = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    let second = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    assert_ne!(first.operation_id, second.operation_id);
}

#[tokio::test]
async fn an_action_key_is_shared_by_one_account_and_never_across_signed_out_sessions() {
    let service = service();
    let signed_out = service
        .propose("refund", &refund("A-1", 20), &agent("ses_1"))
        .await
        .unwrap();
    let other_session = service
        .propose("refund", &refund("A-1", 20), &agent("ses_2"))
        .await
        .unwrap();
    assert_ne!(signed_out.operation_id, other_session.operation_id);

    let on_phone = service
        .propose("refund", &refund("A-1", 20), &signed_in("ses_3", "acct_9"))
        .await
        .unwrap();
    let on_laptop = service
        .propose("refund", &refund("A-1", 30), &signed_in("ses_4", "acct_9"))
        .await
        .unwrap();
    assert_eq!(on_laptop.operation_id, on_phone.operation_id);
    assert_eq!(on_laptop.revision, 2);
}

#[tokio::test]
async fn only_the_owner_can_use_an_operation() {
    let service = service();
    let signed_out = service
        .propose("refund", &refund("A-1", 20), &agent("ses_1"))
        .await
        .unwrap();
    assert!(
        service
            .read(&signed_out.operation_id, &agent("ses_1"))
            .await
            .is_ok()
    );
    for stranger in [
        agent("ses_2"),
        signed_in("ses_2", "acct_9"),
        PersonalAgentCaller {
            client_id: Some("https://other-agent.example/agent.json".to_owned()),
            ..agent("ses_1")
        },
        PersonalAgentCaller {
            client_id: None,
            ..agent("ses_1")
        },
    ] {
        assert!(
            matches!(
                service.read(&signed_out.operation_id, &stranger).await,
                Err(OperationError::NotFound)
            ),
            "{stranger:?}"
        );
        assert!(matches!(
            service.cancel(&signed_out.operation_id, &stranger).await,
            Err(OperationError::NotFound)
        ));
        assert!(matches!(
            service
                .confirm(&signed_out.operation_id, &stranger, 1, ApprovedBy::User)
                .await,
            Err(OperationError::NotFound)
        ));
    }

    let account = service
        .propose("refund", &refund("B-2", 20), &signed_in("ses_3", "acct_9"))
        .await
        .unwrap();
    assert!(
        service
            .read(&account.operation_id, &signed_in("ses_4", "acct_9"))
            .await
            .is_ok(),
        "another Session signed in to the account"
    );
    assert!(
        service
            .read(&account.operation_id, &agent("ses_3"))
            .await
            .is_ok(),
        "the proposing Session, signed out again"
    );
    for stranger in [
        agent("ses_4"),
        signed_in("ses_4", "acct_other"),
        PersonalAgentCaller {
            user_id: Some("u_2".to_owned()),
            ..signed_in("ses_4", "acct_9")
        },
    ] {
        assert!(
            matches!(
                service.read(&account.operation_id, &stranger).await,
                Err(OperationError::NotFound)
            ),
            "{stranger:?}"
        );
    }
}

#[tokio::test]
async fn a_plain_mcp_client_proposes_nothing() {
    let service = service();
    let plain = PersonalAgentCaller {
        client_id: None,
        ..agent("ses_1")
    };
    assert!(matches!(
        service.propose("refund", &refund("A-1", 20), &plain).await,
        Err(OperationError::NotFound)
    ));
    let sessionless = PersonalAgentCaller {
        session_id: None,
        ..agent("ses_1")
    };
    assert!(
        matches!(
            service
                .propose("refund", &refund("A-1", 20), &sessionless)
                .await,
            Err(OperationError::NotFound)
        ),
        "no request could use it again"
    );
    assert!(matches!(
        service
            .propose("not_listed", &refund("A-1", 20), &agent("ses_1"))
            .await,
        Err(OperationError::NotFound)
    ));
}

#[tokio::test]
async fn a_confirm_of_an_older_revision_gets_the_current_terms() {
    let service = service();
    let caller = agent("ses_1");
    let first = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    service
        .propose("refund", &refund("A-1", 25), &caller)
        .await
        .unwrap();

    match service
        .confirm(&first.operation_id, &caller, 1, ApprovedBy::User)
        .await
    {
        Err(OperationError::TermsChanged(current)) => {
            assert_eq!(current.revision, 2);
            assert_eq!(current.terms, refund("A-1", 25));
            assert_eq!(current.state, OperationState::Proposed);
        }
        other => panic!("expected terms_changed, got {other:?}"),
    }
    assert!(matches!(
        service
            .confirm(&first.operation_id, &caller, 2, ApprovedBy::User)
            .await,
        Ok(ConfirmOutcome::Run(_))
    ));
}

#[tokio::test]
async fn a_tool_that_needs_the_users_approval_refuses_a_standing_permission() {
    let service = service_with(vec![OperationToolConfig {
        user_approval_required: true,
        ..tool("refund")
    }]);
    let caller = agent("ses_1");
    let record = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    assert!(record.user_approval_required);
    assert!(matches!(
        service
            .confirm(
                &record.operation_id,
                &caller,
                1,
                ApprovedBy::StandingPermission
            )
            .await,
        Err(OperationError::UserApprovalRequired)
    ));
    assert_eq!(
        service
            .read(&record.operation_id, &caller)
            .await
            .unwrap()
            .state,
        OperationState::Proposed,
        "the refusal changes nothing"
    );
    match service
        .confirm(&record.operation_id, &caller, 1, ApprovedBy::User)
        .await
    {
        Ok(ConfirmOutcome::Run(running)) => {
            let confirmation = running.confirmation.expect("confirmation recorded");
            assert_eq!(confirmation.approved_by, ApprovedBy::User);
            assert_eq!(confirmation.revision, 1);
        }
        other => panic!("expected a run, got {other:?}"),
    }
}

#[tokio::test]
async fn a_second_confirm_finds_the_operation_and_runs_nothing() {
    let service = service();
    let caller = agent("ses_1");
    let record = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();

    let Ok(ConfirmOutcome::Run(running)) = service
        .confirm(
            &record.operation_id,
            &caller,
            1,
            ApprovedBy::StandingPermission,
        )
        .await
    else {
        panic!("the first confirm runs the action");
    };
    assert_eq!(running.state, OperationState::InProgress);
    let wire = running.wire();
    assert!(wire.get("expires_at").is_none(), "{wire}");
    assert_eq!(wire["confirmation"]["approved_by"], "standing_permission");

    match service
        .confirm(&record.operation_id, &caller, 1, ApprovedBy::User)
        .await
    {
        Ok(ConfirmOutcome::AsIs(current)) => {
            assert_eq!(current.state, OperationState::InProgress);
            assert_eq!(
                current.confirmation.map(|c| c.approved_by),
                Some(ApprovedBy::StandingPermission),
                "the first approval stands"
            );
        }
        other => panic!("expected the operation as it is, got {other:?}"),
    }

    service
        .finish(
            &record.operation_id,
            ExecutionOutcome::Succeeded {
                summary: "Refunded 20 EUR.".to_owned(),
                data: Some(json!({ "refund_id": "r_1" })),
            },
        )
        .await
        .unwrap();
    match service
        .confirm(&record.operation_id, &caller, 1, ApprovedBy::User)
        .await
    {
        Ok(ConfirmOutcome::AsIs(current)) => assert_eq!(current.state, OperationState::Succeeded),
        other => panic!("expected the operation as it is, got {other:?}"),
    }
}

#[tokio::test]
async fn confirms_that_race_run_the_action_once() {
    let service = Arc::new(service());
    let caller = agent("ses_1");
    let record = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();

    let confirms = (0..8).map(|_| {
        let service = Arc::clone(&service);
        let caller = caller.clone();
        let id = record.operation_id.clone();
        tokio::spawn(async move { service.confirm(&id, &caller, 1, ApprovedBy::User).await })
    });
    let mut runs = 0;
    for confirm in futures::future::join_all(confirms).await {
        match confirm.expect("task ends") {
            Ok(ConfirmOutcome::Run(_)) => runs += 1,
            Ok(ConfirmOutcome::AsIs(current)) => {
                assert_eq!(current.state, OperationState::InProgress);
            }
            Err(error) => panic!("a confirm failed: {error:?}"),
        }
    }
    assert_eq!(runs, 1);
}

#[tokio::test]
async fn the_outcome_is_recorded_and_an_unknown_one_stays_in_progress() {
    let service = service();
    let caller = agent("ses_1");
    let unknown = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    service
        .confirm(&unknown.operation_id, &caller, 1, ApprovedBy::User)
        .await
        .unwrap();
    let still = service
        .finish(
            &unknown.operation_id,
            ExecutionOutcome::Unknown {
                reason: "the backend timed out".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(still.state, OperationState::InProgress);
    assert!(still.result.is_none());

    let failed = service
        .propose("refund", &refund("B-2", 20), &caller)
        .await
        .unwrap();
    service
        .confirm(&failed.operation_id, &caller, 1, ApprovedBy::User)
        .await
        .unwrap();
    let failed = service
        .finish(
            &failed.operation_id,
            ExecutionOutcome::Failed {
                summary: "The order was already refunded.".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(failed.state, OperationState::Failed);
    assert_eq!(
        failed.wire()["result"],
        json!({ "summary": "The order was already refunded." })
    );
    let again = service
        .finish(
            &failed.operation_id,
            ExecutionOutcome::Succeeded {
                summary: "late".to_owned(),
                data: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(again.state, OperationState::Failed, "a final state is kept");
}

#[tokio::test]
async fn a_cancel_ends_a_proposed_operation_and_leaves_a_confirmed_one() {
    let service = service();
    let caller = agent("ses_1");
    let proposed = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    let cancelled = service
        .cancel(&proposed.operation_id, &caller)
        .await
        .unwrap();
    assert_eq!(cancelled.state, OperationState::Cancelled);
    assert!(cancelled.result.is_some());
    assert!(matches!(
        service
            .confirm(&proposed.operation_id, &caller, 1, ApprovedBy::User)
            .await,
        Ok(ConfirmOutcome::AsIs(current)) if current.state == OperationState::Cancelled
    ));
    let fresh = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    assert_ne!(
        fresh.operation_id, proposed.operation_id,
        "a cancelled operation is not revised"
    );

    service
        .confirm(&fresh.operation_id, &caller, 1, ApprovedBy::User)
        .await
        .unwrap();
    let running = service.cancel(&fresh.operation_id, &caller).await.unwrap();
    assert_eq!(running.state, OperationState::InProgress);
}

#[tokio::test]
async fn a_proposal_past_its_expiry_is_expired_and_cannot_be_confirmed() {
    let service = service_with(vec![OperationToolConfig {
        expires_after_secs: 0,
        ..tool("refund")
    }]);
    let caller = agent("ses_1");
    let record = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let read = service.read(&record.operation_id, &caller).await.unwrap();
    assert_eq!(read.state, OperationState::Expired);
    assert!(read.wire().get("expires_at").is_none());
    assert!(matches!(
        service
            .confirm(&record.operation_id, &caller, 1, ApprovedBy::User)
            .await,
        Ok(ConfirmOutcome::AsIs(current)) if current.state == OperationState::Expired
    ));
    let fresh = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    assert_ne!(fresh.operation_id, record.operation_id);
}

#[tokio::test]
async fn a_held_lease_makes_a_state_change_wait() {
    let service = Arc::new(service());
    let caller = agent("ses_1");
    let record = service
        .propose("refund", &refund("A-1", 20), &caller)
        .await
        .unwrap();
    let lease = service.acquire(&record.operation_id).await.unwrap();

    let waiting = {
        let service = Arc::clone(&service);
        let caller = caller.clone();
        let id = record.operation_id.clone();
        tokio::spawn(async move { service.cancel(&id, &caller).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished(), "the cancel waits for the lease");
    service.release(lease).await;
    let cancelled = waiting.await.unwrap().unwrap();
    assert_eq!(cancelled.state, OperationState::Cancelled);
}

#[test]
fn the_result_text_joins_the_text_blocks() {
    let result = json!({
        "content": [
            { "type": "text", "text": "Refunded." },
            { "type": "image", "data": "…" },
            { "type": "text", "text": "Ref r_1." },
        ]
    });
    assert_eq!(result_text(&result, "Done."), "Refunded.\nRef r_1.");
    assert_eq!(result_text(&json!({ "content": [] }), "Done."), "Done.");
}
