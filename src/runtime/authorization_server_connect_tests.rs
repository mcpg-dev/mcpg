//! Links that store a caller's IdP sign-in, and the connect page: a link
//! is offered to one principal and names nobody; the page binds its form
//! to the browser; the callback stores the sign-in only for the user the
//! link was offered to, once, and tells the session that offered it.

use super::*;
use crate::runtime::authorization_server::connect::{
    CompletedLink, ConnectLink, ConnectPage, LINK_REQUEST_STATE_PREFIX, LINK_RESUME_WAIT,
    LinkError, LinkOffer, LinkStateCheck, LinkStatus, MAX_NEW_LINKS_PER_PRINCIPAL,
};
use crate::runtime::authorization_server::interactive::ConsentRequest;
use crate::runtime::authorization_server::state::LinkRecord;

const SESSION: &str = "sess-legacy-1";

fn offer<'a>(principal: &'a str, resume: Option<&'a str>) -> LinkOffer<'a> {
    LinkOffer {
        principal,
        client_id: Some("web-app"),
        session_id: Some(SESSION),
        notify: true,
        resume,
    }
}

async fn offered(server: &AuthorizationServer, principal: &str) -> ConnectLink {
    server
        .offer_link(offer(principal, None))
        .await
        .expect("a link is offered")
}

async fn link_record(server: &AuthorizationServer, id: &str) -> Option<LinkRecord> {
    state_of(server).get(&keys::link(id)).await.expect("store")
}

#[track_caller]
fn connect_page(response: &BrowserResponse) -> &ConnectPage {
    match response.outcome {
        BrowserOutcome::Connect(ref page) => page,
        ref other => panic!("expected the connect page, got {other:?}"),
    }
}

#[track_caller]
fn csrf_cookie(response: &BrowserResponse) -> String {
    response
        .cookies
        .iter()
        .find_map(|change| match change {
            CookieChange::Set {
                cookie: BrowserCookie::Csrf,
                value,
                ..
            } => Some(value.clone()),
            _ => None,
        })
        .expect("the CSRF cookie is set")
}

/// Post `decision` on the connect page `response` shows, in the browser
/// that loaded it.
async fn decide(
    server: &AuthorizationServer,
    response: &BrowserResponse,
    decision: &str,
) -> BrowserResponse {
    let page = connect_page(response);
    server
        .decide_connect(
            &ConsentForm {
                req: Some(page.request.clone()),
                csrf: Some(page.csrf_token.clone()),
                decision: Some(decision.to_owned()),
            },
            &BrowserCookies {
                csrf: Some(csrf_cookie(response)),
                consent_memory: None,
            },
        )
        .await
}

/// Open the link `id` and approve its page; the sign-in sent to the IdP.
async fn start_link(server: &AuthorizationServer, id: &str) -> Started {
    let page = server
        .connect(&format!("e={id}"), &BrowserCookies::default())
        .await;
    assert!(connect_page(&page).link);
    started(&decide(server, &page, "approve").await, "")
}

fn another_principal(idp: &Idp) -> String {
    format!("verified::ema::{}::user-7", idp.issuer)
}

// ---------------------------------------------------------------------------
// Offering links
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_link_is_offered_to_one_principal_and_names_nobody() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let before = now_unix();
    let link = offered(&server, &principal).await;

    assert_eq!(link.id.len(), 43, "256 random bits");
    assert_eq!(
        link.url,
        format!("{GW_ISSUER}/oauth/connect?e={}", link.id),
        "the URL carries the link id and nothing else"
    );
    assert!(!link.url.contains(USER) && !link.url.contains("web-app"));
    assert_eq!(link.idp_name, "Acme SSO");
    assert!(!link.resumed);
    let ttl = server.interactive_settings().transaction_ttl_secs;
    assert!(link.expires_at >= before + ttl && link.expires_at <= now_unix() + ttl);

    let record = link_record(&server, &link.id).await.expect("stored");
    assert_eq!(
        record,
        LinkRecord {
            principal: principal.clone(),
            client_id: Some("web-app".to_owned()),
            session_id: Some(SESSION.to_owned()),
            notify: true,
            exp: link.expires_at,
        }
    );
    for sealed in raw(&server, "link/").await {
        assert!(!contains(&sealed, USER) && !contains(&sealed, SESSION));
    }
    assert!(format!("{link:?}").find(&link.id).is_none());
}

#[tokio::test]
async fn a_pending_link_is_offered_again_to_its_principal_only() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = offered(&server, &principal).await;

    let again = server
        .offer_link(offer(&principal, Some(&link.id)))
        .await
        .expect("offered");
    assert_eq!((again.id.as_str(), again.resumed), (link.id.as_str(), true));
    assert_eq!(again.url, link.url);

    let other = another_principal(&idp);
    let theirs = server
        .offer_link(offer(&other, Some(&link.id)))
        .await
        .expect("offered");
    assert_ne!(
        theirs.id, link.id,
        "another principal gets a link of their own"
    );
    assert!(!theirs.resumed);

    let garbage = server
        .offer_link(offer(&principal, Some("not-a-link")))
        .await
        .expect("offered");
    assert_eq!(
        (garbage.id.as_str(), garbage.resumed),
        (link.id.as_str(), true),
        "a resume that names no link offers the session's pending one"
    );

    let mut expiring = link_record(&server, &link.id).await.expect("stored");
    expiring.exp = now_unix() + 30;
    state_of(&server)
        .put(&keys::link(&link.id), &expiring, Duration::from_secs(30))
        .await
        .expect("store");
    let fresh = server
        .offer_link(offer(&principal, Some(&link.id)))
        .await
        .expect("offered");
    assert_ne!(
        fresh.id, link.id,
        "a link about to expire is replaced, so the user has time to complete it"
    );

    state_of(&server)
        .claim_once(&keys::link_done(&fresh.id), Duration::from_secs(60))
        .await
        .expect("store");
    let after_done = server
        .offer_link(offer(&principal, Some(&fresh.id)))
        .await
        .expect("offered");
    assert_ne!(
        after_done.id, fresh.id,
        "a completed link is not offered again"
    );
}

/// A caller retrying on the `2025-11-25` wire names no link, so each of
/// their calls on one session is offered the link that session is
/// pending, and the store holds one link per principal and session. A
/// principal is offered at most [`MAX_NEW_LINKS_PER_PRINCIPAL`] new links
/// per link lifetime; a pending one is still offered again.
#[tokio::test]
async fn a_session_is_offered_its_pending_link_and_new_links_are_capped() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let first = offered(&server, &principal).await;
    for _ in 0..3 {
        let again = offered(&server, &principal).await;
        assert_eq!(
            (again.id.as_str(), again.resumed),
            (first.id.as_str(), true)
        );
        assert_eq!(again.expires_at, first.expires_at);
    }
    assert_eq!(raw(&server, "link/").await.len(), 1, "one link is stored");

    let other_session = server
        .offer_link(LinkOffer {
            session_id: Some("sess-other"),
            ..offer(&principal, None)
        })
        .await
        .expect("offered");
    assert_ne!(other_session.id, first.id);
    let silent = server
        .offer_link(LinkOffer {
            notify: false,
            ..offer(&principal, None)
        })
        .await
        .expect("offered");
    assert_ne!(
        silent.id, first.id,
        "a link the session is told of is not reused where it is not"
    );
    let theirs = offered(&server, &another_principal(&idp)).await;
    assert_ne!(theirs.id, first.id);

    state_of(&server)
        .claim_once(&keys::link_done(&first.id), Duration::from_secs(60))
        .await
        .expect("store");
    let after_done = offered(&server, &principal).await;
    assert_ne!(after_done.id, first.id, "a completed link is not reused");
    assert!(!after_done.resumed);

    let window = now_unix() / server.interactive_settings().transaction_ttl_secs;
    let rate = keys::link_rate(&principal, window);
    let taken = state_of(&server).incr(&rate, 0, None).await.expect("store");
    assert_eq!(taken, 4, "only new links count");
    state_of(&server)
        .incr(&rate, MAX_NEW_LINKS_PER_PRINCIPAL - taken, None)
        .await
        .expect("store");
    let pending = offered(&server, &principal).await;
    assert_eq!(
        pending.id, after_done.id,
        "the pending link is offered over the cap"
    );
    let refused = server
        .offer_link(LinkOffer {
            session_id: Some("sess-third"),
            ..offer(&principal, None)
        })
        .await;
    assert_eq!(refused, Err(LinkError::Limited));
    assert_eq!(
        state_of(&server).incr(&rate, 0, None).await.expect("store"),
        MAX_NEW_LINKS_PER_PRINCIPAL,
        "a refused link takes no slot"
    );
    server
        .offer_link(LinkOffer {
            session_id: Some("sess-third"),
            ..offer(&another_principal(&idp), None)
        })
        .await
        .expect("another user has new links left");
    for sealed in raw(&server, "link_by/").await {
        assert!(!contains(&sealed, &first.id) && !contains(&sealed, SESSION));
    }
}

#[tokio::test]
async fn without_the_connect_page_no_link_is_offered_and_the_page_answers_404() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    interactive(&mut config).idp_sessions.connect_page = false;
    let server = server_with(&config);
    assert!(!server.offers_links());
    assert_eq!(
        server
            .offer_link(offer(&principal_of_user(&idp), None))
            .await,
        Err(LinkError::NotOffered)
    );
    let response = server.connect("", &BrowserCookies::default()).await;
    assert_eq!(page(&response), &ErrorPage::not_offered());
    assert!(raw(&server, "link/").await.is_empty());
}

/// A retry waits for its link at most a third of the time the gateway
/// answers a request in, and never longer than the default.
#[tokio::test]
async fn a_retry_waits_within_the_request_timeout() {
    let idp = Idp::start().await;
    assert_eq!(server(&idp).link_resume_wait(), LINK_RESUME_WAIT);
    assert_eq!(
        server(&idp)
            .with_request_timeout(Duration::from_secs(6))
            .link_resume_wait(),
        Duration::from_secs(2)
    );
    assert_eq!(
        server(&idp)
            .with_request_timeout(Duration::from_secs(300))
            .link_resume_wait(),
        LINK_RESUME_WAIT
    );
}

#[tokio::test]
async fn a_store_that_cannot_be_used_offers_no_link() {
    let idp = Idp::start().await;
    let config = config(&idp);
    let state = InteractiveState::new(StateParts {
        kv: Arc::new(UnavailableStore::new("disk full")),
        backend: StateBackend::InProcess,
        keyring: Arc::new(StateKeyring::process().expect("key")),
        issuer: GW_ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(10),
    })
    .expect("state");
    let server = build(&config, state);
    let refused = server
        .offer_link(offer(&principal_of_user(&idp), None))
        .await;
    assert!(
        matches!(refused, Err(LinkError::Unavailable(_))),
        "{refused:?}"
    );
}

// ---------------------------------------------------------------------------
// The requestState of a link
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_link_request_state_opens_only_for_its_caller_and_tool() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = offered(&server, &principal).await;
    let sealed = server
        .link_request_state(&link.id, link.expires_at, &principal, "crm.lookup")
        .expect("seals");
    assert!(sealed.starts_with(LINK_REQUEST_STATE_PREFIX));
    assert!(!sealed.contains(&link.id) && !sealed.contains(USER));
    assert_eq!(
        server.open_link_request_state(&sealed, &principal, "crm.lookup"),
        LinkStateCheck::Valid(link.id.clone())
    );
    assert!(!format!("{:?}", LinkStateCheck::Valid(link.id.clone())).contains(&link.id));
    assert_eq!(
        server.open_link_request_state(&sealed, &another_principal(&idp), "crm.lookup"),
        LinkStateCheck::Refused,
        "another caller cannot present it"
    );
    assert_eq!(
        server.open_link_request_state(&sealed, &principal, "crm.delete"),
        LinkStateCheck::Refused,
        "nor present it for another tool"
    );
    let mut altered = sealed.clone().into_bytes();
    let last = altered.len() - 3;
    altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
    let altered = String::from_utf8(altered).expect("ASCII");
    assert_eq!(
        server.open_link_request_state(&altered, &principal, "crm.lookup"),
        LinkStateCheck::Refused
    );
    assert_eq!(
        server.open_link_request_state(
            &sealed[LINK_REQUEST_STATE_PREFIX.len()..],
            &principal,
            "crm.lookup"
        ),
        LinkStateCheck::Refused,
        "the prefix is part of the state"
    );
    let expired = server
        .link_request_state(&link.id, now_unix() - 1, &principal, "crm.lookup")
        .expect("seals");
    assert_eq!(
        server.open_link_request_state(&expired, &principal, "crm.lookup"),
        LinkStateCheck::Expired,
        "an expired state of this caller and tool runs the call again"
    );
    for (caller, tool) in [
        (another_principal(&idp), "crm.lookup"),
        (principal.clone(), "crm.delete"),
    ] {
        assert_eq!(
            server.open_link_request_state(&expired, &caller, tool),
            LinkStateCheck::Refused,
            "an expired state of another caller or tool is refused"
        );
    }
    let foreign = build(
        &config(&idp),
        InteractiveState::in_memory("https://other.test").expect("state"),
    )
    .link_request_state(&link.id, link.expires_at, &principal, "crm.lookup")
    .expect("seals");
    assert_eq!(
        server.open_link_request_state(&foreign, &principal, "crm.lookup"),
        LinkStateCheck::Refused,
        "another issuer's state does not open"
    );
}

#[tokio::test]
async fn a_retry_waits_for_a_link_and_sees_it_complete() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = offered(&server, &principal).await;
    let short = Duration::from_millis(60);

    let started = tokio::time::Instant::now();
    assert_eq!(
        server.await_link(&link.id, &principal, short).await,
        LinkStatus::Pending
    );
    assert!(started.elapsed() >= short, "a pending link is waited for");
    assert_eq!(
        server
            .await_link(&link.id, &another_principal(&idp), short)
            .await,
        LinkStatus::Gone
    );
    assert_eq!(
        server.await_link("not-a-link", &principal, short).await,
        LinkStatus::Gone
    );

    state_of(&server)
        .claim_once(&keys::link_done(&link.id), Duration::from_secs(60))
        .await
        .expect("store");
    assert_eq!(
        server.await_link(&link.id, &principal, short).await,
        LinkStatus::Pending,
        "a completion claimed while the sign-in is still being stored is pending"
    );
    let waiting = server.await_link(&link.id, &principal, Duration::from_secs(5));
    let completing = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        state_of(&server)
            .claim_once(&keys::link_stored(&link.id), Duration::from_secs(60))
            .await
            .expect("store");
    };
    let (status, ()) = tokio::join!(waiting, completing);
    assert_eq!(status, LinkStatus::Completed);
}

// ---------------------------------------------------------------------------
// The connect page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_connect_page_seals_its_request_and_binds_it_to_the_browser() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let response = server.connect("", &BrowserCookies::default()).await;
    let page = connect_page(&response);
    assert_eq!(page.service_name, "gw.test");
    assert_eq!(page.idp_name, "Acme SSO");
    assert!(!page.link);
    assert_eq!(page.form_action, format!("{GW_ISSUER}/oauth/connect"));
    let consent: ConsentRequest = state_of(&server)
        .open_value("consent_req", &page.request)
        .expect("the request opens");
    assert_eq!(consent.purpose, TransactionPurpose::Connect);
    assert_eq!((consent.authorization, consent.link), (None, None));
    let cookie = csrf_cookie(&response);
    assert_eq!(cookie.len(), 43);
    assert!(
        raw(&server, "").await.is_empty(),
        "showing the page stores nothing"
    );

    let kept = server
        .connect(
            "",
            &BrowserCookies {
                csrf: Some(cookie.clone()),
                consent_memory: None,
            },
        )
        .await;
    assert_eq!(
        csrf_cookie(&kept),
        cookie,
        "a browser keeps its CSRF cookie"
    );

    let repeated = server.connect("e=a&e=b", &BrowserCookies::default()).await;
    assert_eq!(page_status(&repeated), 400);
}

fn page_status(response: &BrowserResponse) -> u16 {
    page(response).status
}

#[tokio::test]
async fn a_link_page_is_shown_only_while_the_link_is_pending() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let link = offered(&server, &principal_of_user(&idp)).await;

    let response = server
        .connect(&format!("e={}", link.id), &BrowserCookies::default())
        .await;
    let page = connect_page(&response);
    assert!(page.link);
    let consent: ConsentRequest = state_of(&server)
        .open_value("consent_req", &page.request)
        .expect("the request opens");
    assert_eq!(consent.purpose, TransactionPurpose::Link);
    assert_eq!(consent.link.as_deref(), Some(link.id.as_str()));
    assert!(consent.exp <= link.expires_at);

    for query in [
        "e=not-a-link".to_owned(),
        format!("e={}", random_token().expect("random")),
    ] {
        let refused = server.connect(&query, &BrowserCookies::default()).await;
        assert_eq!(self::page(&refused), &ErrorPage::link_expired(), "{query}");
    }
    state_of(&server)
        .claim_once(&keys::link_done(&link.id), Duration::from_secs(60))
        .await
        .expect("store");
    let done = server
        .connect(&format!("e={}", link.id), &BrowserCookies::default())
        .await;
    assert_eq!(self::page(&done), &ErrorPage::link_expired());
}

#[tokio::test]
async fn a_connect_decision_is_bound_to_the_browser_and_taken_once() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let response = server.connect("", &BrowserCookies::default()).await;
    let page = connect_page(&response);
    let cookie = csrf_cookie(&response);
    let form = |csrf: &str, decision: &str| ConsentForm {
        req: Some(page.request.clone()),
        csrf: Some(csrf.to_owned()),
        decision: Some(decision.to_owned()),
    };
    let browser = BrowserCookies {
        csrf: Some(cookie.clone()),
        consent_memory: None,
    };

    let other_browser = BrowserCookies {
        csrf: Some(random_token().expect("random")),
        consent_memory: None,
    };
    let forged = server
        .decide_connect(&form(&page.csrf_token, "approve"), &other_browser)
        .await;
    assert_eq!(self::page(&forged), &ErrorPage::forged());
    assert!(matches!(forged.audit, Some(BrowserAudit::Refused { .. })));

    let approved = server
        .decide_connect(&form(&page.csrf_token, "approve"), &browser)
        .await;
    let started = started(&approved, "");
    assert!(!started.idp.contains_key("prompt"));
    let record = transaction(&server, &started).await;
    assert_eq!(record.purpose, TransactionPurpose::Connect);
    assert_eq!(record.link_id, None);
    assert_eq!(record.client, None);
    assert_eq!(record.redirect_uri, None);

    let replayed = server
        .decide_connect(&form(&page.csrf_token, "approve"), &browser)
        .await;
    assert_eq!(self::page(&replayed), &ErrorPage::already_answered());

    let authorize = server
        .authorize(
            &authorize_query("desktop", DESKTOP_REDIRECT, &fresh_challenge()),
            &BrowserCookies::default(),
        )
        .await;
    let BrowserOutcome::Consent(ref consent_page) = authorize.outcome else {
        panic!("expected the consent page, got {:?}", authorize.outcome);
    };
    let consent_cookie = authorize
        .cookies
        .iter()
        .find_map(|change| match change {
            CookieChange::Set {
                cookie: BrowserCookie::Csrf,
                value,
                ..
            } => Some(value.clone()),
            _ => None,
        })
        .expect("CSRF cookie");
    let crossed = server
        .decide_connect(
            &ConsentForm {
                req: Some(consent_page.request.clone()),
                csrf: Some(consent_page.csrf_token.clone()),
                decision: Some("approve".to_owned()),
            },
            &BrowserCookies {
                csrf: Some(consent_cookie),
                consent_memory: None,
            },
        )
        .await;
    assert_eq!(
        self::page(&crossed),
        &ErrorPage::expired(),
        "a consent form is not a connect decision"
    );
}

#[tokio::test]
async fn cancelling_the_connect_page_stores_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    idp.never_redeems().await;
    let link = offered(&server, &principal_of_user(&idp)).await;
    let page = server
        .connect(&format!("e={}", link.id), &BrowserCookies::default())
        .await;
    let cancelled = decide(&server, &page, "deny").await;
    match cancelled.outcome {
        BrowserOutcome::Done(ref notice) => assert_eq!(notice.title, "Not connected"),
        ref other => panic!("expected the notice, got {other:?}"),
    }
    assert!(raw(&server, "txn/").await.is_empty());
    assert!(raw(&server, "link_done/").await.is_empty());
    idp.server.verify().await;
}

// ---------------------------------------------------------------------------
// Completing a link
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_link_completed_by_its_user_stores_the_sign_in_and_tells_the_session() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = offered(&server, &principal).await;
    let started = start_link(&server, &link.id).await;
    let record = transaction(&server, &started).await;
    assert_eq!(record.purpose, TransactionPurpose::Link);
    assert_eq!(record.link_id.as_deref(), Some(link.id.as_str()));

    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    match response.outcome {
        BrowserOutcome::Done(ref notice) => assert_eq!(notice.title, "Connected"),
        ref other => panic!("expected the connected page, got {other:?}"),
    }
    assert!(clears_binding(&response, &started));
    let completed = response
        .link_completed
        .clone()
        .expect("the session is told");
    assert_eq!(
        completed,
        CompletedLink {
            session_id: SESSION.to_owned(),
            elicitation_id: link.id.clone(),
        }
    );
    assert_eq!(
        completed.notification(),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": { "elicitationId": link.id },
        })
    );
    assert!(!format!("{completed:?}").contains(&link.id));
    let audit = login_audit(&response);
    assert_eq!(audit.purpose, TransactionPurpose::Link);
    let stored = state_of(&server)
        .get(&keys::idp_session(&principal))
        .await
        .expect("store")
        .expect("the sign-in is stored for the link's user");
    assert_eq!(stored.origin, IdpSessionOrigin::Link);
    assert_eq!(
        stored.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-1")
    );
    assert_eq!(
        server
            .await_link(&link.id, &principal, Duration::ZERO)
            .await,
        LinkStatus::Completed
    );
    assert!(raw(&server, "code/").await.is_empty());
    assert!(
        captured.seen("mcpg_as_connect_total{purpose=link,outcome=shown}"),
        "{:?}",
        captured.recorded()
    );
    assert!(captured.seen("mcpg_as_callback_total{outcome=connected,reason=none}"));
}

#[tokio::test]
async fn a_link_without_a_session_to_tell_completes_silently() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = server
        .offer_link(LinkOffer {
            principal: &principal,
            client_id: None,
            session_id: Some(SESSION),
            notify: false,
            resume: None,
        })
        .await
        .expect("offered");
    let started = start_link(&server, &link.id).await;
    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    assert!(matches!(response.outcome, BrowserOutcome::Done(_)));
    assert_eq!(response.link_completed, None);
}

#[tokio::test]
async fn a_link_completed_by_another_user_stores_nothing_and_is_audited() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let offered_to = another_principal(&idp);
    let link = offered(&server, &offered_to).await;
    let started = start_link(&server, &link.id).await;

    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    let refused = page(&response);
    assert_eq!(refused, &ErrorPage::another_user("Acme SSO"));
    assert_eq!(refused.status, 403);
    assert!(clears_binding(&response, &started));
    assert_eq!(response.link_completed, None);
    assert!(response.superseded.is_none());
    let Some(BrowserAudit::ConnectRefused(ref audit)) = response.audit else {
        panic!("expected mcpg.as.connect_refused, got {:?}", response.audit);
    };
    assert_eq!(audit.offered_to, offered_to);
    assert_eq!(audit.subject, USER);
    assert_eq!(audit.client_id.as_deref(), Some("web-app"));
    let event = response.audit.as_ref().expect("audit").event("req-1");
    assert_eq!(event.action, "mcpg.as.connect_refused");
    assert_eq!(
        event.outcome,
        mcpg_plugin_protocol::audit::AuditOutcome::Denied
    );
    assert_eq!(event.actor.subject_id.as_deref(), Some(USER));
    assert_eq!(event.details["offered_to"], offered_to);
    let serialized = serde_json::to_string(&event).expect("event serializes");
    assert!(!serialized.contains("idp-refresh-1") && !serialized.contains(&link.id));

    assert!(raw(&server, "idp/").await.is_empty(), "nothing is stored");
    assert!(
        state_of(&server)
            .get(&keys::idp_session(&offered_to))
            .await
            .expect("store")
            .is_none()
    );
    assert_eq!(
        server
            .await_link(&link.id, &offered_to, Duration::ZERO)
            .await,
        LinkStatus::Pending,
        "the link stays for the user it was offered to"
    );
    assert!(captured.seen("mcpg_as_callback_total{outcome=refused,reason=other_user}"));
}

#[tokio::test]
async fn a_link_is_completed_once() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let principal = principal_of_user(&idp);
    let link = offered(&server, &principal).await;
    let first = start_link(&server, &link.id).await;
    let second = start_link(&server, &link.id).await;
    let response = complete(&server, &idp, &first, Some("idp-refresh-1")).await;
    assert!(matches!(response.outcome, BrowserOutcome::Done(_)));

    idp.never_redeems().await;
    let again = callback(&server, &second, &[("code", IDP_CODE), ("iss", idp.issuer)]).await;
    assert_eq!(page(&again), &ErrorPage::link_expired());
    idp.server.verify().await;
}

#[tokio::test]
async fn a_link_that_expired_during_sign_in_stores_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let link = offered(&server, &principal_of_user(&idp)).await;
    let started = start_link(&server, &link.id).await;
    state_of(&server)
        .delete(&keys::link(&link.id))
        .await
        .expect("store");
    idp.never_redeems().await;
    let response = callback(
        &server,
        &started,
        &[("code", IDP_CODE), ("iss", idp.issuer)],
    )
    .await;
    assert_eq!(page(&response), &ErrorPage::link_expired());
    assert!(raw(&server, "idp/").await.is_empty());
    idp.server.verify().await;
}

#[tokio::test]
async fn a_standalone_connect_stores_the_sign_in_of_whoever_signs_in() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let page = server.connect("", &BrowserCookies::default()).await;
    let started = started(&decide(&server, &page, "approve").await, "");
    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    assert!(matches!(response.outcome, BrowserOutcome::Done(_)));
    assert_eq!(response.link_completed, None);
    let stored = state_of(&server)
        .get(&keys::idp_session(&principal_of_user(&idp)))
        .await
        .expect("store")
        .expect("stored");
    assert_eq!(stored.origin, IdpSessionOrigin::Connect);
}
