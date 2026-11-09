//! SEP-2640 Skills over HTTP: the capability, `skills/list`, `skills/get`,
//! `resources/directory/read`, `resources/read` and `resources/list`, on
//! both wires and under the access policy.

use super::*;
use crate::config::skills::{SkillSourceConfig, SkillsConfig};
use crate::runtime::skills::SkillCatalog;
use sha2::{Digest, Sha256};

const COMPUTER_USE: &str = "---\nname: computer-use\ndescription: Drive the Mac. Load first.\nlicense: Apache-2.0\nmetadata:\n  version: \"1.0\"\n---\n\n# Computer use\n\nSee `references/tool-map.md`.\n";
const TOOL_MAP: &str = "# Tool map\n\n| Tool | Use |\n";
const MOUSE: &str = "---\nname: mouse\ndescription: Click safely.\n---\n\nAim at the centre.\n";

fn write(root: &std::path::Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

fn skills_folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "computer-use/SKILL.md", COMPUTER_USE);
    write(dir.path(), "computer-use/references/tool-map.md", TOOL_MAP);
    write(dir.path(), "mouse/SKILL.md", MOUSE);
    dir
}

fn catalog(dir: &std::path::Path) -> SkillCatalog {
    let config = SkillsConfig {
        sources: vec![SkillSourceConfig {
            path: dir.display().to_string(),
            prefix: Some("macos".to_owned()),
        }],
        ..SkillsConfig::default()
    };
    SkillCatalog::load(&config, None).unwrap().unwrap()
}

fn skills_state(
    dir: &std::path::Path,
    policy: ToolAccessPolicyConfig,
    page_size: usize,
) -> AppState {
    let catalog = catalog(dir);
    build_test_state_with_all_runtime_controls_mut(
        false,
        RuntimeDebugConfig::default(),
        Vec::new(),
        policy,
        move |runtime| {
            runtime.set_skills(Some(catalog));
            runtime.set_list_page_size(page_size);
        },
    )
}

fn sha(bytes: &[u8]) -> String {
    crate::protocol::shared::skills::format_digest(&Sha256::digest(bytes))
}

async fn call(app: &Router, session_id: &str, id: u64, method: &str, params: Value) -> Value {
    let (_, response) = mcp_request(app.clone(), session_id, id, method, Some(params)).await;
    extract_jsonrpc_response(response, id).await
}

#[tokio::test]
async fn initialize_declares_the_extension_with_directory_read() {
    let dir = skills_folder();
    let app = router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100),
        "/health",
        "/mcp",
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "t", "version": "1" }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = extract_jsonrpc_response(response, 1).await;
    let capabilities = &body["result"]["capabilities"];
    assert_eq!(
        capabilities["extensions"]["io.modelcontextprotocol/skills"],
        serde_json::json!({ "directoryRead": true }),
        "{body}"
    );
    assert!(capabilities["resources"].is_object(), "{body}");
}

#[tokio::test]
async fn skills_list_returns_complete_manifests_whose_digests_match_the_reads() {
    let dir = skills_folder();
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100),
        "/health",
        "/mcp",
    ))
    .await;

    let listed = call(&app, &session, 2, "skills/list", serde_json::json!({})).await;
    let skills = listed["result"]["skills"].as_array().expect("skills");
    let uris: Vec<&str> = skills.iter().map(|s| s["uri"].as_str().unwrap()).collect();
    assert_eq!(
        uris,
        [
            "skill://macos/computer-use/SKILL.md",
            "skill://macos/mouse/SKILL.md"
        ]
    );
    assert!(
        listed["result"].get("resultType").is_none(),
        "legacy wire: {listed}"
    );
    let computer_use = &skills[0];
    assert_eq!(
        computer_use["frontmatter"],
        serde_json::json!({
            "name": "computer-use",
            "description": "Drive the Mac. Load first.",
            "license": "Apache-2.0",
            "metadata": { "version": "1.0" }
        })
    );
    assert_eq!(
        computer_use["resources"],
        serde_json::json!([
            { "uri": "skill://macos/computer-use/SKILL.md", "digest": sha(COMPUTER_USE.as_bytes()), "size": COMPUTER_USE.len() },
            { "uri": "skill://macos/computer-use/references/tool-map.md", "digest": sha(TOOL_MAP.as_bytes()), "size": TOOL_MAP.len() },
        ])
    );

    for (id, file) in computer_use["resources"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let read = call(
            &app,
            &session,
            10 + id as u64,
            "resources/read",
            serde_json::json!({ "uri": file["uri"] }),
        )
        .await;
        let content = &read["result"]["contents"][0];
        let text = content["text"].as_str().expect("a text file");
        assert_eq!(sha(text.as_bytes()), file["digest"], "{read}");
        assert_eq!(text.len() as u64, file["size"].as_u64().unwrap());
        assert_eq!(content["mimeType"], "text/markdown");
        assert_eq!(read["result"]["cacheToken"], file["digest"]);
    }
}

#[tokio::test]
async fn skills_get_answers_for_a_served_skill_and_refuses_any_other_uri() {
    let dir = skills_folder();
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100),
        "/health",
        "/mcp",
    ))
    .await;
    let got = call(
        &app,
        &session,
        2,
        "skills/get",
        serde_json::json!({ "uri": "skill://macos/mouse/SKILL.md" }),
    )
    .await;
    assert_eq!(
        got["result"]["skill"]["frontmatter"]["name"], "mouse",
        "{got}"
    );
    assert_eq!(
        got["result"]["skill"]["resources"][0]["digest"],
        sha(MOUSE.as_bytes())
    );
    for (id, uri) in [
        (3, "skill://macos/keyboard/SKILL.md"),
        (4, "skill://macos/computer-use/references/tool-map.md"),
        (5, "skill://macos/computer-use"),
    ] {
        let refused = call(
            &app,
            &session,
            id,
            "skills/get",
            serde_json::json!({ "uri": uri }),
        )
        .await;
        assert_eq!(refused["error"]["code"], -32602, "{uri}: {refused}");
    }
    let no_params = call(&app, &session, 6, "skills/get", serde_json::json!({})).await;
    assert_eq!(no_params["error"]["code"], -32602, "{no_params}");
}

#[tokio::test]
async fn directory_read_lists_the_direct_children_of_every_level() {
    let dir = skills_folder();
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100),
        "/health",
        "/mcp",
    ))
    .await;
    let children = |body: &Value| -> Vec<(String, String)> {
        body["result"]["resources"]
            .as_array()
            .unwrap_or_else(|| panic!("{body}"))
            .iter()
            .map(|r| {
                (
                    r["uri"].as_str().unwrap().to_owned(),
                    r["mimeType"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let root = call(
        &app,
        &session,
        2,
        "resources/directory/read",
        serde_json::json!({ "uri": "skill://macos" }),
    )
    .await;
    assert_eq!(
        children(&root),
        [
            (
                "skill://macos/computer-use".to_owned(),
                "inode/directory".to_owned()
            ),
            (
                "skill://macos/mouse".to_owned(),
                "inode/directory".to_owned()
            ),
        ]
    );
    let skill = call(
        &app,
        &session,
        3,
        "resources/directory/read",
        serde_json::json!({ "uri": "skill://macos/computer-use" }),
    )
    .await;
    assert_eq!(
        children(&skill),
        [
            (
                "skill://macos/computer-use/SKILL.md".to_owned(),
                "text/markdown".to_owned()
            ),
            (
                "skill://macos/computer-use/references".to_owned(),
                "inode/directory".to_owned()
            ),
        ]
    );
    assert_eq!(
        skill["result"]["resources"][0]["size"],
        COMPUTER_USE.len() as u64
    );
    for (id, uri) in [
        (4, "skill://macos/computer-use/SKILL.md"),
        (5, "skill://macos/nothing"),
        (6, "skill://macos/"),
    ] {
        let refused = call(
            &app,
            &session,
            id,
            "resources/directory/read",
            serde_json::json!({ "uri": uri }),
        )
        .await;
        assert_eq!(refused["error"]["code"], -32602, "{uri}: {refused}");
    }
}

#[tokio::test]
async fn resources_list_names_each_skill_md() {
    let dir = skills_folder();
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100),
        "/health",
        "/mcp",
    ))
    .await;
    let listed = call(&app, &session, 2, "resources/list", serde_json::json!({})).await;
    let entry = listed["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["uri"] == "skill://macos/computer-use/SKILL.md")
        .cloned()
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(entry["name"], "computer-use");
    assert_eq!(entry["description"], "Drive the Mac. Load first.");
    assert_eq!(entry["mimeType"], "text/markdown");
    assert_eq!(entry["size"], COMPUTER_USE.len() as u64);
}

#[tokio::test]
async fn skills_list_pages_with_a_cursor_and_refuses_a_forged_one() {
    let dir = skills_folder();
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), ToolAccessPolicyConfig::default(), 1),
        "/health",
        "/mcp",
    ))
    .await;
    let first = call(&app, &session, 2, "skills/list", serde_json::json!({})).await;
    assert_eq!(first["result"]["skills"].as_array().unwrap().len(), 1);
    let cursor = first["result"]["nextCursor"]
        .as_str()
        .expect("a next page")
        .to_owned();
    let second = call(
        &app,
        &session,
        3,
        "skills/list",
        serde_json::json!({ "cursor": cursor }),
    )
    .await;
    assert_eq!(
        second["result"]["skills"][0]["uri"],
        "skill://macos/mouse/SKILL.md"
    );
    assert!(second["result"].get("nextCursor").is_none(), "{second}");
    let forged = call(
        &app,
        &session,
        4,
        "skills/list",
        serde_json::json!({ "cursor": "forged" }),
    )
    .await;
    assert_eq!(forged["error"]["code"], -32602, "{forged}");
}

#[tokio::test]
async fn the_skills_floor_hides_and_refuses_everything_a_caller_may_not_read() {
    let dir = skills_folder();
    let policy = ToolAccessPolicyConfig {
        rules: vec![ToolTrustRule {
            tool_name: crate::runtime::policy::SKILLS_POLICY_KEY.to_owned(),
            minimum_trust: RequestTrustLevel::Verified,
            cel_allow_if: None,
            required_scopes: Vec::new(),
            surface: Some(crate::runtime::PolicySurface::Resource),
        }],
        ..ToolAccessPolicyConfig::default()
    };
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), policy, 100),
        "/health",
        "/mcp",
    ))
    .await;
    let listed = call(&app, &session, 2, "skills/list", serde_json::json!({})).await;
    assert_eq!(
        listed["result"]["skills"],
        serde_json::json!([]),
        "{listed}"
    );
    let got = call(
        &app,
        &session,
        3,
        "skills/get",
        serde_json::json!({ "uri": "skill://macos/mouse/SKILL.md" }),
    )
    .await;
    assert_eq!(got["error"]["code"], -32602, "{got}");
    let directory = call(
        &app,
        &session,
        4,
        "resources/directory/read",
        serde_json::json!({ "uri": "skill://macos" }),
    )
    .await;
    assert_eq!(directory["error"]["code"], -32602, "{directory}");
    let read = call(
        &app,
        &session,
        5,
        "resources/read",
        serde_json::json!({ "uri": "skill://macos/mouse/SKILL.md" }),
    )
    .await;
    assert!(
        read["error"].is_object(),
        "a header-asserted caller reads nothing: {read}"
    );
    let resources = call(&app, &session, 6, "resources/list", serde_json::json!({})).await;
    assert!(
        !resources.to_string().contains("skill://"),
        "resources/list hides the skills too: {resources}"
    );
}

#[tokio::test]
async fn the_skills_floor_can_open_skills_to_an_anonymous_caller() {
    let dir = skills_folder();
    let policy = ToolAccessPolicyConfig {
        rules: vec![ToolTrustRule {
            tool_name: crate::runtime::policy::SKILLS_POLICY_KEY.to_owned(),
            minimum_trust: RequestTrustLevel::Unauthenticated,
            cel_allow_if: None,
            required_scopes: Vec::new(),
            surface: Some(crate::runtime::PolicySurface::Resource),
        }],
        ..ToolAccessPolicyConfig::default()
    };
    let (app, session) = initialize_session(router(
        skills_state(dir.path(), policy, 100),
        "/health",
        "/mcp",
    ))
    .await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session)
                // deliberately no SUBJECT_ID_HEADER
                .body(Body::from(
                    serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "skills/list" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = extract_jsonrpc_response(response, 2).await;
    assert_eq!(
        listed["result"]["skills"].as_array().map(Vec::len),
        Some(2),
        "{listed}"
    );
}

#[tokio::test]
async fn without_a_source_the_methods_are_unknown() {
    let (app, session) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;
    for (id, method, params) in [
        (2, "skills/list", serde_json::json!({})),
        (
            3,
            "skills/get",
            serde_json::json!({ "uri": "skill://a/SKILL.md" }),
        ),
        (4, "skills/get", serde_json::json!({})),
        (
            5,
            "resources/directory/read",
            serde_json::json!({ "uri": "skill://a" }),
        ),
    ] {
        let answer = call(&app, &session, id, method, params).await;
        assert_eq!(answer["error"]["code"], -32601, "{method}: {answer}");
    }
}

#[tokio::test]
async fn directory_read_is_unknown_when_it_is_turned_off() {
    let dir = skills_folder();
    let config = SkillsConfig {
        sources: vec![SkillSourceConfig {
            path: dir.path().display().to_string(),
            prefix: None,
        }],
        directory_read: false,
        ..SkillsConfig::default()
    };
    let catalog = SkillCatalog::load(&config, None).unwrap().unwrap();
    let state = build_test_state_with_all_runtime_controls_mut(
        false,
        RuntimeDebugConfig::default(),
        Vec::new(),
        ToolAccessPolicyConfig::default(),
        move |runtime| runtime.set_skills(Some(catalog)),
    );
    let (app, session) = initialize_session(router(state, "/health", "/mcp")).await;
    let answer = call(
        &app,
        &session,
        2,
        "resources/directory/read",
        serde_json::json!({ "uri": "skill://mouse" }),
    )
    .await;
    assert_eq!(answer["error"]["code"], -32601, "{answer}");
    let listed = call(&app, &session, 3, "skills/list", serde_json::json!({})).await;
    assert_eq!(listed["result"]["skills"].as_array().map(Vec::len), Some(2));
}

/// One 2026-07-28 request, as a header-asserted caller.
async fn modern(app: &Router, id: u64, method: &str, params: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", method)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "conformance-user")
                .body(Body::from(
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, extract_jsonrpc_response(response, id).await)
}

#[tokio::test]
async fn the_modern_wire_declares_the_extension_and_stamps_its_results() {
    let dir = skills_folder();
    let state = skills_state(dir.path(), ToolAccessPolicyConfig::default(), 100);
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let (_, discovered) = modern(
        &app,
        1,
        "server/discover",
        serde_json::json!({
            "protocolVersion": "2026-07-28",
            "clientInfo": { "name": "t", "version": "1" },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "1" },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }),
    )
    .await;
    let capabilities = &discovered["result"]["capabilities"];
    assert_eq!(
        capabilities["extensions"]["io.modelcontextprotocol/skills"],
        serde_json::json!({ "directoryRead": true }),
        "{discovered}"
    );
    assert!(capabilities["resources"].is_object(), "{discovered}");

    let (status, listed) = modern(&app, 2, "skills/list", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["result"]["resultType"], "complete", "{listed}");
    assert_eq!(listed["result"]["cacheScope"], "private");
    assert!(listed["result"]["ttlMs"].is_u64());
    assert_eq!(listed["result"]["skills"].as_array().map(Vec::len), Some(2));

    let (_, got) = modern(
        &app,
        3,
        "skills/get",
        serde_json::json!({ "uri": "skill://macos/mouse/SKILL.md" }),
    )
    .await;
    assert_eq!(got["result"]["resultType"], "complete", "{got}");
    assert_eq!(
        got["result"]["skill"]["uri"],
        "skill://macos/mouse/SKILL.md"
    );

    let (_, directory) = modern(
        &app,
        4,
        "resources/directory/read",
        serde_json::json!({ "uri": "skill://macos/mouse" }),
    )
    .await;
    assert_eq!(directory["result"]["resultType"], "complete", "{directory}");
    assert_eq!(
        directory["result"]["resources"][0]["uri"],
        "skill://macos/mouse/SKILL.md"
    );
}

#[tokio::test]
async fn the_modern_wire_answers_404_while_no_skills_are_served() {
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");
    let (status, answer) = modern(&app, 2, "skills/list", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["error"]["code"], -32601);
}
