use super::*;

/// Paginate a list endpoint with HMAC-bound cursors. The cursor encodes an
/// offset + HMAC so it is tamper-proof and session-scoped — a cursor from one
/// session cannot be replayed on another because the binding key is derived from
/// the session ID via the runtime's per-process HMAC key.
/// Security: cursor HMAC verification uses constant-time comparison.
pub(super) fn paginate_list_bound<T: Clone>(
    items: &[T],
    cursor: Option<&str>,
    bind_key: Option<&[u8]>,
) -> (Vec<T>, Option<String>) {
    let offset = cursor.and_then(|c| decode_cursor(c, bind_key)).unwrap_or(0);

    if offset >= items.len() {
        return (vec![], None);
    }

    let end = (offset + DEFAULT_PAGE_SIZE).min(items.len());
    let page = items[offset..end].to_vec();
    let next_cursor = if end < items.len() {
        Some(encode_cursor(end, bind_key))
    } else {
        None
    };
    (page, next_cursor)
}

pub(super) fn encode_cursor(offset: usize, bind_key: Option<&[u8]>) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let offset_b64 = URL_SAFE_NO_PAD.encode(offset.to_string());
    match bind_key {
        Some(key) => {
            let mac = hmac_sha256::HMAC::mac(offset_b64.as_bytes(), key);
            let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
            format!("{offset_b64}.{mac_b64}")
        }
        None => offset_b64,
    }
}

pub(super) fn decode_cursor(cursor: &str, bind_key: Option<&[u8]>) -> Option<usize> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let (offset_part, mac_part) = match (cursor.split_once('.'), bind_key) {
        (Some((o, m)), Some(_)) => (o, Some(m)),
        // Unbound cursor but MAC required: reject.
        (None, Some(_)) => return None,
        (Some((_, _)), None) => return None, // MAC supplied but no key — suspicious.
        (None, None) => (cursor, None),
    };
    if let (Some(key), Some(mac_b64)) = (bind_key, mac_part) {
        let expected = hmac_sha256::HMAC::mac(offset_part.as_bytes(), key);
        let actual = URL_SAFE_NO_PAD.decode(mac_b64).ok()?;
        if !constant_time_eq(&expected, &actual) {
            return None;
        }
    }
    let bytes = URL_SAFE_NO_PAD.decode(offset_part).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    s.parse::<usize>().ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Composite cursor for resources/list — static + dynamic providers
// ---------------------------------------------------------------------------

/// Wire-encoded composite cursor for `resources/list` pagination.
///
/// On page 1 (incoming cursor is `None`): the gateway pages
/// `DEFAULT_PAGE_SIZE` static resources AND fans out to every
/// dynamic provider's first page. The outgoing cursor records
/// (a) where to resume the static walk, and (b) which dynamic
/// providers reported a non-null `next_cursor` plus their
/// cursors.
///
/// On page N: each call walks EITHER more static resources OR
/// one round of remaining dynamic providers, never both, so a
/// single page response never exceeds `DEFAULT_PAGE_SIZE` items
/// (the static cap) plus the dynamic-walk batch.
///
/// HMAC-bound to the session via the same key derivation as the
/// scalar `paginate_list_bound` helper, so cursors aren't
/// replayable across sessions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(super) struct CompositeCursor {
    /// Next static-resource offset (`None` once static exhausts).
    #[serde(default)]
    pub(super) s: Option<usize>,
    /// Per-binding next-cursor pairs for dynamic providers that
    /// haven't yet exhausted. Iteration order matches the
    /// runtime's stable `dynamic_list_bindings` order on page 1;
    /// follow-up pages preserve the order returned by the
    /// previous page.
    #[serde(default)]
    pub(super) d: Vec<DynCursor>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct DynCursor {
    /// Binding name (`BackendConfig.name`).
    pub(super) b: String,
    /// Provider-supplied next cursor — opaque to the gateway.
    pub(super) c: String,
}

impl CompositeCursor {
    /// `true` when neither static nor dynamic walking has more
    /// pages to emit. Caller emits a wire-level `next_cursor: None`
    /// in that case.
    pub(super) fn is_done(&self) -> bool {
        self.s.is_none() && self.d.is_empty()
    }
}

pub(super) fn encode_composite_cursor(cursor: &CompositeCursor, bind_key: Option<&[u8]>) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    // Tag with a `c.` prefix so callers can distinguish a
    // composite cursor from a legacy bare-offset one without a
    // round-trip through serde — the bare-offset form is just a
    // base64-encoded number, never starts with `c.`.
    let payload = serde_json::to_vec(cursor).expect("composite cursor serializes");
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    match bind_key {
        Some(key) => {
            let mac = hmac_sha256::HMAC::mac(payload_b64.as_bytes(), key);
            let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
            format!("c.{payload_b64}.{mac_b64}")
        }
        None => format!("c.{payload_b64}"),
    }
}

pub(super) fn decode_composite_cursor(
    cursor: &str,
    bind_key: Option<&[u8]>,
) -> Option<CompositeCursor> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let body = cursor.strip_prefix("c.")?;
    let (payload_b64, mac_part) = match (body.split_once('.'), bind_key) {
        (Some((p, m)), Some(_)) => (p, Some(m)),
        (None, Some(_)) => return None, // MAC required but missing
        (Some((_, _)), None) => return None, // MAC supplied but no key — suspicious
        (None, None) => (body, None),
    };
    if let (Some(key), Some(mac_b64)) = (bind_key, mac_part) {
        let expected = hmac_sha256::HMAC::mac(payload_b64.as_bytes(), key);
        let actual = URL_SAFE_NO_PAD.decode(mac_b64).ok()?;
        if !constant_time_eq(&expected, &actual) {
            return None;
        }
    }
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice::<CompositeCursor>(&payload).ok()
}

impl GatewayRuntime {
    pub(super) fn generate_cursor_hmac_key() -> [u8; 32] {
        // 32 bytes of system-CSPRNG-backed randomness scoped to
        // this process. uuid::Uuid::new_v4 is backed by getrandom on
        // every supported target; concatenating two v4 UUIDs gives us
        // the required 32 bytes without adding the `rand` crate to the
        // workspace. A gateway restart invalidates outstanding
        // cursors, matching the replay-window semantics of the
        // session store.
        let mut key = [0u8; 32];
        let a = *uuid::Uuid::new_v4().as_bytes();
        let b = *uuid::Uuid::new_v4().as_bytes();
        key[..16].copy_from_slice(&a);
        key[16..].copy_from_slice(&b);
        key
    }

    /// Derive a per-session cursor binding key from the runtime HMAC
    /// key and the session identifier. A cursor issued under one
    /// session can never be replayed on another because the MAC will
    /// fail verification.
    pub(super) fn cursor_binding_key(&self, session_id: Option<&str>) -> Vec<u8> {
        let sid = session_id.unwrap_or("anonymous");
        hmac_sha256::HMAC::mac(sid.as_bytes(), self.cursor_hmac_key).to_vec()
    }
}
