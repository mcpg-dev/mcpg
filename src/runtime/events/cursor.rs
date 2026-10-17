//! Event cursors.
//!
//! A cursor is `ev1.` followed by the unpadded base64url of a random 24-byte
//! nonce and the XChaCha20-Poly1305 seal of a [`CursorPosition`]. The
//! associated data is the source key plus a SHA-256 of the RFC 8785 form of
//! the subscription arguments ([`CursorScope`]), so a cursor opens only for
//! the type, scope and arguments it was issued for. The key derives from the
//! cluster-stable state key, so every replica opens every cursor and a restart
//! keeps them valid.
//!
//! A client can neither read a position nor forge or move one. A cursor that
//! does not open is never an error: [`CursorCodec::resume`] turns it, like a
//! stale epoch or a position below the retained floor, into a restart at the
//! head with `truncated: true`.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead as _, Generate as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mcpg_mcp_wire::shared::canonical::canonical_value_bytes;
use serde_json::Value;
use zeroize::Zeroizing;

/// Domain of the cursor key derived from the cluster state key.
pub const CURSOR_KEY_DOMAIN: &[u8] = b"mcpg:events:cursor:v1";
/// Prefix of every cursor this codec issues.
pub const CURSOR_PREFIX: &str = "ev1.";

/// First part of the associated data, so a cursor never opens as any other
/// sealed value under a key that happened to be shared.
const AAD_LABEL: &[u8] = b"mcpg:events:cursor:v1\0";
const NONCE_BYTES: usize = 24;
const POSITION_BYTES: usize = 8 + 4 + 8;
const TAG_BYTES: usize = 16;
const SEALED_BYTES: usize = NONCE_BYTES + POSITION_BYTES + TAG_BYTES;
/// Length of every issued cursor; anything else is refused before decoding.
const CURSOR_CHARS: usize = CURSOR_PREFIX.len() + (SEALED_BYTES * 4).div_ceil(3);

/// A position in one event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPosition {
    /// The log's random epoch; a lost and re-created log has another.
    pub epoch: u64,
    /// The type's schema epoch when the cursor was issued.
    pub schema_epoch: u32,
    /// The last sequence number delivered (or acknowledged) at this cursor.
    pub seq: u64,
}

impl CursorPosition {
    fn to_bytes(self) -> [u8; POSITION_BYTES] {
        let mut out = [0u8; POSITION_BYTES];
        out[..8].copy_from_slice(&self.epoch.to_be_bytes());
        out[8..12].copy_from_slice(&self.schema_epoch.to_be_bytes());
        out[12..].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != POSITION_BYTES {
            return None;
        }
        Some(Self {
            epoch: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            schema_epoch: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            seq: u64::from_be_bytes(bytes[12..].try_into().ok()?),
        })
    }
}

/// What a cursor is bound to: the source key of the log and the
/// subscription's arguments, compared by canonical JSON. Build it once per
/// subscription and reuse it for every cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorScope {
    aad: Vec<u8>,
}

impl CursorScope {
    /// The scope of `source_key` with `arguments`.
    pub fn new(source_key: &str, arguments: &Value) -> Self {
        let arguments_hash = hmac_sha256::Hash::hash(&canonical_value_bytes(arguments));
        let mut aad = Vec::with_capacity(AAD_LABEL.len() + 8 + source_key.len() + 32);
        aad.extend_from_slice(AAD_LABEL);
        // Length-prefixed, so no (source key, hash) pair can collide with
        // another by shifting bytes across the boundary.
        aad.extend_from_slice(&(source_key.len() as u64).to_be_bytes());
        aad.extend_from_slice(source_key.as_bytes());
        aad.extend_from_slice(&arguments_hash);
        Self { aad }
    }
}

impl fmt::Debug for CursorScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CursorScope(..)")
    }
}

/// The bounds of one log at the moment a cursor is resolved.
///
/// Sequence numbers start at 1, so `head` 0 is a log with nothing appended
/// and a reader that starts at the head of an empty log still receives the
/// first row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogBounds {
    /// The log's current epoch.
    pub epoch: u64,
    /// The lowest retained sequence number; rows `floor..=head` are retained.
    pub floor: u64,
    /// The committed head.
    pub head: u64,
}

/// Where delivery resumes for a client-supplied cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// Deliver the rows after `seq`. `truncated` reports that events the
    /// client may expect were skipped.
    After { seq: u64, truncated: bool },
    /// The cursor predates a non-additive schema change of the type; the
    /// client must re-list before it subscribes again.
    SchemaChanged,
}

/// Seals and opens cursors under one key.
#[derive(Clone)]
pub struct CursorCodec {
    cipher: XChaCha20Poly1305,
}

impl fmt::Debug for CursorCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CursorCodec(..)")
    }
}

impl CursorCodec {
    /// A codec over an already-derived 32-byte cursor key.
    pub fn from_key(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new_from_slice(key)
                .expect("XChaCha20-Poly1305 takes a 32-byte key"),
        }
    }

    /// A codec over the key derived from the cluster-stable state key `base`
    /// in [`CURSOR_KEY_DOMAIN`]: identical on every replica that holds
    /// `base`.
    pub fn from_state_key(base: &[u8; 32]) -> Self {
        let key = Zeroizing::new(crate::app::derive_cluster_subkey(base, CURSOR_KEY_DOMAIN));
        Self::from_key(&key)
    }

    /// The cursor for `position` in `scope`. Two calls give different text
    /// for the same position; both open.
    pub fn seal(&self, position: CursorPosition, scope: &CursorScope) -> String {
        let nonce = XNonce::generate();
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &position.to_bytes(),
                    aad: &scope.aad,
                },
            )
            .expect("sealing a fixed-size position cannot fail");
        let mut raw = Vec::with_capacity(SEALED_BYTES);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&sealed);
        let mut out = String::with_capacity(CURSOR_CHARS);
        out.push_str(CURSOR_PREFIX);
        URL_SAFE_NO_PAD.encode_string(&raw, &mut out);
        out
    }

    /// The position `cursor` holds, or `None` when it was not issued by this
    /// key for this scope, or was altered in any way.
    pub fn open(&self, cursor: &str, scope: &CursorScope) -> Option<CursorPosition> {
        if cursor.len() != CURSOR_CHARS {
            return None;
        }
        let raw = URL_SAFE_NO_PAD
            .decode(cursor.strip_prefix(CURSOR_PREFIX)?)
            .ok()?;
        if raw.len() != SEALED_BYTES {
            return None;
        }
        let (nonce, sealed) = raw.split_at(NONCE_BYTES);
        let nonce = XNonce::try_from(nonce).ok()?;
        let plain = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed,
                    aad: &scope.aad,
                },
            )
            .ok()?;
        CursorPosition::from_bytes(&plain)
    }

    /// Where delivery resumes for the cursor a client sent.
    ///
    /// - No cursor: from now (the head), not truncated.
    /// - A cursor that does not open, from another log epoch, from a newer
    ///   schema epoch, past the head, or below the retained floor: the head,
    ///   truncated.
    /// - A cursor from an older schema epoch: [`Resume::SchemaChanged`].
    /// - Otherwise: right after the cursor, not truncated.
    ///
    /// `maxAgeMs` is applied by the log reader on top of this, since it needs
    /// row timestamps.
    pub fn resume(
        &self,
        cursor: Option<&str>,
        scope: &CursorScope,
        log: LogBounds,
        schema_epoch: u32,
    ) -> Resume {
        let gap = Resume::After {
            seq: log.head,
            truncated: true,
        };
        let Some(cursor) = cursor else {
            return Resume::After {
                seq: log.head,
                truncated: false,
            };
        };
        let Some(position) = self.open(cursor, scope) else {
            return gap;
        };
        if position.epoch != log.epoch {
            return gap;
        }
        if position.schema_epoch < schema_epoch {
            return Resume::SchemaChanged;
        }
        if position.schema_epoch > schema_epoch || position.seq > log.head {
            return gap;
        }
        // The next row the cursor needs is `seq + 1`; below the floor it is
        // gone.
        if position.seq.saturating_add(1) < log.floor {
            return gap;
        }
        Resume::After {
            seq: position.seq,
            truncated: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const LOG: LogBounds = LogBounds {
        epoch: 0x5eed,
        floor: 10,
        head: 50,
    };

    fn codec() -> CursorCodec {
        CursorCodec::from_state_key(&[7u8; 32])
    }

    fn scope() -> CursorScope {
        CursorScope::new("sk_orders", &json!({"region": "eu", "limit": 5}))
    }

    fn at(seq: u64) -> CursorPosition {
        CursorPosition {
            epoch: LOG.epoch,
            schema_epoch: 2,
            seq,
        }
    }

    #[test]
    fn a_sealed_position_opens_in_its_scope() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        assert_eq!(c.open(&cursor, &scope()), Some(at(42)));
    }

    #[test]
    fn cursors_have_a_fixed_url_safe_shape_and_hide_the_position() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        assert!(cursor.starts_with("ev1."));
        assert_eq!(cursor.len(), CURSOR_CHARS);
        assert_eq!(cursor.len(), 84);
        assert!(
            cursor[4..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let again = c.seal(at(42), &scope());
        assert_ne!(cursor, again, "a fresh nonce per seal");
        assert_eq!(c.open(&again, &scope()), Some(at(42)));
    }

    #[test]
    fn extreme_positions_round_trip() {
        let c = codec();
        for p in [
            CursorPosition {
                epoch: 0,
                schema_epoch: 0,
                seq: 0,
            },
            CursorPosition {
                epoch: u64::MAX,
                schema_epoch: u32::MAX,
                seq: u64::MAX,
            },
        ] {
            assert_eq!(c.open(&c.seal(p, &scope()), &scope()), Some(p));
        }
    }

    #[test]
    fn a_cursor_is_bound_to_its_source_and_arguments() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        for other in [
            CursorScope::new("sk_orders2", &json!({"region": "eu", "limit": 5})),
            CursorScope::new("sk_order", &json!({"region": "eu", "limit": 5})),
            CursorScope::new("sk_orders", &json!({"region": "us", "limit": 5})),
            CursorScope::new("sk_orders", &json!({"region": "eu"})),
            CursorScope::new("sk_orders", &json!({})),
        ] {
            assert_eq!(c.open(&cursor, &other), None);
        }
    }

    #[test]
    fn argument_key_order_and_number_spelling_do_not_matter() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        let reordered: Value = serde_json::from_str(r#"{"limit": 5.0, "region": "eu"}"#).unwrap();
        assert_eq!(
            c.open(&cursor, &CursorScope::new("sk_orders", &reordered)),
            Some(at(42))
        );
    }

    #[test]
    fn another_key_does_not_open_it() {
        let cursor = codec().seal(at(42), &scope());
        assert_eq!(
            CursorCodec::from_state_key(&[8u8; 32]).open(&cursor, &scope()),
            None
        );
        // The derived key, not the state key itself, seals cursors.
        assert_eq!(
            CursorCodec::from_key(&[7u8; 32]).open(&cursor, &scope()),
            None
        );
        let derived = crate::app::derive_cluster_subkey(&[7u8; 32], CURSOR_KEY_DOMAIN);
        assert_eq!(
            CursorCodec::from_key(&derived).open(&cursor, &scope()),
            Some(at(42))
        );
    }

    #[test]
    fn every_changed_byte_is_refused() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        let raw = URL_SAFE_NO_PAD.decode(&cursor[4..]).unwrap();
        for i in 0..raw.len() {
            for flip in [0x01u8, 0x80] {
                let mut bad = raw.clone();
                bad[i] ^= flip;
                let text = format!("ev1.{}", URL_SAFE_NO_PAD.encode(&bad));
                assert_eq!(c.open(&text, &scope()), None, "byte {i} flip {flip:#x}");
            }
        }
    }

    #[test]
    fn malformed_text_is_refused() {
        let c = codec();
        let cursor = c.seal(at(42), &scope());
        let wrong_prefix = format!("ev2.{}", &cursor[4..]);
        let padded = format!("{cursor}=");
        let short = &cursor[..cursor.len() - 1];
        let std_alphabet = cursor.replace('-', "+").replace('_', "/");
        for bad in [
            "",
            "ev1.",
            "null",
            wrong_prefix.as_str(),
            padded.as_str(),
            short,
            &"A".repeat(10_000),
        ] {
            assert_eq!(c.open(bad, &scope()), None, "{bad:?}");
        }
        if std_alphabet != cursor {
            assert_eq!(c.open(&std_alphabet, &scope()), None);
        }
    }

    #[test]
    fn no_cursor_starts_at_the_head_without_a_gap() {
        assert_eq!(
            codec().resume(None, &scope(), LOG, 2),
            Resume::After {
                seq: 50,
                truncated: false
            }
        );
    }

    #[test]
    fn an_empty_log_resumes_before_its_first_row() {
        let c = codec();
        let empty = LogBounds {
            epoch: LOG.epoch,
            floor: 1,
            head: 0,
        };
        let from_now = Resume::After {
            seq: 0,
            truncated: false,
        };
        assert_eq!(c.resume(None, &scope(), empty, 2), from_now);
        let cursor = c.seal(at(0), &scope());
        assert_eq!(c.resume(Some(&cursor), &scope(), empty, 2), from_now);
    }

    #[test]
    fn a_valid_cursor_resumes_right_after_itself() {
        let c = codec();
        for seq in [9, 10, 42, 50] {
            let cursor = c.seal(at(seq), &scope());
            assert_eq!(
                c.resume(Some(&cursor), &scope(), LOG, 2),
                Resume::After {
                    seq,
                    truncated: false
                },
                "seq {seq}"
            );
        }
    }

    #[test]
    fn unusable_cursors_restart_at_the_head_truncated() {
        let c = codec();
        let gap = Resume::After {
            seq: 50,
            truncated: true,
        };
        let foreign = CursorScope::new("sk_other", &json!({}));
        let cases = [
            ("garbage".to_owned(), "does not open"),
            (c.seal(at(42), &foreign), "another scope"),
            (
                c.seal(
                    CursorPosition {
                        epoch: 0xdead,
                        ..at(42)
                    },
                    &scope(),
                ),
                "another log epoch",
            ),
            (
                c.seal(
                    CursorPosition {
                        schema_epoch: 3,
                        ..at(42)
                    },
                    &scope(),
                ),
                "a newer schema epoch",
            ),
            (c.seal(at(51), &scope()), "past the head"),
            (c.seal(at(8), &scope()), "below the floor"),
            (c.seal(at(0), &scope()), "far below the floor"),
        ];
        for (cursor, why) in cases {
            assert_eq!(c.resume(Some(&cursor), &scope(), LOG, 2), gap, "{why}");
        }
    }

    #[test]
    fn an_older_schema_epoch_asks_the_client_to_re_list() {
        let c = codec();
        let cursor = c.seal(
            CursorPosition {
                schema_epoch: 1,
                ..at(42)
            },
            &scope(),
        );
        assert_eq!(
            c.resume(Some(&cursor), &scope(), LOG, 2),
            Resume::SchemaChanged
        );
    }

    #[test]
    fn debug_output_holds_no_key_material() {
        assert_eq!(format!("{:?}", codec()), "CursorCodec(..)");
        assert_eq!(format!("{:?}", scope()), "CursorScope(..)");
    }
}
