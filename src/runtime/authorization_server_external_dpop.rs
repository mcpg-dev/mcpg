//! DPoP at the resource for access tokens another verifier accepts
//! (`governance.access.dpop`): the tokens of an `oidc_oauth` provider or of
//! `jwks`, such as a Personal Agent Protocol Company's Session Tokens. The
//! token is verified as a Bearer token would be; this module checks what
//! RFC 9449 adds: the proof, its key against the token's `cnf.jkt`, and
//! single use in the replay ledger the embedded authorization server uses.

use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;

use super::dpop::{
    DpopChallenge, DpopChallengeError, DpopFailure, DpopPresentation, DpopReason, DpopSettings,
    DpopTarget, EmaRefusal, ProvenKey, count_proof, invalid, ledger_key,
};
use super::{ReplayLedger, ct_eq, now_unix};
use crate::config::AccessConfig;

/// `endpoint` label of the proof metrics.
const ENDPOINT: &str = "external_resource";
/// Clock skew allowed when no `oidc_oauth` provider sets one.
const DEFAULT_CLOCK_SKEW_SECS: u64 = 60;

/// The resource's DPoP for externally issued access tokens.
pub struct ExternalDpop {
    dpop: DpopSettings,
    replay: ReplayLedger,
}

impl std::fmt::Debug for ExternalDpop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalDpop")
            .field("dpop", &self.dpop)
            .field("replay", &self.replay)
            .finish()
    }
}

/// What the resource makes of a proof that goes with an externally issued
/// token.
#[derive(Debug)]
pub enum ExternalProof {
    /// The proof is of the token's key and is now spent; the thumbprint of
    /// that key.
    Accepted(String),
    /// Refused with a `WWW-Authenticate: DPoP` challenge.
    Refused(EmaRefusal),
    /// The replay ledger could not record the proof.
    Unavailable,
}

impl ExternalDpop {
    /// `access.dpop`, when it is on, with proofs spent in `replay`. The
    /// `htu` of a proof must name a request under a `resource_metadata`
    /// resource; the clock skew is the largest of the `oidc_oauth`
    /// providers'.
    pub fn from_access(access: &AccessConfig, replay: ReplayLedger) -> Result<Option<Self>> {
        let Some(config) = access.dpop.as_ref().filter(|config| config.enabled) else {
            return Ok(None);
        };
        let resources: Vec<String> = access
            .resource_metadata
            .as_ref()
            .map(|metadata| metadata.resources().map(str::to_owned).collect())
            .unwrap_or_default();
        let skew = access
            .oidc_oauth
            .as_ref()
            .and_then(|oidc| oidc.providers.iter().map(|p| p.clock_skew_secs).max())
            .unwrap_or(DEFAULT_CLOCK_SKEW_SECS);
        let dpop = DpopSettings::from_config(config, skew, "", &resources)?;
        Ok(Some(Self { dpop, replay }))
    }

    /// The ledger proofs are spent in, which a reload takes over when it is
    /// in-process.
    pub fn replay_ledger(&self) -> &ReplayLedger {
        &self.replay
    }

    /// The JWS algorithms a proof may use, by their JWA names.
    pub fn alg_names(&self) -> &[String] {
        self.dpop.alg_names()
    }

    /// What the resource's challenges say about DPoP.
    pub fn challenge(&self) -> DpopChallenge<'_> {
        DpopChallenge {
            algs: self.dpop.algs_param(),
            required: self.dpop.required,
        }
    }

    /// Whether only DPoP-bound tokens are accepted.
    pub fn required(&self) -> bool {
        self.dpop.required
    }

    /// Check the proof of a request at `target` carrying `presentation`
    /// with `token`, whose `cnf.jkt` is `bound`: every check of RFC 9449
    /// §4.3 with `ath`, the proof key against `bound`, then single use.
    pub async fn verify(
        &self,
        token: &str,
        bound: Option<&str>,
        presentation: &DpopPresentation<'_>,
        target: Option<&DpopTarget<'_>>,
    ) -> ExternalProof {
        use DpopChallengeError as E;
        let Some(bound) = bound else {
            const DESCRIPTION: &str =
                "the access token is not DPoP-bound; present it with the Bearer scheme";
            count_proof(ENDPOINT, &Err(invalid(DpopReason::NotBound, DESCRIPTION)));
            return ExternalProof::Refused(self.refusal(E::InvalidToken, DESCRIPTION, DESCRIPTION));
        };
        let Some(target) = target else {
            const DESCRIPTION: &str = "this endpoint takes no DPoP proof";
            count_proof(ENDPOINT, &Err(invalid(DpopReason::NoTarget, DESCRIPTION)));
            return ExternalProof::Refused(self.refusal(
                E::InvalidDpopProof,
                DESCRIPTION,
                DESCRIPTION,
            ));
        };
        // No nonce is required, so the check never asks whether one is
        // current.
        let checked = self
            .dpop
            .check(presentation, target, Some(token), |_| false, now_unix())
            .and_then(|proven| {
                if ct_eq(bound, &proven.jkt) {
                    Ok(proven)
                } else {
                    Err(invalid(
                        DpopReason::KeyMismatch,
                        "the DPoP proof key is not the key the access token is bound to",
                    ))
                }
            });
        let result = match checked {
            Ok(proven) => self.spend(&proven).await.map(|()| proven),
            Err(failure) => Err(failure),
        };
        count_proof(ENDPOINT, &result);
        match result {
            Ok(proven) => ExternalProof::Accepted(proven.jkt),
            // RFC 9449 §7.1 answers a proof of another key as a token
            // failure, not a proof failure.
            Err(DpopFailure::Invalid(DpopReason::KeyMismatch, reason)) => ExternalProof::Refused(
                self.refusal(E::InvalidToken, "Invalid DPoP key binding", reason),
            ),
            Err(DpopFailure::Invalid(_, description)) => ExternalProof::Refused(self.refusal(
                E::InvalidDpopProof,
                &description,
                description.clone(),
            )),
            Err(DpopFailure::UseNonce) => {
                const DESCRIPTION: &str = "this resource takes no DPoP nonce";
                ExternalProof::Refused(self.refusal(E::InvalidDpopProof, DESCRIPTION, DESCRIPTION))
            }
            Err(DpopFailure::Unavailable) => ExternalProof::Unavailable,
        }
    }

    /// A bound token presented with the `Bearer` scheme (RFC 9449 §7.1).
    pub fn bound_token_as_bearer(&self) -> EmaRefusal {
        const DESCRIPTION: &str =
            "the access token is DPoP-bound; present it with the DPoP scheme and a proof";
        self.refusal(DpopChallengeError::InvalidToken, DESCRIPTION, DESCRIPTION)
    }

    /// An unbound token presented with the `Bearer` scheme while `required`
    /// is set.
    pub fn unbound_token_refused(&self) -> Option<EmaRefusal> {
        const DESCRIPTION: &str = "this resource accepts only DPoP-bound tokens";
        self.dpop
            .required
            .then(|| self.refusal(DpopChallengeError::InvalidToken, DESCRIPTION, DESCRIPTION))
    }

    /// A token that `oidc_oauth` or `jwks` refused, presented with the
    /// `DPoP` scheme.
    pub fn invalid_token(&self, reason: impl Into<String>) -> EmaRefusal {
        self.refusal(
            DpopChallengeError::InvalidToken,
            "the access token is invalid, expired or revoked",
            reason,
        )
    }

    fn refusal(
        &self,
        error: DpopChallengeError,
        description: &str,
        reason: impl Into<String>,
    ) -> EmaRefusal {
        EmaRefusal {
            error,
            description: description.to_owned(),
            reason: reason.into(),
            nonce: None,
            algs: self.dpop.algs_param().to_owned(),
        }
    }

    /// Record `proven` in the replay ledger for as long as its proof is
    /// accepted. A proof recorded already is a replay; a ledger that cannot
    /// be written refuses it.
    async fn spend(&self, proven: &ProvenKey) -> Result<(), DpopFailure> {
        let ttl = self
            .dpop
            .accepted_until(proven.iat)
            .saturating_sub(now_unix())
            .max(1);
        let started = Instant::now();
        let claimed = self
            .replay
            .kv
            .put_if_absent(
                &ledger_key(&proven.jkt, &proven.jti),
                Bytes::from_static(b"1"),
                Some(Duration::from_secs(ttl)),
            )
            .await;
        metrics::histogram!("mcpg_as_dpop_ledger_latency_ms", "endpoint" => ENDPOINT)
            .record(started.elapsed().as_secs_f64() * 1000.0);
        match claimed {
            Ok(true) => Ok(()),
            Ok(false) => Err(invalid(
                DpopReason::Replayed,
                "the DPoP proof has already been used; sign a new proof for each request",
            )),
            Err(error) => {
                metrics::counter!("mcpg_ema_jti_store_errors_total").increment(1);
                tracing::error!(
                    error = %error,
                    "the replay ledger could not record a DPoP proof; refusing it"
                );
                Err(DpopFailure::Unavailable)
            }
        }
    }
}
