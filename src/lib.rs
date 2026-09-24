#![forbid(unsafe_code)]

//! Authenticate by Windows: a username and password through the host's
//! SSPI, refusing where no SSPI is reachable.
//!
//! A Windows host, or the domain it belongs to, already knows its users,
//! and the node asks it rather than keeping verifiers of its own. The first
//! gate reads the name and calls it a `username` claim, with the password
//! riding on `Presented::proof` under `password`. This gate reads the name
//! as an account — `CORP\alice`, `alice@corp.example`, or a bare `alice` in
//! the configured domain — hands the pair to the host's logon facility and
//! turns what it concludes into a verdict: a logon that holds proves the
//! claim, `ERROR_LOGON_FAILURE` refuses it without saying whether the name
//! or the password was wrong, as Windows itself does not, and a disabled or
//! locked-out account or an expired password is refused with Win32's name
//! for it.
//!
//! **No SSPI is reachable from this build.** Calling Secur32 takes unsafe
//! code and `unsafe_code = "forbid"` stands in every crate, so the host
//! facility is the [`Logon`] trait, and an authenticator that is given none
//! refuses every logon with that reason, on every operating system, Windows
//! included (ADR-0050, amendment 2026-09-16). [`InProcess`] is a security
//! authority that lives in the process, and is what the tests prove the
//! path against. The binding is queued behind the owner's ruling on where
//! unsafe may live. A Kerberos ticket or an NTLM exchange is `kerberos`'s
//! or `ntlm`'s to verify; this mechanism keeps its own name, `windows`, so
//! an Acceptance can say which verifier a Location uses.
//!
//! The logon name is read by the identify capability's `UserPrincipalName`,
//! so `CORP\alice` and `alice@corp` are one account, and a claim whose
//! `principal.user` evidence names another account than the one it presents
//! is refused naming both (ADR-0054).

pub mod account;
pub mod logon;

pub use account::Account;
pub use logon::{InProcess, Logon, Outcome, UNREACHABLE, Unreachable};

use authenticate::{AuthenticateError, Authenticator};
use context::Verified;
use identify::Presented;
use identify::UserPrincipalName;
use identify::evidence::{self, PASSWORD};
use xcore::{Mechanism, mechanism};

/// Verifies a `username` claim with a `password` proof through the host's
/// logon facility.
pub struct WindowsAuthenticator {
    domain: Option<String>,
    facility: Box<dyn Logon>,
}

impl Default for WindowsAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsAuthenticator {
    /// Authenticates against the facility this build reaches, which is
    /// none: every logon is refused with the reason until
    /// [`WindowsAuthenticator::with_facility`] gives it one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain: None,
            facility: Box::new(Unreachable),
        }
    }

    /// The domain a bare username is looked up in. Without one, a bare name
    /// is an account of the host itself.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// The facility to log on through.
    #[must_use]
    pub fn with_facility(mut self, facility: impl Logon + 'static) -> Self {
        self.facility = Box::new(facility);
        self
    }

    /// The domain a bare username is looked up in, where one is configured.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `windows`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "windows"
}

impl Authenticator for WindowsAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::windows()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the Windows verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let password = presented.proof(evidence::PASSWORD).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PASSWORD}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        let account = Account::parse(&presented.value, self.domain.as_deref())?;
        same_account(&account, presented)?;
        match self.facility.logon(&account, password)? {
            Outcome::Success => Ok(Verified::Proven),
            Outcome::LogonFailure => Ok(Verified::Refused),
            other => Err(AuthenticateError::new(format!(
                "the host refused to log '{account}' on: {} ({})",
                other.name(),
                other.code()
            ))),
        }
    }
}

/// Refuse a claim whose `principal.user` evidence names another account than
/// the one it presents. Evidence is never proof: agreeing with it proves
/// nothing, and the logon still decides.
fn same_account(account: &Account, presented: &Presented) -> Result<(), AuthenticateError> {
    let claimed = presented
        .evidence
        .iter()
        .find(|(name, _)| name == evidence::PRINCIPAL_USER)
        .and_then(|(_, value)| UserPrincipalName::parse(value));
    match (claimed, account.principal()) {
        (Some(claimed), Some(read)) if !claimed.is(&read) => Err(AuthenticateError::new(format!(
            "the claim presents '{read}' and its evidence names '{claimed}': not the same account"
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::{Acceptance, PartyRegistry, Refusal, authenticate};
    use xcore::{PartyId, Purpose};

    fn account(name: &str) -> Account {
        Account::parse(name, None).expect("an account")
    }

    fn verifier() -> WindowsAuthenticator {
        let authority = InProcess::new(64)
            .with_account(&account("CORP\\alice"), "pencil")
            .with_account(&account("CORP\\retired"), "pencil")
            .with_disabled(&account("CORP\\retired"));
        WindowsAuthenticator::new()
            .with_domain("CORP")
            .with_facility(authority)
    }

    fn claim(username: &str, password: &str) -> Presented {
        Presented::passed(mechanism::username(), username).with_proof(evidence::PASSWORD, password)
    }

    #[test]
    fn a_real_logon_is_refused_with_the_reason_on_every_operating_system() {
        let verifier = WindowsAuthenticator::default();
        let failure = verifier
            .verify(&claim("CORP\\alice", "pencil"))
            .expect_err("refused");
        assert!(
            failure
                .message
                .starts_with("no SSPI is reachable from this build"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("pencil"));
        assert_eq!(verifier.mechanism().name(), "windows");
        assert_eq!(verifier.domain(), None);
    }

    #[test]
    fn through_the_in_process_authority_each_spelling_of_the_account_is_proven() {
        let verifier = verifier();
        assert_eq!(verifier.domain(), Some("CORP"));
        for name in ["alice", "CORP\\alice", "corp\\Alice", "alice@corp"] {
            assert_eq!(
                verifier.verify(&claim(name, "pencil")).expect("verified"),
                Verified::Proven,
                "{name}"
            );
        }
        // A claim the first gate already filed under this mechanism reads too.
        let filed = Presented::passed(mechanism::windows(), "alice")
            .with_proof(evidence::PASSWORD, "pencil");
        assert_eq!(verifier.verify(&filed).expect("verified"), Verified::Proven);
    }

    #[test]
    fn a_wrong_password_an_unknown_user_and_another_domain_are_refused_alike() {
        let verifier = verifier();
        for (name, password) in [
            ("alice", "pen"),
            ("mallory", "pencil"),
            ("OTHER\\alice", "pencil"),
        ] {
            assert_eq!(
                verifier.verify(&claim(name, password)).expect("verified"),
                Verified::Refused,
                "{name}"
            );
        }
    }

    #[test]
    fn a_disabled_account_is_refused_with_win32s_name_for_it() {
        let failure = verifier()
            .verify(&claim("retired", "pencil"))
            .expect_err("refused");
        assert_eq!(
            failure.message,
            "the host refused to log 'corp\\retired' on: ERROR_ACCOUNT_DISABLED (1331)"
        );
    }

    #[test]
    fn a_missing_proof_a_malformed_name_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::username(), "alice");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'password' proof"),
            "{}",
            failure.message
        );
        let failure = verifier()
            .verify(&claim("CORP\\", "pencil"))
            .expect_err("refused");
        assert!(
            failure.message.contains("not a Windows account name"),
            "{}",
            failure.message
        );
        let ticket = Presented::passed(mechanism::kerberos(), "alice@CORP.EXAMPLE")
            .with_proof("kerberos.ap-req", "YII=");
        let failure = verifier().verify(&ticket).expect_err("refused");
        assert!(
            failure.message.contains("'kerberos'"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn the_down_level_name_and_the_user_principal_name_log_the_same_account_on() {
        let authority = InProcess::new(64).with_account(&account("jane@partnerx"), "pencil");
        let verifier = WindowsAuthenticator::new().with_facility(authority);
        let filed = claim("PARTNERX\\Jane", "pencil")
            .with_evidence(evidence::PRINCIPAL_USER, "jane@partnerx");
        assert_eq!(verifier.verify(&filed).expect("verified"), Verified::Proven);
        let principal = claim("jane@PartnerX", "pencil");
        assert_eq!(
            verifier.verify(&principal).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn evidence_of_another_account_than_the_one_presented_is_refused_naming_both() {
        let filed =
            claim("CORP\\alice", "pencil").with_evidence(evidence::PRINCIPAL_USER, "mallory@corp");
        let failure = verifier().verify(&filed).expect_err("refused");
        assert!(
            failure.message.contains("'alice@corp'") && failure.message.contains("'mallory@corp'"),
            "{}",
            failure.message
        );
    }

    struct Registry;

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
            (mechanism == "windows" && value == "CORP\\alice").then(|| PartyId::new(9))
        }
    }

    #[test]
    fn through_the_gate_the_refusal_carries_the_reason_to_the_operator() {
        let acceptance = Acceptance::closed().accepting(&mechanism::windows());
        let filed = Presented::passed(mechanism::windows(), "CORP\\alice")
            .with_proof(evidence::PASSWORD, "pencil");

        let bound = verifier();
        let identity = authenticate(&acceptance, &[&bound], &Registry, &filed).expect("accepted");
        assert_eq!(identity.party_id, Some(PartyId::new(9)));
        assert_eq!(identity.verified, Verified::Proven);

        let unbound = WindowsAuthenticator::new();
        let refusal =
            authenticate(&acceptance, &[&unbound], &Registry, &filed).expect_err("refused");
        assert!(
            matches!(&refusal, Refusal::NotProven { detail, .. } if detail.contains(UNREACHABLE)),
            "{refusal}"
        );
    }
}
