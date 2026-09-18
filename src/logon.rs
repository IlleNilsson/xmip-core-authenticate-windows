//! The logon: the host facility, as a trait, with the two implementations
//! this build has.
//!
//! On Windows a username and password are proven by handing them to the
//! Security Support Provider Interface — `AcquireCredentialsHandle` and an
//! `AcceptSecurityContext` loop under Negotiate, or `LogonUser` over it —
//! which is a call into C, and `unsafe_code = "forbid"` stands in every
//! crate of the estate (ADR-0050, amendment 2026-09-16). So the facility is
//! a trait. [`Unreachable`] is what a node gets unless it is given another:
//! it refuses every logon, on every operating system, Windows included, and
//! says why. [`InProcess`] is a security authority that lives in the
//! process, which is what the tests run against and what a binding will be
//! measured against when the owner rules on where unsafe may live.

use crate::account::Account;
use authenticate::AuthenticateError;
use authenticate::store::CredentialStore;

/// Why [`Unreachable`] refuses, word for word.
pub const UNREACHABLE: &str = "no SSPI is reachable from this build";

/// What the host concluded, by the Win32 errors a logon meets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The logon held.
    Success,
    /// `ERROR_LOGON_FAILURE`: unknown user name or bad password; Windows
    /// does not say which.
    LogonFailure,
    /// `ERROR_PASSWORD_EXPIRED`: the password is right and must be changed.
    PasswordExpired,
    /// `ERROR_ACCOUNT_DISABLED`: the password is right and the account is
    /// disabled.
    AccountDisabled,
    /// `ERROR_ACCOUNT_LOCKED_OUT`: the account takes no logon for now.
    AccountLockedOut,
}

impl Outcome {
    /// The Win32 error code.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::LogonFailure => 1326,
            Self::PasswordExpired => 1330,
            Self::AccountDisabled => 1331,
            Self::AccountLockedOut => 1909,
        }
    }

    /// The Win32 name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "ERROR_SUCCESS",
            Self::LogonFailure => "ERROR_LOGON_FAILURE",
            Self::PasswordExpired => "ERROR_PASSWORD_EXPIRED",
            Self::AccountDisabled => "ERROR_ACCOUNT_DISABLED",
            Self::AccountLockedOut => "ERROR_ACCOUNT_LOCKED_OUT",
        }
    }
}

/// The host's logon facility.
pub trait Logon: Send + Sync {
    /// Log `account` on with `password`, over the network and without a
    /// desktop, and answer with what the host concluded.
    ///
    /// # Errors
    ///
    /// The facility could not be asked at all, which is not a verdict on
    /// the credential.
    fn logon(&self, account: &Account, password: &str) -> Result<Outcome, AuthenticateError>;
}

/// The facility of a build that binds none: every logon is refused with the
/// reason.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unreachable;

impl Logon for Unreachable {
    fn logon(&self, account: &Account, _password: &str) -> Result<Outcome, AuthenticateError> {
        Err(AuthenticateError::new(format!(
            "{UNREACHABLE}: binding Secur32 takes unsafe code, which the estate forbids, so \
             '{account}' was not logged on"
        )))
    }
}

/// A security authority in the process: accounts enrolled by domain and
/// user, compared without regard to case as Windows compares them, with the
/// passwords kept as the capability's salted verifiers.
#[derive(Debug)]
pub struct InProcess {
    store: CredentialStore,
    disabled: Vec<String>,
    locked_out: Vec<String>,
}

impl InProcess {
    /// An authority with no accounts, deriving verifiers with `iterations`.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self {
            store: CredentialStore::with_iterations(iterations),
            disabled: Vec::new(),
            locked_out: Vec::new(),
        }
    }

    /// Enroll `account` with `password`.
    #[must_use]
    pub fn with_account(mut self, account: &Account, password: &str) -> Self {
        self.store.insert(&account.canonical(), password);
        self
    }

    /// Disable `account`: its password still checks, and it may not log on.
    #[must_use]
    pub fn with_disabled(mut self, account: &Account) -> Self {
        self.disabled.push(account.canonical());
        self
    }

    /// Lock `account` out: no logon is taken, right password or wrong.
    #[must_use]
    pub fn with_locked_out(mut self, account: &Account) -> Self {
        self.locked_out.push(account.canonical());
        self
    }
}

impl Logon for InProcess {
    fn logon(&self, account: &Account, password: &str) -> Result<Outcome, AuthenticateError> {
        let name = account.canonical();
        if self.locked_out.contains(&name) {
            return Ok(Outcome::AccountLockedOut);
        }
        if !self.store.verify(&name, password) {
            return Ok(Outcome::LogonFailure);
        }
        if self.disabled.contains(&name) {
            return Ok(Outcome::AccountDisabled);
        }
        Ok(Outcome::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str) -> Account {
        Account::parse(name, None).expect("an account")
    }

    fn authority() -> InProcess {
        InProcess::new(64)
            .with_account(&account("CORP\\alice"), "pencil")
            .with_account(&account("CORP\\retired"), "pencil")
            .with_account(&account("CORP\\hammered"), "pencil")
            .with_disabled(&account("CORP\\retired"))
            .with_locked_out(&account("CORP\\hammered"))
    }

    #[test]
    fn the_in_process_authority_concludes_as_windows_does() {
        let authority = authority();
        let logon = |name: &str, password: &str| {
            authority
                .logon(&account(name), password)
                .expect("the authority was asked")
        };
        assert_eq!(logon("CORP\\alice", "pencil"), Outcome::Success);
        assert_eq!(logon("corp\\ALICE", "pencil"), Outcome::Success);
        assert_eq!(logon("alice@CORP", "pencil"), Outcome::Success);
        assert_eq!(logon("CORP\\alice", "Pencil"), Outcome::LogonFailure);
        assert_eq!(logon("OTHER\\alice", "pencil"), Outcome::LogonFailure);
        assert_eq!(logon("alice", "pencil"), Outcome::LogonFailure);
        assert_eq!(logon("CORP\\retired", "pencil"), Outcome::AccountDisabled);
        assert_eq!(logon("CORP\\retired", "pen"), Outcome::LogonFailure);
        assert_eq!(logon("CORP\\hammered", "pencil"), Outcome::AccountLockedOut);
    }

    #[test]
    fn an_outcome_carries_its_win32_code_and_name() {
        assert_eq!(Outcome::Success.code(), 0);
        assert_eq!(Outcome::LogonFailure.code(), 1326);
        assert_eq!(Outcome::PasswordExpired.name(), "ERROR_PASSWORD_EXPIRED");
        assert_eq!(Outcome::AccountDisabled.code(), 1331);
        assert_eq!(Outcome::AccountLockedOut.code(), 1909);
    }

    #[test]
    fn the_unreachable_facility_logs_nobody_on_and_says_why() {
        let failure = Unreachable
            .logon(&account("CORP\\alice"), "pencil")
            .expect_err("refused");
        assert!(
            failure.message.starts_with(UNREACHABLE),
            "{}",
            failure.message
        );
        assert!(
            failure.message.contains("'CORP\\alice'"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("pencil"));
    }
}
