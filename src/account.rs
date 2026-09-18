//! The account a Windows logon names: a user, and the domain that knows it.
//!
//! A name arrives in one of three shapes. `CORP\alice` is the down-level
//! logon name, domain first. `alice@corp.example` is a user principal name,
//! domain last. Both are read by the identify capability's
//! `UserPrincipalName` and by nothing here (ADR-0054). A bare `alice` names
//! no domain, and is looked up in the one the authenticator was configured
//! with, or on the host itself where none was. Windows compares both halves
//! without regard to case.

use authenticate::AuthenticateError;
use identify::UserPrincipalName;
use std::fmt;

/// A user and the domain it is looked up in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// The domain, in the lower case a principal name is written in, or
    /// `None` for an account of the host itself.
    pub domain: Option<String>,
    /// The user, as it was written.
    pub user: String,
}

impl Account {
    /// Read a presented name, falling back to `default_domain` where the
    /// name carries none.
    ///
    /// # Errors
    ///
    /// The name holds a backslash or an at-sign and is not a user principal
    /// name, a bare user is empty or holds a slash, or `default_domain` is
    /// not a domain.
    pub fn parse(name: &str, default_domain: Option<&str>) -> Result<Self, AuthenticateError> {
        if let Some(principal) = UserPrincipalName::parse(name) {
            return Ok(Self::from(&principal));
        }
        let user = name.trim();
        if user.is_empty() || user.contains(['\\', '@', '/']) {
            return Err(AuthenticateError::new(format!(
                "'{name}' is not a Windows account name: DOMAIN\\user, user@domain or user"
            )));
        }
        let Some(domain) = default_domain else {
            return Ok(Self {
                domain: None,
                user: user.to_string(),
            });
        };
        UserPrincipalName::of(user, domain)
            .map(|principal| Self::from(&principal))
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "'{domain}' is not a domain the bare name '{name}' can be looked up in"
                ))
            })
    }

    /// The account as a user principal name, where it is in a domain. An
    /// account of the host itself is not one.
    #[must_use]
    pub fn principal(&self) -> Option<UserPrincipalName> {
        UserPrincipalName::of(&self.user, self.domain.as_deref()?)
    }

    /// Whether another name is the same account: by the capability's own
    /// question where both are in a domain, and by the user without regard
    /// to case where both are the host's.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        match (self.principal(), other.principal()) {
            (Some(ours), Some(theirs)) => ours.is(&theirs),
            (None, None) => self.user.eq_ignore_ascii_case(&other.user),
            _ => false,
        }
    }

    /// The account in one case-folded form, `domain\user`, with `.` for the
    /// host itself — what two spellings of one account share.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{}\\{}",
            self.domain.as_deref().unwrap_or("."),
            self.user.to_lowercase()
        )
    }
}

impl From<&UserPrincipalName> for Account {
    fn from(principal: &UserPrincipalName) -> Self {
        Self {
            domain: Some(principal.domain().to_string()),
            user: principal.user().to_string(),
        }
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.domain {
            Some(domain) => write!(f, "{domain}\\{}", self.user),
            None => f.write_str(&self.user),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_read_in_each_of_its_three_shapes() {
        let down_level = Account::parse("CORP\\alice", None).expect("read");
        assert_eq!(down_level.domain.as_deref(), Some("corp"));
        assert_eq!(down_level.user, "alice");
        assert_eq!(down_level.to_string(), "corp\\alice");

        let principal = Account::parse("alice@corp.example", Some("OTHER")).expect("read");
        assert_eq!(principal.domain.as_deref(), Some("corp.example"));
        assert_eq!(principal.user, "alice");

        let bare = Account::parse("alice", Some("CORP")).expect("read");
        assert_eq!(bare, down_level);
        let local = Account::parse("alice", None).expect("read");
        assert_eq!(local.domain, None);
        assert_eq!(local.to_string(), "alice");
    }

    #[test]
    fn two_spellings_of_one_account_share_a_canonical_form() {
        let upper = Account::parse("CORP\\Alice", None).expect("read");
        let lower = Account::parse("alice", Some("corp")).expect("read");
        assert_eq!(upper.canonical(), "corp\\alice");
        assert_eq!(upper.canonical(), lower.canonical());
        let local = Account::parse("Alice", None).expect("read");
        assert_eq!(local.canonical(), ".\\alice");
    }

    #[test]
    fn the_down_level_name_and_the_user_principal_name_are_the_same_account() {
        let down_level = Account::parse("PARTNERX\\jane", None).expect("read");
        let principal = Account::parse("Jane@partnerx", None).expect("read");
        let bare = Account::parse("JANE", Some("PartnerX")).expect("read");
        assert!(down_level.is(&principal));
        assert!(principal.is(&bare));
        let name = down_level.principal().expect("in a domain");
        assert_eq!(name.to_string(), "jane@partnerx");

        let local = Account::parse("jane", None).expect("read");
        assert_eq!(local.principal(), None);
        assert!(local.is(&Account::parse("Jane", None).expect("read")));
        assert!(
            !local.is(&down_level),
            "the host's jane is not the domain's"
        );
        let elsewhere = Account::parse("jane@other", None).expect("read");
        assert!(!down_level.is(&elsewhere));
    }

    #[test]
    fn what_is_not_an_account_name_is_refused_by_name() {
        for name in ["", "CORP\\", "\\alice", "@corp", "alice@", "A\\B\\c", "a/b"] {
            let failure = Account::parse(name, Some("CORP")).expect_err("refused");
            assert!(
                failure.message.contains("is not a Windows account name"),
                "{name}: {}",
                failure.message
            );
        }
        // The last at-sign divides, so a user part may hold one (ADR-0054).
        let guest = Account::parse("a@b@c", Some("CORP")).expect("read");
        assert_eq!(
            (guest.user.as_str(), guest.domain.as_deref()),
            ("a@b", Some("c"))
        );
        let failure = Account::parse("alice", Some("not a domain")).expect_err("refused");
        assert!(
            failure.message.contains("'not a domain' is not a domain"),
            "{}",
            failure.message
        );
    }
}
