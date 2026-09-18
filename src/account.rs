//! The account a Windows logon names: a user, and the domain that knows it.
//!
//! A name arrives in one of three shapes. `CORP\alice` is the down-level
//! logon name, domain first. `alice@corp.example` is a user principal name,
//! domain last. A bare `alice` names no domain, and is looked up in the one
//! the authenticator was configured with, or on the host itself where none
//! was. Windows compares both halves without regard to case.

use authenticate::AuthenticateError;
use std::fmt;

/// A user and the domain it is looked up in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// The domain, or `None` for an account of the host itself.
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
    /// The user or a written domain is empty, or the name has more than one
    /// backslash or at-sign in it.
    pub fn parse(name: &str, default_domain: Option<&str>) -> Result<Self, AuthenticateError> {
        let malformed = || {
            AuthenticateError::new(format!(
                "'{name}' is not a Windows account name: DOMAIN\\user, user@domain or user"
            ))
        };
        let (domain, user) = if let Some((domain, user)) = name.split_once('\\') {
            (Some(domain), user)
        } else if let Some((user, domain)) = name.split_once('@') {
            (Some(domain), user)
        } else {
            (default_domain, name)
        };
        let stray = |text: &str| text.contains(['\\', '@']);
        if user.is_empty() || stray(user) || domain.is_some_and(|d| d.is_empty() || stray(d)) {
            return Err(malformed());
        }
        Ok(Self {
            domain: domain.map(str::to_string),
            user: user.to_string(),
        })
    }

    /// The account in one case-folded form, `domain\user`, with `.` for the
    /// host itself — what two spellings of one account share.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{}\\{}",
            self.domain.as_deref().unwrap_or(".").to_lowercase(),
            self.user.to_lowercase()
        )
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
        assert_eq!(down_level.domain.as_deref(), Some("CORP"));
        assert_eq!(down_level.user, "alice");
        assert_eq!(down_level.to_string(), "CORP\\alice");

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
    fn what_is_not_an_account_name_is_refused_by_name() {
        for name in [
            "", "CORP\\", "\\alice", "@corp", "alice@", "A\\B\\c", "a@b@c",
        ] {
            let failure = Account::parse(name, Some("CORP")).expect_err("refused");
            assert!(
                failure.message.contains("is not a Windows account name"),
                "{name}: {}",
                failure.message
            );
        }
    }
}
