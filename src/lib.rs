#![forbid(unsafe_code)]
//! Authenticate by windows: verifies the credential through the host's SSPI, refusing where
//! there is none.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authenticator` (ADR-0050).
