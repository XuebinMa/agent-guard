//! Content-layer validation (S6-1 spike).
//!
//! Where `bash` and `path` guard the *action* an agent is about to take, this
//! module inspects the *content* an agent is about to emit — the second half of
//! agent-guard's two-layer outbound model. The first proof point is detecting
//! credentials/secrets in text before it leaves for an LLM provider or a
//! mutation HTTP call.
//!
//! This is a feasibility PoC: it is gated behind the off-by-default `content`
//! feature and is intentionally *not* wired into the `Guard` pipeline yet.

pub mod secrets;

pub use secrets::{scan, SecretFinding, SecretKind};
