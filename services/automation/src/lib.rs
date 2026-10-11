//! Pure M7 automation logic: workflow validation, retry/schedule policy, GitHub OIDC
//! verification and outbound-webhook primitives. No database, no HTTP server.
pub mod oidc;
pub mod retry;
pub mod schedule;
pub mod webhook;
pub mod workflow;
