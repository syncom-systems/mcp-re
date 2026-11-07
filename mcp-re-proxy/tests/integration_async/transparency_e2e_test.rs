// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPRE-054 vertical, end to end, from a served call to an offline-verifiable
//! receipt.
//!
//! ```text
//! signed request -> HttpProfileProxy (delegated-required, retention ON)
//!   -> the exchange is RETAINED before the response goes out
//!   -> auditor: reconstruct_chain over the retained hop
//!   -> issue_signed_statement committing to the reconstruction
//!   -> register with a transparency service -> Receipt
//!   -> verify_receipt_offline + verify_retained_evidence, contacting nobody
//! ```
//!
//! Until this wiring the whole SCITT surface was reachable only from tests, conformance
//! vectors and interop harnesses: nothing on the serving path produced a statement,
//! reconstructed a chain, or retained anything, so `retained_evidence.rs` was dead code
//! inside the serving crate. This lane is the production caller.
//!
//! The transparency service here is `PrototypeTransparencyService` — an in-process
//! Merkle log, NOT a running SCITT Transparency Service. Registering against a real one
//! is ADR-MCPRE-054's remaining external dependency. What this proves without one is
//! everything either side of that hop: that a served call is retained, that the
//! reconstruction and the statement are about the retained bytes, and that the receipt
//! verifies offline.

mod attestation;
mod audit_run;
mod auditor;
mod fixtures;
mod live;
mod registration;
mod retention;
mod server;
mod service;
