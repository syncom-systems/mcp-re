// SPDX-License-Identifier: Apache-2.0
//! Authoritative layer-A rules whose semantic OWNER has not been ruled.
//!
//! Residue means exactly one thing here:
//!
//! > an authoritative layer-A rule that the boundary must enforce, and for which no
//! > narrower owner has yet been ruled.
//!
//! It does not mean "miscellaneous validation we did not know where to put". Every entry
//! below states three things in its doc comment — the proposition it enforces, why layer A
//! is where it must be enforced, and why no narrower owner currently claims it. An entry
//! that cannot state the third belongs in a machine, not here.
//!
//! This file is an architectural work queue. Each function is meant to LEAVE, one at a
//! time, when an owner is ruled for it; what must not happen is the set growing back into
//! one anonymous function whose contents nobody can count. That is what [`INVENTORY`] and
//! its self-check are for: the inventory is derived from this file's own source, so a rule
//! added without registering it fails the build rather than joining a junk drawer.
//!
//! Nothing here decides precedence. `legality_violations` calls each of these at the
//! position its clauses already occupied.

use crate::deployment_request::{AuthzKind, DeploymentRequest, OnlineRevocationEvidenceRequest};

/// The one decision about whether a configured authorization profile can be honored.
///
/// `Some(diagnostic)` means it cannot. Two independent facts make it so, and the
/// diagnostic carries both because an operator needs both to know what to do:
///
/// - the reference profile is a CONFORMANCE implementation, never accepted as the production
///   authority (ADR-MCPS-013), and it was bound to the object carrier ADR-MCPRE-050 retired;
/// - it names no mechanism this build can install: the production mechanism is the carried
///   PDP decision (ADR-MCPRE-065 §8), which `--authz pdp-decision` selects instead.
///
/// Either alone is sufficient to refuse. A configured policy that would silently not
/// enforce is the forbidden-claim shape (security-boundary §2).
///
/// One function because this prohibition was once stated TWICE, in two places, with two
/// different messages: in `parse_args` and in the composition root. Neither was at the
/// validation boundary. That was not a bypass — the composition root did catch a
/// programmatically built `DeploymentRequest` — but two independent statements of one prohibition can
/// drift, and a policy decision does not belong in a composition root (ADR-MCPRE-056 §12).
fn unaccepted_authz_profile_refusal(authz: AuthzKind) -> Option<String> {
    (authz == AuthzKind::Reference).then(|| {
        "--authz reference selects the reference/conformance signed-authorization \
         profile, which is NOT accepted as the production authorization authority \
         (ADR-MCPS-013) and was bound to the object carrier this release retired. The \
         production mechanism is the carried PDP decision, selected with \
         --authz pdp-decision (ADR-MCPRE-065). Run that, or --authz off."
            .to_string()
    })
}

/// The one decision about whether `--client-ocsp require` can be honored.
///
/// `Some(diagnostic)` means it cannot. Today that is unconditional, and the reason is a
/// property of the SERVING PATH rather than of the build: `ocsp_rejection` is reached only
/// from `connection_rejection`, which only the blocking serve loops call. The production
/// data plane is the per-core async fleet (ADR-MCPRE-051 §1), which calls
/// `connection_rejection_for_chain` and performs only the offline cert-lifetime and CRL
/// checks. So the responder round trip never happens, with or without the `online_ocsp`
/// feature — without it the code is absent, with it the code is present but never called.
///
/// Accepting it would announce `ONLINE OCSP client-cert revocation enabled` at startup on
/// a deployment that admits every revoked client certificate: the forbidden-claim shape
/// (security-boundary §2). The refusal lifts when the async path performs the round trip
/// off the runtime worker, and this is the single place that would have to change.
///
/// A function rather than an inline condition because it is what
/// [`unsafe_config_violations`] consults, and that is what a programmatically built
/// `DeploymentRequest` meets. Two copies is how the two drifted in the first place: the
/// parser refused, the validation boundary did not, and a caller that skipped the parser
/// reached the serving path with the claim intact.
fn online_ocsp_refusal(online: &OnlineRevocationEvidenceRequest) -> Option<String> {
    online.is_required().then(|| {
        "--client-ocsp require cannot be honored: online OCSP is implemented only on \
         the blocking serve loop, while the production data plane is the per-core \
         async fleet, which performs no OCSP revocation check. Accepting it would \
         announce enforcement that does not happen. Use --client-crl (with \
         --client-crl-reload-secs for restart-free refresh) for client-certificate \
         revocation on the async serving path."
            .to_string()
    })
}

/// The AIA-override responder, held to its own shape and then to the mode that reads it.
///
/// `--ocsp-responder-url` is the one OCSP parameter, and it parameterizes a mode rather
/// than naming a state, so it has no machine of its own; these are its two columns in the
/// order semantic dependency puts them. A responder that names nothing is a defect in the
/// value; a responder no mode will read is a defect in the combination, and only the second
/// depends on the online-evidence selection.
///
/// The second clause is GONE and its absence is the result. It refused a responder beside
/// `--client-ocsp off` — an authority nothing would ever ask, left where an operator could
/// believe one was configured. The responder now travels inside
/// [`OnlineRevocationEvidenceRequest::Required`], so the combination cannot be built
/// (ADR-MCPRE-067 §7); the argv form is answered by `cli::revocation_flags`.
///
/// What survives is the clause about the VALUE, which is intra-mechanism: a responder that
/// names nothing replaces a resolvable authority with none.
fn ocsp_responder_violations(config: &DeploymentRequest) -> Vec<String> {
    let Some(url) = config.peer_revocation.online.responder_override() else {
        return Vec::new();
    };
    if url.trim().is_empty() {
        return vec![
            "--ocsp-responder-url is empty: it overrides the responder named by the \
             certificate's AIA extension, so an empty value replaces a resolvable authority \
             with none"
                .to_string(),
        ];
    }
    Vec::new()
}

/// `--client-ocsp require` cannot be honored.
///
/// **Why layer A enforces it.** The selection is a public field, so a request built in
/// code reaches the serving path announcing revocation checking that never happens.
///
/// **Why no narrower owner.** It is client-certificate revocation, but CRL and OCSP are different mechanisms: if CRL support were removed tomorrow this rule would still hold, because the async data plane performs no responder round trip. `CrlRevocation` is therefore not its owner, and no OCSP state exists because every OCSP posture is excluded.
pub(super) fn ocsp_mode_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(refusal) = online_ocsp_refusal(&config.peer_revocation.online) {
        out.push(refusal);
    }
    out
}

/// A responder URL must name something, and something must read it.
///
/// **Why layer A enforces it.** A responder configured beside a mode that never consults one leaves an operator believing a revocation authority is in force.
///
/// **Why no narrower owner.** Same as the mode it parameterizes: it belongs to whatever owner OCSP eventually gets.
pub(super) fn ocsp_responder_url_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(ocsp_responder_violations(config));
    out
}

/// `--authz reference` is not an accepted production authorization authority.
///
/// **Why layer A enforces it.** Accepting it would surface a capability the serving path does not deliver.
///
/// **Why no narrower owner.** A LOCAL degenerate-posture refusal. X6 mentions `Authz` only because `Authz` is degenerate; colocating there would let a local refusal acquire cross-machine relation semantics.
pub(super) fn authz_profile_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(refusal) = unaccepted_authz_profile_refusal(config.authorization.kind) {
        out.push(refusal);
    }
    out
}

/// `--audience` names something.
///
/// **Why layer A enforces it.** It is the audience a verifier binds a response to, and
/// nothing dereferences it — an empty one fails no startup step and simply makes this
/// deployment's evidence indistinguishable from any other deployment that also set none.
///
/// **Why no narrower owner.** It is consumed as an ordinary audience PARAMETER — into
/// `AudienceTuple` beside `--target-uri` and `--route`, and into `CustodyConfig::aud` — not
/// as part of an identity. `ServerIdentity` deliberately does not take it: grouping it with
/// the identity coordinates because they were validated together is how a validation
/// location gets mistaken for an owner. `DelegatedSigning` guards the RESOLVED
/// `audience_hash` that this may default into, which is a different proposition.
pub(super) fn audience_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.audience.trim().is_empty() {
        out.push(
            "--audience is empty: it is the audience verifiers bind a response to, so an \
             empty one makes this deployment's evidence indistinguishable from that of any \
             other deployment that also set none"
                .to_string(),
        );
    }
    out
}

/// The three locators this deployment opens are non-empty.
///
/// **Why layer A enforces it.** That a string names nothing is purely knowable (ADR-MCPRE-056 §5.1); that the file is absent is an observation for materialization.
///
/// **Why no narrower owner.** They span the listener and the TLS plane — no single existing machine owns the set, and inventing one to hold three strings would be the premature abstraction. `--trust` was the fourth until it acquired one: `TrustDocumentSource` exists because a `TrustPlan` has to pair the locator with a sealed revocation posture, which is a reason none of these three have.
pub(super) fn required_locator_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    for (value, message) in [
        (
            config.bind.as_str(),
            "--bind is empty: it names the address this proxy listens on, and an empty value \
             resolves to no address rather than to a default",
        ),
        (
            config.channel_credential.credential_chain.as_str(),
            "--tls-cert is empty: it names the server certificate chain presented on every \
             handshake",
        ),
        (
            config.peer_trust_anchors.as_str(),
            "--client-ca is empty: it names the roots every client certificate is verified \
             against, which is the whole of who may connect",
        ),
    ] {
        if value.trim().is_empty() {
            out.push(message.to_string());
        }
    }
    out
}

/// A deployment names at least one inner server.
///
/// **Why layer A enforces it.** It arrived here from the trust plane, which could reject it only after two planes had established resources.
///
/// **Why no narrower owner.** There is no inner-plane machine; the request carries a list and nothing classifies it into states.
pub(super) fn inner_plane_presence_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.inner_http_urls.expose().is_empty() {
        out.push(
            "the proxy serves over an async HTTP inner plane: pass --inner-http-url <url>. To \
             protect a local stdio MCP server, run it behind the mcp-re-stdio-bridge adapter \
             and point --inner-http-url at the bridge."
                .to_string(),
        );
    }
    out
}

/// No inner-server URL is blank.
///
/// **Why layer A enforces it.** A list holding `""` satisfies the presence clause and then contributes a backend the pool can never reach — a trailing comma produces exactly that.
///
/// **Why no narrower owner.** Same absent owner as the presence clause it follows.
pub(super) fn inner_plane_structure_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config
        .inner_http_urls
        .expose()
        .iter()
        .any(|url| url.trim().is_empty())
    {
        out.push(
            "--inner-http-url contains an empty URL: every backend in the inner plane must \
             name one, or the pool carries a member no request can be forwarded to"
                .to_string(),
        );
    }
    out
}

/// Every ownerless obligation in this file, by name.
///
/// Hand-maintained lists drift, so this one is CHECKED against the file it describes
/// rather than trusted. Any count that appears in prose or a commit message should be
/// derived from here — `INVENTORY.len()` — and never typed.
/// Compiled only for the self-check: it exists to be COMPARED with this file, not to be
/// read at runtime. A residue rule is invoked by name from the orchestrator, so nothing in
/// the shipped binary needs the list — only the test that keeps it honest does.
#[cfg(test)]
pub(super) const INVENTORY: &[&str] = &[
    "ocsp_mode_violations",
    "ocsp_responder_url_violations",
    "authz_profile_violations",
    "audience_violations",
    "required_locator_violations",
    "inner_plane_presence_violations",
    "inner_plane_structure_violations",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_build_admits_the_online_ocsp_mode() {
        let refusal = online_ocsp_refusal(&OnlineRevocationEvidenceRequest::Required(
            crate::deployment_request::OcspResponderRequest::default(),
        ))
        .expect("--client-ocsp require is refused in every build");
        assert!(
            refusal.contains("--client-ocsp require cannot be honored"),
            "the refusal must name the flag it refuses, got: {refusal}"
        );
        assert!(
            refusal.contains("--client-crl"),
            "and it must name the mechanism that does work on the async plane: {refusal}"
        );
        assert!(
            online_ocsp_refusal(&OnlineRevocationEvidenceRequest::NotRequired).is_none(),
            "the OFF posture is the one the legality model admits"
        );
    }

    /// THM-0013 evidence, half two: the refusal is on the route to a validated deployment.
    ///
    /// The predicate above could be correct and unreached. This asserts it through
    /// `ocsp_mode_violations`, which is what the boundary's clause list calls, so what is
    /// measured is the rule's PLACEMENT and not only its content. Together the two halves
    /// give the theorem: every validated deployment has online OCSP off.
    #[test]
    fn the_boundary_clause_carries_the_online_ocsp_refusal() {
        let mut config = crate::config_state::test_support::legal_config();
        assert!(
            ocsp_mode_violations(&config).is_empty(),
            "the legal fixture does not request online OCSP"
        );
        config.peer_revocation.online = OnlineRevocationEvidenceRequest::Required(
            crate::deployment_request::OcspResponderRequest::default(),
        );
        let violations = ocsp_mode_violations(&config);
        assert_eq!(
            violations.len(),
            1,
            "exactly one clause answers for the mode: {violations:?}"
        );
        assert!(violations[0].contains("--client-ocsp require cannot be honored"));
    }

    /// The inventory names exactly the residue rules this file defines.
    ///
    /// Reads its own source at compile time, so adding a `pub(super) fn` without
    /// registering it — or registering one that no longer exists — fails here. Without
    /// this the inventory would be prose about the code rather than a statement of it,
    /// which is the drift this whole campaign keeps finding.
    #[test]
    fn the_inventory_is_the_file() {
        let source = include_str!("residue.rs");
        let defined: Vec<&str> = source
            .lines()
            .filter_map(|l| l.strip_prefix("pub(super) fn "))
            .filter_map(|l| l.split('(').next())
            .collect();
        assert_eq!(
            defined, INVENTORY,
            "the residue inventory and the functions defined in residue.rs have diverged"
        );
        assert!(
            !INVENTORY.is_empty(),
            "an empty inventory would make this test vacuous"
        );
    }
}
