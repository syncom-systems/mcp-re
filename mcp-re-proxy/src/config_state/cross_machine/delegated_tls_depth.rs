// SPDX-License-Identifier: Apache-2.0
//! Relation X10 — `ChannelCredentialCustody` × `ShardTopology`: the one serving topology with
//! no safe shape, refused at configuration.

use crate::config_state::channel_credential_custody::ChannelCredentialCustodyState;
use crate::config_state::custody::PrivateKeyExposure;
use crate::config_state::topology::ShardTopologyRequest;

/// X10: a channel key that cannot leave its device is not served on a single-threaded shard
/// the operator asked for.
///
/// Under `NonExporting` channel custody the handshake signature is a blocking KMS or
/// PKCS#11 round trip inside rustls' synchronous `Signer::sign`, and on a current-thread
/// runtime one such call freezes the whole core for a peer that needs no credential to
/// trigger it. An explicit `--workers-per-shard 1` asks for exactly that runtime. Serving it
/// as asked exposes the starvation; widening it serves a topology the operator stated they
/// did not want. So the pair is refused, and neither half alone is: an exported key on one
/// worker, and a delegated key on a depth the host derives, both have a safe shape.
///
/// Both facts are read from their owners' decisions — the exposure from the recognised
/// channel-custody state, the stated depth from the shard request — so nothing is
/// re-derived from the channel-key selection or `workers_per_shard` (CF-09). A custody the
/// machine refused is `None` and has its own diagnostic. The serving snapshot signs with
/// the custody this state names, because the key-source owner refuses material whose
/// exposure differs from the requested one, so no admitted deployment reaches the fleet
/// with the pair.
pub(super) fn x10(
    channel_custody: Option<&ChannelCredentialCustodyState>,
    shard_topology: ShardTopologyRequest,
) -> Vec<String> {
    let Some(custody) = channel_custody else {
        return Vec::new();
    };
    let stated_single_thread = shard_topology
        .workers_per_shard()
        .is_some_and(|depth| depth.get() == 1);
    if custody.exposure() != PrivateKeyExposure::NonExporting || !stated_single_thread {
        return Vec::new();
    }
    vec![DELEGATED_TLS_DEPTH_REFUSAL.to_string()]
}

/// X10's refusal. Names BOTH settings and BOTH ways out: a refusal that named only the
/// depth would send an operator to change the number, which is one of the two answers and
/// not necessarily the one their deployment wants.
const DELEGATED_TLS_DEPTH_REFUSAL: &str = "--workers-per-shard 1 asks for the \
    single-threaded share-nothing runtime, and this deployment's TLS custody is DELEGATED: \
    the handshake signature is a blocking KMS/PKCS#11 call inside rustls' synchronous \
    signer, so one handshake freezes the whole core — its accept loop, its established \
    connections and every in-flight request — and any peer can open one without presenting \
    a credential. Serving this as configured is the measured unauthenticated handshake \
    starvation, and widening it silently would serve a topology you did not ask for. Either \
    raise --workers-per-shard to 2 or more (or drop it for the host-derived depth), or move \
    TLS to an exported key, where the signature is in-memory and the single-threaded runtime \
    is safe.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{
        ChannelKeyRequest, DelegatedChannelKeyRequest, DeploymentRequest, Pkcs11ChannelKeyRequest,
    };

    fn pkcs11_channel(config: &mut DeploymentRequest) {
        config.channel_credential.key = ChannelKeyRequest::Delegated(
            DelegatedChannelKeyRequest::Pkcs11(Pkcs11ChannelKeyRequest {
                key_label: "tls".to_string(),
            }),
        );
    }

    /// X10 over the two owners' decisions for `mutate`d legal request.
    fn relation(mutate: impl FnOnce(&mut DeploymentRequest)) -> Vec<String> {
        let mut config = legal_config();
        mutate(&mut config);
        let (channel, _) =
            crate::config_state::channel_credential_custody::classify_and_validate(&config);
        let (_, shards) = crate::config_state::topology::classify(&config);
        x10(channel.as_ref(), shards)
    }

    /// X10 refuses the PAIR: a delegated channel key beside an operator-stated single
    /// worker is one refusal, at configuration.
    #[test]
    fn a_delegated_channel_key_on_a_stated_single_worker_is_refused() {
        let found = relation(|c| {
            pkcs11_channel(c);
            c.workers_per_shard = 1;
        });
        assert_eq!(found.len(), 1, "{:?}", found);
    }

    /// The refusal names both settings and both ways out, so an operator is not sent to
    /// change the one number when moving the key is the answer their deployment wants.
    #[test]
    fn the_depth_refusal_names_both_settings_and_both_ways_out() {
        for fragment in [
            "--workers-per-shard",
            "DELEGATED",
            "exported key",
            "2 or more",
        ] {
            assert!(
                DELEGATED_TLS_DEPTH_REFUSAL.contains(fragment),
                "{fragment}: {DELEGATED_TLS_DEPTH_REFUSAL}"
            );
        }
    }

    /// THE BOUNDARY SPLICES IT: a request built in code with the pair is refused by the
    /// layer-A boundary, with X10's sentence, so no `ValidatedDeployment` can carry it to the
    /// fleet. A relation the boundary never reads refuses nothing.
    #[test]
    fn the_boundary_refuses_the_pair_however_the_request_was_built() {
        let mut config = legal_config();
        pkcs11_channel(&mut config);
        config.workers_per_shard = 1;
        let violations = crate::config_state::validation::unsafe_config_violations(&config);
        assert!(
            violations.iter().any(|v| v == DELEGATED_TLS_DEPTH_REFUSAL),
            "{violations:?}"
        );
    }

    /// NEITHER HALF REFUSES ALONE. An exported key on one stated worker is the share-nothing
    /// runtime the operator asked for and signs in memory; a delegated key under a derived
    /// depth, or a stated depth of two or more, has a pool to absorb a blocking signature.
    /// Without this the test above is satisfied by refusing delegated custody outright, or
    /// every stated single worker.
    #[test]
    fn neither_half_of_the_refused_pair_refuses_on_its_own() {
        let exported_single = relation(|c| c.workers_per_shard = 1);
        assert!(exported_single.is_empty());
        for depth in [0, 2, 16] {
            let delegated = relation(|c| {
                pkcs11_channel(c);
                c.workers_per_shard = depth;
            });
            assert!(delegated.is_empty(), "depth {depth}: {:?}", delegated);
        }
    }
}
