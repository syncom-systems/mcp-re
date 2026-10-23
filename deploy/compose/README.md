<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reference deployment: Docker Compose

One `mcp-re-proxy` (the official image from GHCR) in front of your Streamable-HTTP MCP server,
and the Redis it needs as its replay store. This is a small single-host reference; the
Kubernetes fleet is in [`deploy/helm`](../helm/mcp-re-proxy).

Nothing in it is a default you can run unchanged. It ships no credentials, generates no
production trust anchors, and the proxy refuses unsafe configuration by name.

## What you provide

| what | where | notes |
| --- | --- | --- |
| identity of this server | `.env`: `MCP_RE_AUDIENCE`, `MCP_RE_TARGET_URI`, `MCP_RE_TRUST_DOMAIN`, `MCP_RE_SERVER_KEY_ID`, `MCP_RE_TRUST_EPOCH` | must equal what your clients sign; the `did:example:` / `example.com` placeholders are refused |
| your MCP backend | `.env`: `MCP_RE_INNER_URL` | a Streamable-HTTP endpoint the proxy container can reach; a stdio-only server needs an external adapter |
| Redis password | `.env`: `REDIS_PASSWORD` | `openssl rand -hex 24` |
| key material | `secrets/server/`: `signing.seed`, `server-key.pem`, `server-chain.pem`, `client-ca.pem`, `trust.json` | from your own CA and key management; mode `0600`, owned by the uid in `MCP_RE_UID` |
| image version | `.env`: `MCP_RE_VERSION` | an immutable tag, for example `0.19.0` |

The proxy refuses key files that anyone but their owner can read. The container runs as uid
65532 unless `MCP_RE_UID` / `MCP_RE_GID` say otherwise, so either `chown 65532` the files or run
the container as their owner.

## Evaluate it in two minutes

```sh
cd deploy/compose
./dev-pki.sh                     # THROWAWAY CA, server cert, signing seed, one 1-hour client cert
cp env.example .env              # edit: REDIS_PASSWORD, MCP_RE_VERSION, MCP_RE_INNER_URL, and
                                 # add the MCP_RE_UID / MCP_RE_GID lines dev-pki.sh printed
docker compose up -d
./verify.sh ready                # mTLS completes; an unsigned request is refused (HTTP 403)
./verify.sh closed               # a connection with no client certificate is refused
```

`dev-pki.sh` is for evaluation only. Its client certificate lives one hour (the proxy's
`--max-client-cert-lifetime` ceiling); `./dev-pki.sh client` issues another.

## Operate

| task | command |
| --- | --- |
| readiness | `./verify.sh ready`, or the log line `async fleet serving on 0.0.0.0:8600` in `docker compose logs proxy` |
| restart | `docker compose restart proxy` (admitted replay nonces survive in the `redis-data` volume) |
| upgrade | set `MCP_RE_VERSION` to the new tag, then `docker compose pull && docker compose up -d` |
| uninstall | `docker compose down --volumes` removes the containers, network and replay state |
| inspect | `docker compose logs proxy`: the startup transcript states every posture, including those that are off |

## Persistent state

Only Redis holds state: the admitted request nonces (`appendonly yes`, volume `redis-data`).
Losing it re-opens the replay window for the freshness interval, which is why it persists and
why it must run with `maxmemory-policy noeviction`, as it does here and as the proxy checks.
The proxy container is read-only and keeps nothing. Redis is on the compose network only and
not published.

## What this single-host reference leaves out

It does not wire the push trust-epoch source or key-revocation reload, so a revoked request
signer is dropped on the next restart, not live, and the trust epoch advances only by changing
`MCP_RE_TRUST_EPOCH` and restarting. The proxy's startup transcript says so. Fleet revocation,
KMS custody and TLS to Redis are in the [fleet guide](../../docs/fleet-deployment-guide.md) and
the Helm chart.
