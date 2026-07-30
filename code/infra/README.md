# `code/infra/` -- Docker Compose regtest stack

Six containers: three strfry relays, two LND nodes (alice, bob), and one
bitcoind on regtest. This is the substrate that B4, B7, B8, B9, B11 and the
Docker-dependent failure modes (FM-1, FM-2, FM-4, FM-5, FM-11, FM-13, FM-14,
FM-16) require.

**No mainnet. No testnet. Regtest only.** The credentials shipped under
`credentials/` are synthetic, were generated locally inside the LND containers
during the original bootstrap, and have zero monetary value. They are included
so a reviewer can bring up the L402 path on a fresh machine without re-running
bootstrap from scratch. They are not real-world keys.

For a deeper LND-on-Docker walkthrough, see `LND_GRPC_SETUP.md` and
`QUICK_START_LND_GRPC.md` in this directory.

## Layout

```
infra/
|- README.md                         # this file
|- docker-compose.yml                # 3 x strfry + 2 x LND + 1 x bitcoind
|- scripts/
|   |- bootstrap.sh                  # idempotent regtest setup (mines, funds, opens channel)
|- bootstrap_lnd_credentials.sh      # extracts admin.macaroon and tls.cert from running LND containers
|- compile_lnd_protos.sh             # regenerates the LND gRPC stubs under ../src/nostr_agent/lnd_grpc/
|- verify_relays.py                  # relay sanity check; exits non-zero if any of the three is unreachable
|- LND_GRPC_SETUP.md                 # detailed setup notes for the LND gRPC integration
|- QUICK_START_LND_GRPC.md           # short LND quick-start
|- config/
|   |- bitcoin.conf                  # regtest; rpcuser / rpcpassword for LND
|   |- strfry.conf                   # no gossip; kinds 38100..38102 allowed
|   |- lnd-alice.conf                # alice's LND config
|   |- lnd-bob.conf                  # bob's LND config
|- credentials/                      # synthetic regtest credentials, zero monetary value
    |- alice/
    |   |- admin.macaroon
    |   |- tls.cert
    |- bob/
        |- admin.macaroon
        |- tls.cert
```

All commands below assume the current working directory is `code/` (one level
up from here).

## Bring it up

```bash
docker compose -f infra/docker-compose.yml up -d           # pull images, start containers
bash infra/scripts/bootstrap.sh                            # mine blocks, fund channels, open alice <-> bob
uv run python infra/verify_relays.py                       # 9 checks; exit 0 iff all three relays accept kinds 38100..38102
```

`bootstrap.sh` is idempotent: re-running it on a partially-initialised stack
brings up the missing pieces and is a no-op when everything is already in
place. It also handles the Bitcoin Core v27+ explicit-wallet-creation step
internally (`bitcoin-cli createwallet "default"`), so no separate command
is needed.

The container images (`lncm/bitcoind:v27.0`, `lightninglabs/lnd:v0.18.4-beta`,
`dockurr/strfry:1.0.4`) are pulled from Docker Hub as multi-architecture
manifests. Docker auto-selects the right variant for macOS Apple Silicon
(arm64) and Linux x86_64 (amd64) without a hardcoded `platform:` override.

## Tear it down

```bash
docker compose -f infra/docker-compose.yml down            # stops containers, preserves volumes
docker compose -f infra/docker-compose.yml down -v         # stops containers AND removes volumes (clean slate)
```

The `-v` is intentional whenever benchmark medians shift between runs: a stale
chain or stale LND state is the most common cause of B9 and FM-4 producing
different numbers across runs. Always start clean when reproducing.

## What runs where

| Container | Role | Host port |
| --- | --- | --- |
| `nostragent-bitcoind` | Bitcoin Core v27 on regtest | 18443 (RPC) |
| `nostragent-lnd-alice` | LND v0.18.4-beta | 10009 (gRPC), 8080 (REST) |
| `nostragent-lnd-bob` | LND v0.18.4-beta | 10010 (gRPC), 8081 (REST) |
| `nostragent-relay-1` | strfry Nostr relay | 7771 |
| `nostragent-relay-2` | strfry Nostr relay | 7772 |
| `nostragent-relay-3` | strfry Nostr relay | 7773 |

All ports bind to loopback. Nothing in this stack listens on the public
network.

## Why credentials are shipped

The L402 gRPC integration test and B9 both authenticate against LND using
`admin.macaroon` and `tls.cert`. Generating these from scratch requires running
`bootstrap_lnd_credentials.sh` against the running containers and waiting for
LND to finish key generation. Shipping the credentials saves an evaluator that
step and removes a class of "macaroon not found" failures that otherwise look
like real bugs.

These credentials authenticate to the local regtest LND nodes only. They cannot
be used against mainnet, against another testnet LND, or against any real
Lightning channel. The bitcoind they ultimately point at is regtest, which
mines on demand and has no monetary value.

If a reviewer prefers to regenerate the credentials from scratch:

```bash
rm -rf infra/credentials/
docker compose -f infra/docker-compose.yml down -v
docker compose -f infra/docker-compose.yml up -d
bash infra/bootstrap_lnd_credentials.sh
```

## Compile LND gRPC stubs

Pre-compiled gRPC stubs ship under `../src/nostr_agent/lnd_grpc/*_pb2*.py`. If
they are missing or corrupted, regenerate from the LND `.proto` definitions:

```bash
bash infra/compile_lnd_protos.sh
```

The generated stubs retain LND's MIT license. The license header is preserved
inside each generated file.

## Common failures and fixes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `verify_relays.py` exits non-zero | strfry container did not finish starting before the check | wait a few seconds and retry; if persistent, `docker compose logs nostragent-relay-1` |
| B9 hangs at "waiting for invoice" | the alice -> bob channel did not open during bootstrap | `docker compose -f infra/docker-compose.yml down -v && docker compose -f infra/docker-compose.yml up -d && bash infra/scripts/bootstrap.sh` |
| `ImportError` for `lightning_pb2` or `router_pb2` | LND proto stubs missing | `bash infra/compile_lnd_protos.sh` |
| `macaroon not found` | credentials volume mount path wrong | confirm `infra/credentials/{alice,bob}/{admin.macaroon,tls.cert}` exist on host |
| Bootstrap fails with "No wallet is loaded" | bitcoind container started but the wallet step did not run (rare, would only happen if `bootstrap.sh` was interrupted) | `docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default"`, then re-run `bash infra/scripts/bootstrap.sh` |
| Slow B9 / B11 medians | first cold-start of the LND container takes longer | the warm-up window in `benchmark_config.py` already accounts for this. Discard the first run if running ad-hoc |

## Determinism

The bootstrap script seeds the wallet HD path deterministically and mines a
fixed number of blocks before opening the alice-bob channel. This makes the
on-chain state of regtest identical across clean runs and is what lets B9
reproduce within IQR across machines.

## Pointers

- Code overview: `../README.md`
- Reproduction guide (claim -> command map): `../../REPRODUCE.md`
- Python implementation: `../src/nostr_agent/`
- Evaluation harness: `../eval/`
