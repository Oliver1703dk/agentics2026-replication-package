# NostrAgent

Reference implementation, evaluation harness, and expert-panel data for:

> **NostrAgent: A Decentralized Identity and Delegation Architecture for Sovereign Agentic Systems**  
> Oliver Aleksander Larsen and Mahyar Tourchi Moghaddam  
> Accepted as a Full Paper at AIPAA 2026 (AGENTICS / IJCCI 2026).

NostrAgent is an *operator-sovereign* identity and delegation architecture for
autonomous agents, built on BIP340 Schnorr signatures, Nostr relays for
discovery, scoped delegation chains with attenuation, peer attestation trust
graphs, and Lightning L402 for unified identity-payment flows. No registration
authority. No centralized identity provider. Relays are transport, not trust root.

This repository is the artifact accompanying the paper: code, tests, benchmarks,
frozen evaluation results, ATAM mini-Delphi expert-panel data, and the Docker
infrastructure required to reproduce every quantitative claim in Section 5.

---

## Status


|         |                                                            |
| ------- | ---------------------------------------------------------- |
| Stage   | Camera-ready artifact: AIPAA 2026 Full Paper (AGENTICS / IJCCI 2026), paper #8 |
| Authors | Oliver Aleksander Larsen, Mahyar Tourchi Moghaddam (SDU Software Engineering) |
| License | MIT for code; CC BY 4.0 for data and prose. See `LICENSE`. |
| DOI     | Zenodo DOI to be minted from GitHub release `v1.0`         |
| Tag     | `v1.0` marks this camera-ready snapshot                    |


The paper Data Availability section points at this repository
(`https://github.com/Oliver1703dk/agentics2026-replication-package`)
and will add the Zenodo DOI once minted.

---

## Contents

```
nostragent/
|- README.md          # this file
|- LICENSE            # MIT + CC BY 4.0
|- REPRODUCE.md       # paper-claim -> exact command map  <- read this to reproduce results
|
|- code/              # Python prototype, 438-item test suite, evaluation harness, and Docker infra
|   |- src/nostr_agent/   # the package
|   |- tests/             # unit, property, adversarial, integration
|   |- eval/              # benchmark + sensitivity + failure-mode harness; frozen results under eval/results/
|   |- infra/             # Docker Compose stack (strfry relays + LND + bitcoind) and regtest credentials
|- atam/              # mini-Delphi expert-panel data: briefing, rating instrument, raw ratings, alpha + kappa recomputation
```

Each subdirectory has its own `README.md` describing what is there and how to
run it.

---

## Prerequisites

- Docker 24+ with Compose v2
- Python 3.11+
- `uv` for Python environment management (Astral's Python package manager)
- macOS Apple Silicon or Linux x86_64 (other platforms untested)
- ~10 GB free disk for the Docker images and benchmark outputs
- No network access required at run time except to pull Docker images on first use; the Lightning side runs on regtest and never touches mainnet

---

## Quick start

```bash
cd code

# 1. Install Python dependencies
uv sync --python 3.11 --extra dev

# 2. Bring up the regtest infrastructure (strfry relays + LND + bitcoind)
docker compose -f infra/docker-compose.yml up -d
docker exec nostragent-bitcoind bitcoin-cli -regtest -rpcuser=nostr -rpcpassword=nostr createwallet "default" 2>/dev/null || true
bash infra/scripts/bootstrap.sh
uv run python infra/verify_relays.py

# 3. Run the full evaluation: B1..B11 benchmarks, SP-1..SP-5 sensitivity sweeps, and the 17 empirical failure-mode tests
uv run python -m eval.run_full_evaluation
```

Or run everything in one shot with the bundled script:

```bash
cd code && bash reproduce.sh
```

Results land under `code/eval/results/<UTC_TIMESTAMP>/`. See `REPRODUCE.md` for
the mapping from each paper claim to its exact command and output file.

---

## What the prototype covers

- **Kind 38100** Agent Identity Declaration events, with `next_key_hash` (SHA256 of the next rotation pubkey) committed at publication time so a future rotation can be verified against the prior commitment
- **Kind 38101** Delegation Chain events with seven enforced attenuation invariants
- **Kind 38102** Peer Attestation events feeding a bounded-sum / noisy-OR trust graph (decay d = 0.5, depth limit 4)
- **Key rotation** with pre-committed next-key recovery
- **Multi-relay discovery** and cross-relay consistency verification
- **L402 unified flow** on regtest Lightning: macaroon issuance, attenuation, payment proof, and the 5-check verification

Out of scope for the prototype, deliberately: production hardening, monitoring,
mainnet Lightning, deployment infrastructure. Boundaries are documented in
`code/README.md`.

---

## Citation

See `CITATION.cff`. After the Zenodo DOI is minted, update that file and cite:

```
Larsen, O. A., & Moghaddam, M. T. (2026). NostrAgent: A Decentralized Identity
and Delegation Architecture for Sovereign Agentic Systems (Version 1.0)
[Computer software]. https://github.com/Oliver1703dk/agentics2026-replication-package
```

---

## Contact

Oliver Aleksander Larsen (`olar@mmmi.sdu.dk`) and Mahyar Tourchi Moghaddam
(`mtmo@mmmi.sdu.dk`), SDU Software Engineering, University of Southern Denmark.

---

## License

Source code, scripts, and configuration under `code/` (including `code/eval/`
and `code/infra/`): MIT.
Data, prose, and panel materials under `atam/` and the `README.md` files:
CC BY 4.0. See `LICENSE` for the full text and the precise scope.

The regtest credentials under `code/infra/credentials/` are synthetic, carry
zero monetary value, and exist only so a reader can bring up the L402 path
on a fresh machine. They are not real-world keys.