# Known test-suite issues

Tracks tests that are skipped, xfail, or otherwise known to misbehave in the
package as shipped. Each entry must state: what, why, and how to fix.

If this file lists nothing under a heading, every test under that scope is
expected to pass on a supported platform with the Docker infrastructure
running.

---

## Tests requiring Docker (auto-skipped when absent)

The following tests require the Docker infrastructure under `infra/` to be
running. They auto-skip cleanly when prerequisites are absent, via two
session-scoped gates in `tests/conftest.py`:

- `docker_available` / `require_docker` -- gates on Docker daemon reachability (`docker info`)
- `relays_available` / `require_relays` -- gates on raw TCP reachability of `localhost:7771-7773` (the host-mapped strfry ports)

Tests apply the gate with `@pytest.mark.usefixtures("require_relays")` (or
`require_docker`). When the gate fails the test is reported as SKIPPED with a
message that tells the reviewer how to bring up the stack:

```
SKIPPED [1] Strfry relays not reachable at localhost:7771-7773.
Bring up the stack: cd code && docker compose -f infra/docker-compose.yml up -d
&& bash infra/scripts/bootstrap.sh
```

Tests known to use these gates:

- `tests/integration/` -- the whole subtree
- `tests/test_lnd_grpc_integration.py`
- `tests/test_strfry_relay.py`
- `tests/adversarial/test_scope_escalation.py::test_tp05_unauthenticated_trust_graph_enumeration` (require_relays)
- `tests/adversarial/test_spoofing.py::test_tp03_audit_trail_survives_relay_loss` (require_relays)
- `tests/adversarial/test_tampering.py::test_tp04_event_flood_latency[...]` (require_relays)

To run them: bring up the stack first with the commands in
`../infra/README.md`, then re-run pytest.

Note that `test_tp03_audit_trail_survives_relay_loss` also requires the Python
`docker` SDK package, which is in the `test` optional-dependency extra in
`pyproject.toml`. `uv sync --python 3.11 --extra dev` installs it.
