"""STRIDE adversarial test suite (Plan 11).

Organized by threat category:
- test_spoofing.py       -- TP-01 (forged signature)
- test_tampering.py      -- TP-02 (post-signature content mutation)
- test_replay.py         -- TP-07, TP-08, TP-09 (L402 macaroon/invoice/preimage attacks)
- test_scope_escalation.py -- TP-06 (attenuation violation, depth falsification)
- test_sybil.py          -- FM-13 (Sybil ring trust bounding)

Integration-only tests (require Docker):
- TP-03 (relay partition audit) in test_spoofing.py
- TP-04 (event flood DoS) in test_tampering.py
- TP-05 (trust graph enumeration) in test_scope_escalation.py

Marker mapping: all tests carry @pytest.mark.adversarial.
Unit-level tests additionally carry @pytest.mark.unit.
Relay-dependent tests carry @pytest.mark.integration.
"""
