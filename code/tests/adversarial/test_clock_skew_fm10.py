"""FM-10: Clock Skew / Temporal Validity -- adversarial tests.

Tests the 300s future-timestamp tolerance defined in validate_timestamp().
Clock skew is introduced programmatically by patching time.time in
nostr_agent.validation -- no system clock changes required.

Test matrix:
- Skew levels: ±30s, ±60s, ±120s, ±300s (boundary), ±301s (boundary+1), ±600s
- Acceptance: validate_timestamp() return value under simulated skew
- Disagreement: whether verifier-A (reference clock) and verifier-B (skewed clock)
  agree on the same event created_at.

Paper artifact: run_fm10_table() produces the skew-vs-acceptance-rate table
for Table 3 (FM-10 row) in Section 5.

STRIDE mapping: Tampering (modified timestamps), Spoofing (replay with future ts),
Elevation of Privilege (bypassing expiry via skewed clocks). Trust boundary: TB1.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from nostr_agent.validation import validate_timestamp, validate_event_structure


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_PUBKEY = "a" * 64  # valid 64-char lowercase hex pubkey

SKEW_LEVELS_SECONDS: list[int] = [
    -600, -300, -120, -60, -30,
    0,
    30, 60, 120, 300, 301, 600,
]


def _accept_rate(skew_s: int, n_samples: int = 1000) -> float:
    """Fraction of n_samples event timestamps accepted by a verifier whose
    clock is skew_s seconds SLOW (behind) relative to true wall time.

    The event is always created at wall time ``now``.
    A slow verifier's clock returns ``now - skew_s``, making the event appear
    skew_s seconds in the future from its perspective.

    Convention:
      skew_s > 0  →  verifier clock is slow; event appears skew_s seconds in the future.
      skew_s < 0  →  verifier clock is fast; event appears skew_s seconds in the past.
    """
    now_wall = int(time.time())
    event_ts = now_wall  # event created at true now

    accepted = 0
    for _ in range(n_samples):
        with patch("nostr_agent.validation.time") as mock_t:
            mock_t.time.return_value = float(now_wall - skew_s)
            if validate_timestamp(event_ts):
                accepted += 1
    return accepted / n_samples


def _verifier_disagrees(event_ts: int, skew_s: int, now_wall: int | None = None) -> bool:
    """Return True if verifier-A (wall clock) and verifier-B (skew_s-slow clock)
    disagree on whether event_ts is valid.

    Positive skew_s = verifier-B's clock is slow; it returns (now_wall - skew_s).
    Pass now_wall explicitly to avoid drift when looping over multiple skew values.
    """
    if now_wall is None:
        now_wall = int(time.time())

    with patch("nostr_agent.validation.time") as mock_a:
        mock_a.time.return_value = float(now_wall)
        a_accepts = validate_timestamp(event_ts)

    with patch("nostr_agent.validation.time") as mock_b:
        mock_b.time.return_value = float(now_wall - skew_s)
        b_accepts = validate_timestamp(event_ts)

    return a_accepts != b_accepts


# ===========================================================================
# 1. Future-skew rejection boundary (spec: >300s future → reject)
# ===========================================================================


@pytest.mark.unit
class TestFutureTimestampBoundary:
    """Verify the 300s spec boundary is exactly enforced."""

    def test_exactly_300s_future_accepted(self) -> None:
        """event_ts = now + 300 must be accepted (inclusive boundary)."""
        now = int(time.time())
        ts = now + 300
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            assert validate_timestamp(ts) is True

    def test_301s_future_rejected(self) -> None:
        """event_ts = now + 301 must be rejected."""
        now = int(time.time())
        ts = now + 301
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            assert validate_timestamp(ts) is False

    def test_600s_future_rejected(self) -> None:
        now = int(time.time())
        ts = now + 600
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            assert validate_timestamp(ts) is False

    def test_past_event_always_accepted(self) -> None:
        """Past events (created_at < now) are always valid."""
        now = int(time.time())
        for skew in (30, 60, 120, 300, 600):
            ts = now - skew
            with patch("nostr_agent.validation.time") as m:
                m.time.return_value = float(now)
                assert validate_timestamp(ts) is True, f"past event -{skew}s was rejected"


# ===========================================================================
# 2. Per-skew acceptance rate (parametrized)
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "skew_s, expect_accepted",
    [
        # Negative skew: verifier clock is fast (ahead).
        # Event appears to be in the past → always accepted.
        (-600, True),
        (-300, True),
        (-120, True),
        (-60,  True),
        (-30,  True),
        # Zero skew: wall clock = verifier clock. Event at now → accepted.
        (0,    True),
        # Positive skew: verifier clock is slow (behind).
        # Event appears skew_s seconds in the future from verifier's perspective.
        # Within 300s tolerance window → accepted.
        (30,   True),
        (60,   True),
        (120,  True),
        (300,  True),
        # 301s slow clock: event appears 301s in the future → rejected.
        (301,  False),
        (600,  False),
    ],
)
def test_acceptance_under_verifier_clock_skew(skew_s: int, expect_accepted: bool) -> None:
    """Event at true wall time; verifier clock is skew_s seconds slow.

    Positive skew_s = verifier clock is slow; event appears skew_s seconds in the future.
    Negative skew_s = verifier clock is fast; event appears skew_s seconds in the past.
    """
    rate = _accept_rate(skew_s, n_samples=100)
    if expect_accepted:
        assert rate == 1.0, (
            f"skew={skew_s:+d}s: expected acceptance, got rate={rate:.2f}"
        )
    else:
        assert rate == 0.0, (
            f"skew={skew_s:+d}s: expected rejection, got rate={rate:.2f}"
        )


# ===========================================================================
# 3. Inter-verifier disagreement
# ===========================================================================


@pytest.mark.unit
class TestVerifierDisagreement:
    """When do two verifiers with different clocks disagree on the same event?"""

    def test_no_disagreement_within_tolerance(self) -> None:
        """Two verifiers within ±300s of each other always agree on a now-event."""
        now = int(time.time())
        event_ts = now
        for skew in (30, 60, 120, 300):
            assert not _verifier_disagrees(event_ts, skew), (
                f"Unexpected disagreement at skew={skew}s within tolerance window"
            )

    def test_disagreement_at_301s_skew(self) -> None:
        """Verifier-A (wall clock) accepts; verifier-B (301s slow) rejects event → disagreement.

        Verifier-B's clock returns (now - 301). Event at now appears 301s in the
        future from its perspective and is therefore rejected. Verifier-A accepts.
        """
        now = int(time.time())
        event_ts = now  # at true wall time
        assert _verifier_disagrees(event_ts, 301), (
            "Expected disagreement at 301s skew but verifiers agreed"
        )

    def test_disagreement_at_600s_skew(self) -> None:
        now = int(time.time())
        event_ts = now
        assert _verifier_disagrees(event_ts, 600)

    def test_no_disagreement_for_old_event(self) -> None:
        """An event 1 hour old is accepted by all verifiers regardless of skew."""
        now = int(time.time())
        event_ts = now - 3600
        for skew in (-600, -300, 0, 300, 600):
            assert not _verifier_disagrees(event_ts, skew), (
                f"Old event disagreement at skew={skew}s"
            )

    def test_disagreement_threshold_is_exactly_300s(self) -> None:
        """Skew=300 → agree; skew=301 → disagree. Confirms spec boundary precision."""
        now = int(time.time())
        event_ts = now
        assert not _verifier_disagrees(event_ts, 300), "Should agree at exactly 300s"
        assert _verifier_disagrees(event_ts, 301), "Should disagree at 301s"


# ===========================================================================
# 4. Full event structure validation with skewed timestamps
# ===========================================================================


@pytest.mark.unit
class TestEventStructureClockSkew:
    """validate_event_structure() rejects events with timestamps >300s in future."""

    def _make_event(self, created_at: int) -> dict:
        return {
            "kind": 38100,
            "pubkey": _BASE_PUBKEY,
            "content": "{}",
            "tags": [],
            "created_at": created_at,
        }

    def test_event_300s_future_accepted(self) -> None:
        now = int(time.time())
        event = self._make_event(now + 300)
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            validate_event_structure(event)  # must not raise

    def test_event_301s_future_rejected(self) -> None:
        from nostr_agent.validation import ValidationError
        now = int(time.time())
        event = self._make_event(now + 301)
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            with pytest.raises(ValidationError, match="future"):
                validate_event_structure(event)

    def test_event_delegation_future_rejected(self) -> None:
        """Kind 38101 delegation event with a future timestamp is also rejected."""
        from nostr_agent.validation import ValidationError
        now = int(time.time())
        event = {
            "kind": 38101,
            "pubkey": _BASE_PUBKEY,
            "content": "{}",
            "tags": [],
            "created_at": now + 400,
        }
        with patch("nostr_agent.validation.time") as m:
            m.time.return_value = float(now)
            with pytest.raises(ValidationError, match="future"):
                validate_event_structure(event)


# ===========================================================================
# 5. Paper artifact: skew-vs-acceptance table
# ===========================================================================


def run_fm10_table(n_samples: int = 1000) -> None:
    """Print the FM-10 clock-skew vs acceptance-rate table for Section 5.

    Not a pytest test -- call directly:
        python -c "from tests.adversarial.test_clock_skew_fm10 import run_fm10_table; run_fm10_table()"
    """
    header = f"{'Skew (s)':>10}  {'Acceptance rate':>16}  {'Verdict':>10}  {'Disagrees with wall':>20}"
    print(header)
    print("-" * len(header))

    now = int(time.time())
    for skew in SKEW_LEVELS_SECONDS:
        rate = _accept_rate(skew, n_samples=n_samples)
        event_ts = now  # event at wall time; verifier is offset
        # Pass now explicitly so disagreement check is consistent with rate measurement.
        disagrees = _verifier_disagrees(event_ts, skew, now_wall=now)
        verdict = "ACCEPT" if rate > 0.0 else "REJECT"
        print(
            f"{skew:>+10d}  {rate:>16.3f}  {verdict:>10}  {'YES' if disagrees else 'no':>20}"
        )
