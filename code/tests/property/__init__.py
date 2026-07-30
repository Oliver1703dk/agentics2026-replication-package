"""Property-based tests for NostrAgent using Hypothesis.

Covers:
- Delegation attenuation invariants (INV-1 through INV-7)
- Trust score algebraic bounds (noisy-OR, decay, monotonicity)

Run with: pytest tests/property/ -m property -v
"""
