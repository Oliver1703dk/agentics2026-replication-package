# atam: mini-Delphi expert-panel data

The paper's Section 5.2 (RQ1) reports inter-rater agreement for a
twelve-leaf ATAM utility tree rated by a panel of three independent
anonymous experts in a two-round mini-Delphi protocol:
Krippendorff alpha = 0.94 and Fleiss kappa = 0.78 in Round 2. This
directory contains the rating instrument the panel filled in, the raw
ratings from both rounds, the final utility tree, and the script that
recomputes both agreement statistics from the raw ratings.

## Files

| File | What it is |
| --- | --- |
| `briefing.md` | The background packet the panel reviewed before rating: principles, components, trust boundaries, business drivers, non-goals. |
| `rating_form.md` | The instrument each expert filled in: the twelve leaves with definitions, the H/M/L rating task, and the tradeoff-point endorsement task. |
| `tradeoff_points.md` | The five tradeoff points TP-1 through TP-5 the panel reviewed and endorsed. |
| `round1_ratings.csv` | Raw Round 1 ratings (asynchronous, blind): 3 experts x 12 leaves. |
| `round2_ratings.csv` | Raw Round 2 ratings (after the convergence session). |
| `panel_notes.md` | Condensed rationale: why ratings moved between rounds and the three persistent dissents. |
| `agreement.py` | Recomputes Krippendorff alpha (ordinal, per axis, averaged, bootstrap CI) and Fleiss kappa (joint categories) for both rounds. |
| `agreement_results.json` | Frozen output of `agreement.py`; holds the paper's numbers. |
| `utility_tree.md` | The twelve leaves with the final Round 2 priorities and dissent flags. |

## Panel

Three independent anonymous experts in relevant fields.

Anonymity is strict and deliberate: no names, affiliations, or other
identifying details are recorded anywhere in this repository. This
protects the experts, enables honest disclosure of disagreement,
preserves the independence claim, and keeps the artifact compatible
with double-blind review. No expert had a declared conflict of interest
with the authors or with the work.

## Protocol

Two-round mini-Delphi (Estimate-Talk-Estimate variant), following
Linstone and Turoff (1975) and Gustafson et al. (1973):

1. **Round 1 (asynchronous, blind).** After reviewing the briefing
   packet (`briefing.md`, `rating_form.md`, `tradeoff_points.md`, and
   the failure-mode catalog), each expert independently rated the
   twelve leaves on (importance, difficulty), values in {H, M, L},
   blind to the other experts' ratings and with no candidate ratings
   provided in the packet, with free-text rationale per leaf.
2. **Aggregation.** The authors computed Round 1 agreement and
   circulated the anonymised rationale to all three experts.
3. **Round 2 (synchronous convergence).** Facilitated discussion
   focused on the highest-disagreement leaves, then re-rating on the
   same form.
4. **Post-panel.** Round 2 ratings were propagated into the paper.

Round 1 ran 2026-03-22 to 2026-03-29; Round 2 was held in the week
after Round 1 aggregation.

## Reproduce the paper's numbers

```bash
uv run agreement.py
```

The script declares its sole external dependency (`krippendorff==0.8.2`,
pinned exactly for bit-identical reproduction) in PEP 723 inline
metadata; `uv run` resolves and installs it automatically. Expected
output:

```
round1: alpha importance = 0.8759, difficulty = 0.7083, average = 0.7921  [95% CI 0.5524, 0.9052]
round1: fleiss kappa (joint importance-difficulty categories) = 0.4578
round2: alpha importance = 1.0000, difficulty = 0.8776, average = 0.9388  [95% CI 0.7812, 1.0000]
round2: fleiss kappa (joint importance-difficulty categories) = 0.7769

Wrote agreement_results.json
```

Round 2 alpha 0.9388 rounds to the paper's 0.94 (95% bootstrap CI
[0.78, 1.00]); Round 2 kappa 0.7769 rounds to the paper's 0.78, and
Round 1 kappa 0.4578 to 0.46. Alpha uses the ordinal distance metric
of Krippendorff (2004), averaged across the importance and difficulty
axes. Fleiss kappa (1971) is nominal, so the two axes are not averaged;
each (importance, difficulty) pair is one joint category. Kappa is
reported in the paper for comparability with ATAM studies that use it.

## Scope and panel size

The panel's task was bounded to a fixed, author-constructed utility
tree: it rated priorities and endorsed tradeoff points; it did not
author the tree. That makes this a structured expert rating exercise,
not a generative Delphi study. Three experts sit below the 10 to 18
participants recommended for generative Delphi studies (Okoli and
Pawlowski 2004), but three experts covering three distinct knowledge
dimensions suffice to rate a bounded artifact and surface dissent
(heterogeneity over headcount; Hasson, Keeney, and McKenna 2000), and three-to-five-person evaluation teams are standard ATAM
practice (Kazman, Klein, and Clements 2000). A full multi-stakeholder
ATAM workshop remains future work, as acknowledged in the paper's
threats to validity (Section 5.6).
