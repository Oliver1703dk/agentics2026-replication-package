"""Entry point for `python -m eval` or `python -m eval.bench`.

Usage:
    cd code/
    python -m eval.bench --all
    python -m eval.bench --metrics B1,B2,B6
    python -m eval.bench --metrics B6 --runs 200 --warmup 20
"""

from eval.bench import app

app()
