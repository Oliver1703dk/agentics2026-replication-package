"""Environment metadata capture for reproducibility (spec section 5.3).

Records Python version, platform, library versions, timestamp, and random
seed alongside benchmark results so that any run can be fully reproduced.
"""

from __future__ import annotations

import importlib.metadata
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from eval.benchmark_config import RANDOM_SEED


def capture_environment() -> dict:
    """Capture environment metadata for reproducibility.

    Returns:
        Dict with python_version, platform, machine, processor,
        nostr_sdk_version, coincurve_version, timestamp, random_seed.
    """
    nostr_sdk_version = "unknown"
    try:
        nostr_sdk_version = importlib.metadata.version("nostr-sdk")
    except importlib.metadata.PackageNotFoundError:
        nostr_sdk_version = "not installed"

    coincurve_version = "unknown"
    try:
        import coincurve  # type: ignore[import]
        coincurve_version = getattr(coincurve, "__version__", "unknown")
    except ImportError:
        coincurve_version = "not installed"

    pymacaroons_version = "unknown"
    try:
        import pymacaroons  # type: ignore[import]
        pymacaroons_version = getattr(pymacaroons, "__version__", "unknown")
    except ImportError:
        pymacaroons_version = "not installed"

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "nostr_sdk_version": nostr_sdk_version,
        "coincurve_version": coincurve_version,
        "pymacaroons_version": pymacaroons_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
    }


def save_metadata(output_path: str | Path) -> dict:
    """Save environment metadata to JSON file alongside benchmark results.

    Args:
        output_path: Path to write the JSON metadata file.

    Returns:
        The metadata dict that was written.
    """
    metadata = capture_environment()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(metadata, f, indent=2)
    return metadata
