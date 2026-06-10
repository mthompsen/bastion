"""Download and cache Bastion's external datasets (thin wrapper).

Equivalent to ``bastion fetch``; the shared logic lives in
:mod:`bastion.fetch`. Run from the repository root:

    python scripts/fetch_data.py [--force] [--data-dir DIR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from bastion.fetch import (
    ATTACK_VERSION,
    DEFAULT_DATA_DIR,
    SIGMA_VERSION,
    fetch_attack,
    fetch_sigma,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download even if cached")
    parser.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="cache directory (default: data/)"
    )
    args = parser.parse_args(argv)

    attack_path = fetch_attack(data_dir=args.data_dir, force=args.force)
    size_mb = attack_path.stat().st_size / 1_000_000
    print(f"ATT&CK v{ATTACK_VERSION} STIX bundle cached at {attack_path} ({size_mb:.1f} MB)")
    sigma_path = fetch_sigma(data_dir=args.data_dir, force=args.force)
    rule_files = sum(1 for _ in sigma_path.rglob("*.yml"))
    print(f"Sigma ruleset {SIGMA_VERSION} cached at {sigma_path} ({rule_files} rule files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
