#!/usr/bin/env python3
"""Backtest Timestral / baseline forecasts on exported metric series."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from archimede_ml.timestral_bridge import sliding_window_eval


def load_series(path: Path) -> np.ndarray:
    raw = path.read_text().strip()
    if raw.startswith("["):
        return np.asarray(json.loads(raw), dtype=float)
    vals = []
    for line in raw.splitlines():
        obj = json.loads(line)
        if isinstance(obj, dict):
            vals.append(float(obj.get("value", 0)))
        else:
            vals.append(float(obj))
    return np.asarray(vals, dtype=float)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--series", type=Path, required=True)
    p.add_argument("--horizon", type=int, default=16)
    p.add_argument("--context", type=int, default=64)
    p.add_argument("--model-size", default="5M")
    p.add_argument("--use-timestral", action="store_true")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()

    series = load_series(args.series)
    scores = sliding_window_eval(
        series,
        horizon=args.horizon,
        context=args.context,
        model_size=args.model_size,
        use_timestral=args.use_timestral,
    )
    print(json.dumps(scores, indent=2))
    if args.out:
        args.out.write_text(json.dumps(scores, indent=2))


if __name__ == "__main__":
    main()
