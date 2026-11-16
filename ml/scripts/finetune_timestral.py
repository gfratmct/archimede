#!/usr/bin/env python3
"""
Fine-tune / adapt Timestral-style forecasting on Archimede metric exports.

Timestral foundation weights are typically adapted via Mistral Forge or a
local LoRA-style recipe. This script:
  1. Loads JSONL bucket exports from `archimede export`
  2. Builds sliding windows
  3. Runs baseline + optional Timestral zero-shot scoring
  4. Writes a calibration artifact (scale/bias) that the Rust baseline can apply

Full weight fine-tuning is gated behind --train-torch when torch+timestral are installed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from archimede_ml.metrics import forecast_scores
from archimede_ml.timestral_bridge import baseline_forecast, sliding_window_eval, timestral_forecast


def load_metric_series(path: Path, metric: str, agent: str | None) -> np.ndarray:
    values = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if agent and row.get("agent") != agent:
            continue
        if metric in row:
            values.append(float(row[metric]))
        elif "metrics" in row and metric in row["metrics"]:
            values.append(float(row["metrics"][metric]))
    return np.asarray(values, dtype=float)


def fit_affine_calibration(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """Least-squares scale/bias so rust can apply y' = scale * y + bias."""
    x = y_pred.reshape(-1)
    y = y_true.reshape(-1)
    if x.size < 2:
        return {"scale": 1.0, "bias": 0.0}
    A = np.vstack([x, np.ones_like(x)]).T
    scale, bias = np.linalg.lstsq(A, y, rcond=None)[0]
    return {"scale": float(scale), "bias": float(bias)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--buckets", type=Path, required=True, help="JSONL from archimede export")
    p.add_argument("--metric", default="exec_count")
    p.add_argument("--agent", default=None)
    p.add_argument("--horizon", type=int, default=16)
    p.add_argument("--context", type=int, default=64)
    p.add_argument("--model-size", default="5M")
    p.add_argument("--use-timestral", action="store_true")
    p.add_argument("--out", type=Path, default=Path("artifacts/timestral_calibration.json"))
    p.add_argument(
        "--train-torch",
        action="store_true",
        help="Placeholder flag for local torch fine-tune (requires timestral extras)",
    )
    args = p.parse_args()

    series = load_metric_series(args.buckets, args.metric, args.agent)
    if series.size < args.context + args.horizon + 2:
        raise SystemExit(
            f"need at least {args.context + args.horizon + 2} points, got {series.size}"
        )

    scores = sliding_window_eval(
        series,
        horizon=args.horizon,
        context=args.context,
        model_size=args.model_size,
        use_timestral=args.use_timestral,
    )

    # Build calibration on last windows using baseline (always available)
    preds, trues = [], []
    for i in range(args.context, len(series) - args.horizon):
        hist = series[i - args.context : i]
        future = series[i : i + args.horizon]
        if args.use_timestral:
            out = timestral_forecast(hist, horizon=args.horizon, model_size=args.model_size)
        else:
            out = baseline_forecast(hist, horizon=args.horizon)
        preds.append(out.predicted)
        trues.append(future.tolist())
    calib = fit_affine_calibration(np.asarray(trues), np.asarray(preds))
    calibrated = np.asarray(preds) * calib["scale"] + calib["bias"]
    calib_scores = forecast_scores(np.asarray(trues), calibrated)

    artifact = {
        "metric": args.metric,
        "agent": args.agent,
        "model_size": args.model_size,
        "use_timestral": args.use_timestral,
        "raw_scores": scores,
        "calibration": calib,
        "calibrated_scores": calib_scores,
        "train_torch": bool(args.train_torch),
        "note": (
            "Affine calibration artifact for Rust baseline/Timestral post-process. "
            "Full weight fine-tuning should use Mistral Forge or a local LoRA recipe "
            "when --train-torch and timestral extras are available."
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2))
    print(json.dumps(artifact, indent=2))

    if args.train_torch:
        print(
            "\n[--train-torch] Install timestral + torch, then adapt weights with your "
            "Forge/LoRA pipeline; this script currently emits calibration for on-box use."
        )


if __name__ == "__main__":
    main()
