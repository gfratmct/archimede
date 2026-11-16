#!/usr/bin/env python3
"""
Export a compact forecasting head to ONNX for Rust `ort` inference.

Full Timestral graphs are large and custom; this script exports a small
distilled MLP that maps a fixed context window -> horizon mean forecast,
trained on Archimede metric series (or synthetic data). The Rust ONNX path
loads this file when `forecast.onnx_path` is set and `--features ort` is enabled.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def build_dataset(series: np.ndarray, context: int, horizon: int):
    xs, ys = [], []
    for i in range(context, len(series) - horizon):
        xs.append(series[i - context : i])
        ys.append(series[i : i + horizon])
    return np.asarray(xs, dtype=np.float32), np.asarray(ys, dtype=np.float32)


def train_mlp(x: np.ndarray, y: np.ndarray, epochs: int = 200, lr: float = 0.01):
    """Tiny numpy MLP (context -> horizon) — no torch required for export prep."""
    rng = np.random.default_rng(0)
    n_in, n_out = x.shape[1], y.shape[1]
    n_hidden = 64
    w1 = rng.normal(0, 0.1, size=(n_in, n_hidden)).astype(np.float32)
    b1 = np.zeros(n_hidden, dtype=np.float32)
    w2 = rng.normal(0, 0.1, size=(n_hidden, n_out)).astype(np.float32)
    b2 = np.zeros(n_out, dtype=np.float32)

    for _ in range(epochs):
        h = np.maximum(0, x @ w1 + b1)
        pred = h @ w2 + b2
        err = pred - y
        loss = float(np.mean(err**2))
        # Gradients
        dpred = (2.0 / err.size) * err
        dw2 = h.T @ dpred
        db2 = dpred.sum(axis=0)
        dh = dpred @ w2.T
        dh *= (h > 0).astype(np.float32)
        dw1 = x.T @ dh
        db1 = dh.sum(axis=0)
        w2 -= lr * dw2
        b2 -= lr * db2
        w1 -= lr * dw1
        b1 -= lr * db1
    return {"w1": w1, "b1": b1, "w2": w2, "b2": b2, "loss": loss}


def export_onnx(weights: dict, path: Path, context: int, horizon: int) -> None:
    try:
        import torch
        import torch.nn as nn
    except ImportError as exc:
        raise SystemExit("pip install torch onnx to export") from exc

    class MLP(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(context, 64)
            self.fc2 = nn.Linear(64, horizon)

        def forward(self, x):
            return self.fc2(torch.relu(self.fc1(x)))

    model = MLP()
    with torch.no_grad():
        model.fc1.weight.copy_(torch.tensor(weights["w1"].T))
        model.fc1.bias.copy_(torch.tensor(weights["b1"]))
        model.fc2.weight.copy_(torch.tensor(weights["w2"].T))
        model.fc2.bias.copy_(torch.tensor(weights["b2"]))
    model.eval()
    dummy = torch.zeros(1, context)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        str(path),
        input_names=["history"],
        output_names=["forecast"],
        dynamic_axes={"history": {0: "batch"}, "forecast": {0: "batch"}},
        opset_version=17,
    )
    meta = {
        "context": context,
        "horizon": horizon,
        "input": "history",
        "output": "forecast",
        "final_loss": weights["loss"],
    }
    path.with_suffix(".json").write_text(json.dumps(meta, indent=2))
    print(f"wrote {path} and {path.with_suffix('.json')}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--series", type=Path, help="JSON list of floats; synthetic if omitted")
    p.add_argument("--context", type=int, default=64)
    p.add_argument("--horizon", type=int, default=16)
    p.add_argument("--epochs", type=int, default=300)
    p.add_argument("--out", type=Path, default=Path("models/timestral_head.onnx"))
    args = p.parse_args()

    if args.series and args.series.exists():
        series = np.asarray(json.loads(args.series.read_text()), dtype=np.float32)
    else:
        t = np.arange(0, 2000, dtype=np.float32)
        series = (10 + 0.05 * t + 3 * np.sin(t / 11) + np.random.default_rng(0).normal(0, 0.5, t.shape)).astype(
            np.float32
        )

    x, y = build_dataset(series, args.context, args.horizon)
    weights = train_mlp(x, y, epochs=args.epochs)
    export_onnx(weights, args.out, args.context, args.horizon)


if __name__ == "__main__":
    main()
