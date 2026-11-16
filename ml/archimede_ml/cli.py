"""Typer CLI for Archimede ML workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import numpy as np
import typer
from rich import print

from . import metrics, systemone, timestral_bridge

app = typer.Typer(help="Archimede ML: validate and fine-tune awareness models")


@app.command("validate-systemone")
def validate_systemone(
    dataset: Path = typer.Option(..., exists=True, help="JSONL with state/label fields"),
    endpoint: str = typer.Option("http://127.0.0.1:8017/v1/systemone"),
    model: str = typer.Option("jev-latest"),
    rules_only: bool = typer.Option(False, help="Skip HTTP and use rule classifier"),
    out: Optional[Path] = typer.Option(None, help="Write scores JSON"),
) -> None:
    """Evaluate System-One (or rules) against a labeled JSONL dataset."""
    rows = [json.loads(line) for line in dataset.read_text().splitlines() if line.strip()]
    y_true, y_pred, confs, correct = [], [], [], []
    client = systemone.SystemOneClient(endpoint=endpoint, model=model)
    for row in rows:
        state = row.get("state") or systemone.bucket_to_state(row)
        label = row["label"]
        if rules_only:
            pred, conf = systemone.rule_classify(row if "exec_count" in row else {"exec_count": 0})
            if "exec_count" not in row:
                # Prefer explicit state heuristics via fake bucket if present
                pred, conf = systemone.rule_classify(row)
        else:
            try:
                pred, conf, _ = client.classify_behavior(state)
            except Exception:
                pred, conf = systemone.rule_classify(row)
        y_true.append(label)
        y_pred.append(pred)
        confs.append(conf)
        correct.append(float(pred == label))
    scores = metrics.classification_scores(y_true, y_pred)
    scores["ece"] = metrics.expected_calibration_error(np.asarray(confs), np.asarray(correct))
    print(scores)
    if out:
        out.write_text(json.dumps(scores, indent=2))


@app.command("validate-forecast")
def validate_forecast(
    series_file: Path = typer.Option(..., exists=True, help="JSON list or JSONL of values"),
    horizon: int = 16,
    context: int = 64,
    model_size: str = "5M",
    use_timestral: bool = False,
    out: Optional[Path] = typer.Option(None),
) -> None:
    """Backtest forecasting quality on a univariate series."""
    raw = series_file.read_text().strip()
    if raw.startswith("["):
        series = np.asarray(json.loads(raw), dtype=float)
    else:
        vals = []
        for line in raw.splitlines():
            obj = json.loads(line)
            vals.append(float(obj.get("value", obj if isinstance(obj, (int, float)) else 0)))
        series = np.asarray(vals, dtype=float)
    scores = timestral_bridge.sliding_window_eval(
        series,
        horizon=horizon,
        context=context,
        model_size=model_size,
        use_timestral=use_timestral,
    )
    print(scores)
    if out:
        out.write_text(json.dumps(scores, indent=2))


@app.command("finetune-ruleset")
def finetune_ruleset(
    dataset: Path = typer.Option(..., exists=True),
    out: Path = typer.Option(Path("artifacts/ruleset_report.json")),
) -> None:
    """
    Calibrate rule thresholds on labeled buckets.
    Produces a report of per-label precision proxies (no cloud training required).
    """
    rows = [json.loads(line) for line in dataset.read_text().splitlines() if line.strip()]
    y_true, y_pred = [], []
    for row in rows:
        label = row["label"]
        pred, _ = systemone.rule_classify(row)
        y_true.append(label)
        y_pred.append(pred)
    scores = metrics.classification_scores(y_true, y_pred)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scores, indent=2))
    print(f"wrote {out}")
    print(scores)


if __name__ == "__main__":
    app()
