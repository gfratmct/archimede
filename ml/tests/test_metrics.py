import json
from pathlib import Path

import numpy as np

from archimede_ml import metrics, systemone
from archimede_ml.timestral_bridge import baseline_forecast, sliding_window_eval


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def test_rule_classify_shell():
    row = {
        "exec_count": 14,
        "shell_hints": 7,
        "coding_hints": 0,
        "files_written": 0,
        "files_deleted": 0,
        "session_events": 1,
        "socket_count": 1,
        "egress_proxy_score": 1.0,
        "llm_wait_hints": 0,
    }
    label, conf = systemone.rule_classify(row)
    assert label == "shell_tools"
    assert conf > 0.3


def test_validate_rules_on_fixture():
    rows = [
        json.loads(l)
        for l in (FIXTURES / "labeled_buckets.jsonl").read_text().splitlines()
        if l.strip()
    ]
    y_true, y_pred = [], []
    for row in rows:
        pred, _ = systemone.rule_classify(row)
        y_true.append(row["label"])
        y_pred.append(pred)
    scores = metrics.classification_scores(y_true, y_pred)
    assert scores["accuracy"] >= 0.5


def test_forecast_baseline_backtest():
    series = np.asarray(json.loads((FIXTURES / "exec_series.json").read_text()), dtype=float)
    scores = sliding_window_eval(series, horizon=8, context=32, use_timestral=False)
    assert scores["windows"] > 0
    assert scores["mae"] >= 0.0
    out = baseline_forecast(series[:40].tolist(), horizon=4)
    assert len(out.predicted) == 4
