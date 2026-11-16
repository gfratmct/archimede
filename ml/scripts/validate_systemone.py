#!/usr/bin/env python3
"""Validate open System-One decisions on a labeled Archimede bucket dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from archimede_ml import metrics, systemone


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", type=Path, required=True)
    p.add_argument("--endpoint", default="http://127.0.0.1:8017/v1/systemone")
    p.add_argument("--model", default="jev-latest")
    p.add_argument("--rules-only", action="store_true")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()

    rows = [json.loads(l) for l in args.dataset.read_text().splitlines() if l.strip()]
    client = systemone.SystemOneClient(endpoint=args.endpoint, model=args.model)
    y_true, y_pred, confs, correct = [], [], [], []
    for row in rows:
        state = row.get("state") or systemone.bucket_to_state(row)
        if args.rules_only:
            pred, conf = systemone.rule_classify(row)
        else:
            try:
                pred, conf, _ = client.classify_behavior(state)
            except Exception:
                pred, conf = systemone.rule_classify(row)
        y_true.append(row["label"])
        y_pred.append(pred)
        confs.append(conf)
        correct.append(float(pred == row["label"]))

    scores = metrics.classification_scores(y_true, y_pred)
    scores["ece"] = metrics.expected_calibration_error(np.asarray(confs), np.asarray(correct))
    print(json.dumps(scores, indent=2))
    if args.out:
        args.out.write_text(json.dumps(scores, indent=2))


if __name__ == "__main__":
    main()
