"""Timestral fine-tune / inference helpers with a lightweight fallback forecaster."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np


@dataclass
class ForecastOut:
    predicted: list[float]
    lower: list[float]
    upper: list[float]
    source: str


def baseline_forecast(history: list[float] | np.ndarray, horizon: int = 16, alpha: float = 0.35) -> ForecastOut:
    hist = np.asarray(history, dtype=float)
    if hist.size == 0:
        zeros = [0.0] * horizon
        return ForecastOut(zeros, zeros, zeros, "baseline")
    level = float(hist[0])
    for x in hist[1:]:
        level = alpha * float(x) + (1.0 - alpha) * level
    mean = float(hist.mean())
    std = float(max(hist.std(ddof=0), 1e-3))
    trend = float((hist[-1] - hist[-4]) / 3.0) if hist.size >= 4 else 0.0
    predicted, lower, upper = [], [], []
    for step in range(1, horizon + 1):
        y = max(0.0, level + trend * step)
        band = 1.96 * std * (step**0.5)
        predicted.append(float(y))
        lower.append(float(max(0.0, y - band)))
        upper.append(float(y + band))
    return ForecastOut(predicted, lower, upper, "baseline")


def load_timestral(model_size: str = "5M", device: str = "cpu") -> Any:
    """Load mistralai Timestral if installed; otherwise raise with install hint."""
    try:
        from timestral import TimestralForecaster  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "timestral package not installed. "
            "pip install 'archimede-ml[timestral]' "
            "and `pip install git+https://github.com/mistralai/timestral.git`"
        ) from exc
    repo = f"mistralai/Timestral-{model_size}"
    return TimestralForecaster.from_pretrained(repo, device=device)


def timestral_forecast(
    history: list[float] | np.ndarray,
    horizon: int = 16,
    model_size: str = "5M",
    device: str = "cpu",
) -> ForecastOut:
    """Zero-shot univariate forecast via Timestral; falls back to baseline on error."""
    hist = np.asarray(history, dtype=np.float32).reshape(1, -1, 1)
    try:
        model = load_timestral(model_size=model_size, device=device)
        # Timestral API: forecast returns quantile tensor; use median (~q50).
        out = model.forecast(hist, prediction_length=horizon)
        # Best-effort parsing across possible return shapes.
        arr = np.asarray(out)
        if arr.ndim == 3:
            # [batch, horizon, quantiles] — pick middle quantile
            mid = arr.shape[-1] // 2
            pred = arr[0, :, mid]
        elif arr.ndim == 2:
            pred = arr[0]
        else:
            pred = arr.reshape(-1)[:horizon]
        pred = pred.astype(float).tolist()
        std = float(max(np.std(history), 1e-3)) if len(history) else 1.0
        lower = [max(0.0, p - 1.64 * std) for p in pred]
        upper = [p + 1.64 * std for p in pred]
        return ForecastOut(pred, lower, upper, f"timestral-{model_size}")
    except Exception:
        return baseline_forecast(history, horizon=horizon)


def sliding_window_eval(
    series: np.ndarray,
    horizon: int,
    context: int,
    model_size: str = "5M",
    use_timestral: bool = False,
) -> dict[str, float]:
    from .metrics import forecast_scores, quantile_coverage

    series = np.asarray(series, dtype=float)
    preds, trues, lowers, uppers = [], [], [], []
    for i in range(context, len(series) - horizon):
        hist = series[i - context : i]
        future = series[i : i + horizon]
        if use_timestral:
            out = timestral_forecast(hist, horizon=horizon, model_size=model_size)
        else:
            out = baseline_forecast(hist, horizon=horizon)
        preds.append(out.predicted)
        trues.append(future.tolist())
        lowers.append(out.lower)
        uppers.append(out.upper)
    if not preds:
        return {"mae": 0.0, "rmse": 0.0, "mape": 0.0, "coverage": 0.0, "windows": 0}
    yt = np.asarray(trues)
    yp = np.asarray(preds)
    scores = forecast_scores(yt, yp)
    scores["coverage"] = quantile_coverage(yt, np.asarray(lowers), np.asarray(uppers))
    scores["windows"] = float(len(preds))
    return scores
