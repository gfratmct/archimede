#!/usr/bin/env python3
"""Minimal Timestral / baseline forecast sidecar for Archimede Rust engine."""

from __future__ import annotations

import argparse
from typing import Any

from archimede_ml.timestral_bridge import baseline_forecast, timestral_forecast

try:
    from fastapi import FastAPI
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Install sidecar deps: pip install fastapi uvicorn pydantic"
    ) from exc


class ForecastRequest(BaseModel):
    history: list[float]
    horizon: int = 16
    metric: str = "exec_count"
    model_size: str = "5M"
    use_timestral: bool = True


class ForecastResponse(BaseModel):
    predicted: list[float]
    lower: list[float]
    upper: list[float]
    source: str
    metric: str


app = FastAPI(title="Archimede Timestral Sidecar", version="0.1.0")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "archimede-timestral-sidecar"}


@app.post("/v1/forecast", response_model=ForecastResponse)
def forecast(req: ForecastRequest) -> ForecastResponse:
    if req.use_timestral:
        out = timestral_forecast(req.history, horizon=req.horizon, model_size=req.model_size)
    else:
        out = baseline_forecast(req.history, horizon=req.horizon)
    return ForecastResponse(
        predicted=out.predicted,
        lower=out.lower,
        upper=out.upper,
        source=out.source,
        metric=req.metric,
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=7433)
    args = p.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
