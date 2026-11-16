# Archimede

Local agent awareness engine: monitor coding agents and LLM harnesses on your Linux PC, classify behavior with open System-One models, forecast activity with Timestral, and surface fast logs/stats — built for cooperation and trust, not stealth surveillance.

## What it watches

| Signal | Source | Notes |
|--------|--------|-------|
| Process snapshots | `/proc` via sysinfo | Attributed to Cursor, Claude Code, Copilot, OpenClaw, Hermes, Pi, Ollama, … |
| Sockets | `/proc` TCP tables | Metadata only (local/remote/state) — no TLS body capture |
| Exec deltas | optional eBPF / userspace fallback | `enable_ebpf: true` in config |
| Session logs | `~/.cursor`, `~/.claude`, … | JSONL/JSON summaries |

**Out of scope:** keyloggers, clipboard capture, screenshot OCR, TLS plaintext decryption.

## Architecture

```
collectors (/proc, sockets, sessions, eBPF?)
        │
        ▼
   EventBus (flume)
        │
        ├─► SQLite WAL store
        └─► Feature buckets (30s)
                 │
                 ├─► System-One classify (jevos / llama.cpp / rules)
                 └─► Timestral forecast (sidecar / ONNX / Rust baseline)
                          │
                          ▼
                 CLI + http://127.0.0.1:7432
```

## Quick start

```bash
# Build
cargo build --release -p archimede

# One-shot: which agents are running now?
./target/release/archimede --config configs/archimede.yaml scan

# Daemon (collect + classify + forecast + API)
./target/release/archimede --config configs/archimede.yaml daemon

# Insights
./target/release/archimede stats
./target/release/archimede logs --limit 20
./target/release/archimede alerts
curl -s localhost:7432/v1/stats | jq
```

Data directory defaults to `~/.local/share/archimede/archimede.sqlite`.

## System-One (open Jev)

Point `classify.endpoint` at an open System-One server:

- [feder-cr/jev](https://github.com/feder-cr/jev) (`jevos`) on `:8017`
- [llama.cpp](https://github.com/ggerganov/llama.cpp) `llama-server` `/v1/systemone`
- Ollama ≥ 0.35 with decision models

If the endpoint is down, Archimede falls back to local deterministic rules (`classify.fallback_rules: true`).

## Timestral forecasting

1. **Rust hot path:** exponential-smoothing baseline (always on).
2. **Python sidecar:** `ml/scripts/serve_timestral.py` — set `forecast.sidecar_url: "http://127.0.0.1:7433"`.
3. **ONNX:** export a distilled head with `ml/scripts/export_timestral_onnx.py`, rebuild with `--features ort`, set `forecast.onnx_path`.

```bash
cd ml && pip install -e ".[timestral]"
pip install git+https://github.com/mistralai/timestral.git
python scripts/serve_timestral.py --port 7433
```

## Python ML scripts

```bash
cd ml && pip install -e ".[dev]"

# Validate System-One / rules on labeled buckets
python scripts/validate_systemone.py --dataset ../tests/fixtures/labeled_buckets.jsonl --rules-only

# Forecast backtest
python scripts/validate_forecast.py --series ../tests/fixtures/exec_series.json

# Calibration / fine-tune artifact for Rust post-process
python scripts/finetune_timestral.py --buckets ../tests/fixtures/labeled_buckets.jsonl --out artifacts/calib.json
```

## Workspace crates

| Crate | Role |
|-------|------|
| `archimede-core` | Events, bus, SQLite, attribution, config |
| `archimede-collect` | `/proc`, sockets, sessions, eBPF stub |
| `archimede-features` | Time buckets + JSONL export |
| `archimede-classify` | System-One HTTP + rules |
| `archimede-forecast` | Baseline + sidecar + optional ONNX |
| `archimede` | Daemon, CLI, Axum API |

## Trust posture

Archimede is designed so humans and agents can **co-exist with visibility**: you see what agents are doing, risk is labeled with scores, and predictions are inspectable. No silent interception of secrets.

## License

Apache-2.0. Timestral **weights** use Mistral’s Modified MIT (revenue threshold); see their model cards.
