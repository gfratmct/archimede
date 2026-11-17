# Archimede

Local agent awareness engine: monitor coding agents and LLM harnesses on your machine, ingest Langfuse-like **security traces**, classify behavior with open System-One models, forecast activity with Timestral, and surface logs/stats/flags — built for cooperation and trust, not stealth surveillance.

## What it watches

| Signal | Source | Notes |
|--------|--------|-------|
| Process snapshots | sysinfo / `/proc` | Cursor, Claude Code, Copilot, Windsurf, Aider, Codex, harnesses, local LLMs, … |
| Resource deltas | process polling | RSS/CPU spikes → `ResourceSpike` flags |
| Sockets | Linux `/proc` TCP tables | Metadata only (local/remote/state) — no TLS body capture; macOS idle |
| Exec deltas | optional eBPF / userspace fallback | `enable_ebpf: true` in config |
| Session logs | `~/.cursor`, `~/.claude`, `~/.codex`, … | JSONL/JSON summaries |
| Harness traces | `POST /v1/traces` + `/v1/spans` | Langfuse-shaped spans from custom SDKs |

**Out of scope:** keyloggers, clipboard capture, screenshot OCR, TLS plaintext decryption.

## Security observability (Langfuse-like, flags-first)

Archimede stores **traces → spans** for custom harnesses/LLMs and correlates them with host telemetry. A **policy engine** emits security flags (`SecretExfilHint`, `UnauthorizedTool`, `ResourceSpike`, `NewRemoteHost`, …).

**Enforcement is opt-in** (`enforcement.enabled: false` by default): observe + alert only. When enabled, allowlisted actions may run (`terminate_process`; `deny_egress` is audited/stubbed).

```yaml
enforcement:
  enabled: false
  actions: [terminate_process]
  cool_down_secs: 60

policy:
  max_span_egress_hosts: 8
  flag_on_secret_patterns: true
  flag_on_prompt_injection: true
  flag_on_remote_control: true
  flag_on_resource_spike_pct: 300
  deny_tools: []      # e.g. ["bash", "curl"]
  allow_models: []    # empty = allow all
```

### Instrument a custom harness (Python)

```bash
cd ml && pip install -e .
python examples/harness_instrumentation.py
```

```python
from archimede_ml.tracing import ArchimedeClient, generation, tool, trace

client = ArchimedeClient(agent="my-agent", harness="my-harness")
with trace(client, name="run"):
    with generation(client, model="gpt-demo", input_summary="...") as g:
        g.end(output_summary="...")
    with tool(client, name="read_file") as t:
        t.end(output_summary="ok")
```

API surface:

- `POST /v1/traces`, `GET /v1/traces`, `GET /v1/traces/:id`
- `POST /v1/spans`
- `GET /v1/flags`, `GET /v1/enforcement`

## Architecture

```
collectors (/proc, sockets, sessions, eBPF?)
   + harness SDK spans
        │
        ▼
   EventBus (flume)
        │
        ├─► SQLite WAL (events, traces, spans, flags, enforcement)
        ├─► Feature buckets (30s)
        └─► Policy engine (flags + optional enforce)
                 │
                 ├─► System-One classify
                 └─► Timestral forecast
                          │
                          ▼
                 CLI + http://127.0.0.1:7432
```

## Docker

```bash
# API + span ingest (portable; Docker Desktop OK)
docker compose -f docker/docker-compose.yml up --build -d
curl -s http://127.0.0.1:7432/health

# Linux only: observe host processes/sockets via pid/network host namespace
docker compose -f docker/docker-compose.host.yml up --build -d
```

Config used in containers: [`docker/archimede.yaml`](docker/archimede.yaml) (`0.0.0.0:7432`, data in `/data`).

## Quick start

```bash
# Build
cargo build --release -p archimede

# One-shot: which agents are running now?
./target/release/archimede --config configs/archimede.yaml scan

# Daemon (collect + classify + forecast + policy + API)
./target/release/archimede --config configs/archimede.yaml daemon

# Insights
./target/release/archimede stats
./target/release/archimede logs --limit 20
./target/release/archimede alerts
./target/release/archimede traces
./target/release/archimede flags
./target/release/archimede enforce-status
curl -s localhost:7432/v1/stats | jq
curl -s localhost:7432/v1/flags | jq
```

Data directory defaults to `~/.local/share/archimede/archimede.sqlite`.

## Dashboard (SolidJS)

Live monitor for stats, alerts, flags, logs, traces, enforcement, and config — with toast + optional desktop notifications.

```bash
cd dashboard && npm install && npm run build
# daemon.dashboard_dir: "dashboard/dist" in configs/archimede.yaml
./target/release/archimede --config configs/archimede.yaml daemon
# → http://127.0.0.1:7432/

# Or hot-reload UI while the daemon runs:
cd dashboard && npm run dev   # http://127.0.0.1:5173 (proxies API)
```

See [`dashboard/README.md`](dashboard/README.md).

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
| `archimede-collect` | Process/sockets/sessions/eBPF collectors |
| `archimede-features` | Time buckets + JSONL export |
| `archimede-classify` | System-One HTTP + rules |
| `archimede-forecast` | Baseline + sidecar + optional ONNX |
| `archimede-policy` | Security flags + optional enforcement |
| `archimede` | Daemon, CLI, Axum API |

## Trust posture

Archimede is designed so humans and agents can **co-exist with visibility**: you see what agents are doing, risk is labeled with scores, predictions are inspectable, and **enforcement stays off until you turn it on**. No silent interception of secrets.

## License

Archimede is licensed under the **Archimede Source License 1.0** (see [`LICENSE`](LICENSE)):

- **Free** for non-commercial use (personal, education, research).
- **Free** for commercial use if your organization’s (or employer’s) global consolidated annual revenue is **≤ USD $1,000,000**.
- **Paid commercial license required** if annual revenue exceeds **USD $1,000,000** — contact [gabriele.lanzafame03@gmail.com](mailto:gabriele.lanzafame03@gmail.com) for terms.

Timestral **weights** (optional ML path) use Mistral’s Modified MIT (separate revenue threshold); see their model cards.
