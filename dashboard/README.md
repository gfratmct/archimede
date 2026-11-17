# Archimede dashboard

SolidJS monitor for the local Archimede daemon: overview, alerts, flags, logs, traces, enforcement, and config — with live polling and toast / desktop notifications.

## Dev (proxied to daemon)

```bash
# terminal 1
cargo run --release -p archimede -- --config configs/archimede.yaml daemon

# terminal 2
cd dashboard
npm install
npm run dev
```

Open http://127.0.0.1:5173 — Vite proxies `/v1` and `/health` to `http://127.0.0.1:7432`.

## Production (served by daemon)

```bash
cd dashboard && npm run build
# configs/archimede.yaml → daemon.dashboard_dir: "dashboard/dist"
./target/release/archimede --config configs/archimede.yaml daemon
```

Open http://127.0.0.1:7432/
