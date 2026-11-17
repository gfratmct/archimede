import { Route, Router } from "@solidjs/router";
import { Show, type ParentProps } from "solid-js";
import { Shell } from "./components/Shell";
import { MonitorProvider, useMonitor } from "./lib/monitor";
import { ToastProvider } from "./lib/toast";
import Alerts from "./pages/Alerts";
import Config from "./pages/Config";
import Enforcement from "./pages/Enforcement";
import Flags from "./pages/Flags";
import Logs from "./pages/Logs";
import Overview from "./pages/Overview";
import { TraceDetail, TracesList } from "./pages/Traces";
import "./App.css";

function Layout(props: ParentProps) {
  const m = useMonitor();
  const flagCount = () => m.flags.data()?.length ?? 0;

  return (
    <Shell
      online={m.online()}
      stats={m.stats.data()}
      refreshedAt={m.stats.refreshedAt()}
      notifyEnabled={m.browserOk()}
      onEnableNotify={() => void m.requestPermission()}
      onClearAll={() => void m.clearAll()}
      clearing={m.clearing()}
      flagCount={flagCount()}
    >
      <Show when={m.health.error()}>
        <p class="error-banner sticky-banner">
          Cannot reach Archimede API at this origin. Start the daemon on :7432
          (or use `npm run dev` which proxies). {m.health.error()}
        </p>
      </Show>
      {props.children}
    </Shell>
  );
}

function OverviewPage() {
  const m = useMonitor();
  return (
    <Overview
      stats={m.stats.data}
      alerts={m.alerts.data}
      flagCount={() => m.flags.data()?.length ?? 0}
    />
  );
}

function AlertsPage() {
  const m = useMonitor();
  return (
    <Alerts
      alerts={m.alerts.data}
      loading={m.alerts.loading}
      error={m.alerts.error}
      onRefresh={() => void m.alerts.refresh()}
    />
  );
}

function FlagsPage() {
  const m = useMonitor();
  return (
    <Flags
      flags={m.flags.data}
      loading={m.flags.loading}
      error={m.flags.error}
      onRefresh={() => void m.flags.refresh()}
    />
  );
}

function LogsPage() {
  const m = useMonitor();
  return (
    <Logs
      logs={m.logs.data}
      agents={m.agents}
      loading={m.logs.loading}
      error={m.logs.error}
      onRefresh={() => void m.logs.refresh()}
      agentFilter={m.agentFilter}
      setAgentFilter={m.setAgentFilter}
    />
  );
}

function Root(props: ParentProps) {
  return (
    <ToastProvider>
      <MonitorProvider>
        <Layout>{props.children}</Layout>
      </MonitorProvider>
    </ToastProvider>
  );
}

export default function App() {
  return (
    <Router root={Root}>
      <Route path="/" component={FlagsPage} />
      <Route path="/overview" component={OverviewPage} />
      <Route path="/alerts" component={AlertsPage} />
      <Route path="/flags" component={FlagsPage} />
      <Route path="/logs" component={LogsPage} />
      <Route path="/traces" component={TracesList} />
      <Route path="/traces/:id" component={TraceDetail} />
      <Route path="/enforcement" component={Enforcement} />
      <Route path="/config" component={Config} />
    </Router>
  );
}
