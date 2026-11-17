/** Default alert threshold from configs/archimede.yaml (alerts.risk_score_threshold). */
export const DEFAULT_RISK_THRESHOLD = 0.7

export type RiskLevel = 'benign' | 'low' | 'elevated' | 'high' | 'harmful'

const FLAG_INFO: Record<string, { title: string; meaning: string; watch: string }> = {
  high_egress: {
    title: 'High egress',
    meaning: 'Outbound proxy/egress volume crossed the configured bucket threshold.',
    watch: 'Distinct remotes, egress_proxy_score, and any secret-bearing spans.',
  },
  high_exec_rate: {
    title: 'High exec rate',
    meaning: 'Process execs in the bucket exceeded the configured rate.',
    watch: 'argv summaries, unique binaries, and shell_tools classifications.',
  },
  mass_delete: {
    title: 'Mass delete',
    meaning: 'File deletes in the bucket exceeded the configured rate.',
    watch: 'Working directories and whether deletes target secrets or repos.',
  },
  unknown_binary_storm: {
    title: 'Unknown binary storm',
    meaning: 'Many unfamiliar binaries executed in a short window.',
    watch: 'Binary paths, parent process, and whether tools are allowlisted.',
  },
  suspicious_dns: {
    title: 'Suspicious DNS',
    meaning: 'DNS queries matched suspicious or unexpected patterns.',
    watch: 'Query names, resolving remotes, and concurrent connect events.',
  },
  elevated_risk_score: {
    title: 'Elevated risk score',
    meaning: 'Decision-model risk / risky_egress confidence crossed the alert threshold.',
    watch: 'risk_score vs threshold, behavior label probabilities, and egress_score in state.',
  },
  prompt_injection_hint: {
    title: 'Prompt injection hint',
    meaning: 'Span/session/exec text looked like an instruction-override or jailbreak attempt.',
    watch: 'LLM/tool input summaries, session transcripts, and deny/allow policy.',
  },
  remote_control_hint: {
    title: 'Remote control hint',
    meaning: 'Text or argv resembled reverse shells, remote tunnels, or operator remote-control.',
    watch: 'Exec argv, tool spans, connect remotes, and whether egress should be denied.',
  },
  secret_exfil_hint: {
    title: 'Secret exfil hint',
    meaning: 'Content resembled credentials leaving the host (keys, tokens, env dumps).',
    watch: 'Span outputs, connect destinations, and denied tools.',
  },
  unauthorized_tool: {
    title: 'Unauthorized / dangerous tool',
    meaning:
      'A harness used a denied tool (deny_tools) or a high-risk tool (shell/exec/curl/…).',
    watch: 'tool name, tool-args snippet, trace_id, and whether enforcement ran.',
  },
  shadow_binary: {
    title: 'Shadow binary',
    meaning: 'An unexpected binary path appeared for a known agent family.',
    watch: 'exec argv and parent chain.',
  },
  resource_spike: {
    title: 'Resource spike',
    meaning: 'CPU/RSS/fd delta spiked inside the monitoring bucket.',
    watch: 'resource_delta events and concurrent exec/connect volume.',
  },
  new_remote_host: {
    title: 'New remote host',
    meaning: 'The agent contacted remotes not seen recently.',
    watch: 'connect dest:port, DNS queries, and egress score.',
  },
  policy_deny: {
    title: 'Policy deny',
    meaning: 'Policy engine recorded a deny / enforcement decision.',
    watch: 'Linked enforcement row, action, and whether it was enforced.',
  },
}

export function flagInfo(flag: string) {
  return (
    FLAG_INFO[flag] ?? {
      title: flag.replaceAll('_', ' '),
      meaning: 'Policy or classifier raised this flag for the agent bucket or span.',
      watch: 'Linked agent, score, message, and any trace_id.',
    }
  )
}

export function riskLevel(score: number): RiskLevel {
  if (score >= 0.85) return 'harmful'
  if (score >= 0.7) return 'high'
  if (score >= 0.45) return 'elevated'
  if (score >= 0.2) return 'low'
  return 'benign'
}

export function riskLevelLabel(score: number): string {
  return riskLevel(score).toUpperCase()
}

export function formatScorePct(score: number): string {
  return `${(score * 100).toFixed(0)}%`
}

export function scoreVsThreshold(
  score: number,
  threshold = DEFAULT_RISK_THRESHOLD,
): { over: boolean; deltaPct: number; thresholdPct: number } {
  return {
    over: score >= threshold,
    deltaPct: Math.round((score - threshold) * 100),
    thresholdPct: Math.round(threshold * 100),
  }
}

export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function spanDurationMs(start: string, end: string | null | undefined): number | null {
  if (!end) return null
  const a = new Date(start).getTime()
  const b = new Date(end).getTime()
  if (Number.isNaN(a) || Number.isNaN(b)) return null
  return Math.max(0, b - a)
}
