"""Client and validation helpers for open System-One (/v1/systemone) servers."""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_LABELS = [
    "idle",
    "planning",
    "coding",
    "testing",
    "shell_tools",
    "browsing",
    "llm_wait",
    "risky_egress",
]


class SystemOneClient:
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8017/v1/systemone",
        model: str = "jev-latest",
        timeout: float = 2.0,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.timeout = timeout

    def decide(self, state: str, questions: dict[str, Any]) -> dict[str, Any]:
        payload = {"model": self.model, "state": state, "questions": questions}
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(self.endpoint, json=payload)
            r.raise_for_status()
            return r.json()

    def classify_behavior(
        self, state: str, labels: list[str] | None = None
    ) -> tuple[str, float, dict[str, float]]:
        labels = labels or DEFAULT_LABELS
        questions = {
            "behavior": {
                "type": "choice",
                "instructions": "Classify the primary agent behavior for this monitoring bucket.",
                "choices": labels,
            },
            "risk": {
                "type": "score",
                "instructions": "Score security risk from 0 (benign) to 1 (harmful).",
            },
        }
        data = self.decide(state, questions)
        answers = data.get("answers") or data
        ans = answers.get("behavior") or {}
        probs = ans.get("probabilities") or {}
        if ans.get("choice"):
            label = ans["choice"]
            conf = float(probs.get(label, ans.get("confidence", 0.55)))
        elif probs:
            label, conf = max(probs.items(), key=lambda kv: kv[1])
            conf = float(conf)
        else:
            label, conf = "idle", 0.3
        return label, conf, {k: float(v) for k, v in probs.items()}


def rule_classify(bucket: dict[str, Any]) -> tuple[str, float]:
    """Mirror of Rust rule fallback for offline validation."""
    scores: dict[str, float] = {"idle": 0.1}
    if (
        bucket.get("exec_count", 0) == 0
        and bucket.get("session_events", 0) == 0
        and bucket.get("socket_count", 0) == 0
    ):
        scores["idle"] = 0.9
    if bucket.get("coding_hints", 0) or bucket.get("files_written", 0):
        scores["coding"] = 0.4 + 0.1 * min(5, int(bucket.get("coding_hints", 0)))
    if bucket.get("shell_hints", 0) or bucket.get("exec_count", 0) > 3:
        scores["shell_tools"] = 0.35 + 0.08 * min(6, int(bucket.get("shell_hints", 0)))
    if bucket.get("llm_wait_hints", 0):
        scores["llm_wait"] = 0.4 + 0.1 * min(5, int(bucket.get("llm_wait_hints", 0)))
    if bucket.get("files_deleted", 0) > 5 or bucket.get("egress_proxy_score", 0) > 20:
        scores["risky_egress"] = 0.75
    label, conf = max(scores.items(), key=lambda kv: kv[1])
    return label, conf


def bucket_to_state(bucket: dict[str, Any]) -> str:
    return (
        f"agent={bucket.get('agent')}; execs={bucket.get('exec_count', 0)}; "
        f"binaries={bucket.get('unique_binaries', 0)}; writes={bucket.get('files_written', 0)}; "
        f"deletes={bucket.get('files_deleted', 0)}; sockets={bucket.get('socket_count', 0)}; "
        f"remotes={bucket.get('distinct_remotes', 0)}; sessions={bucket.get('session_events', 0)}; "
        f"cpu_max={bucket.get('cpu_pct_max', 0)}; rss_max={bucket.get('rss_bytes_max', 0)}; "
        f"egress_score={bucket.get('egress_proxy_score', 0)}; "
        f"llm_wait={bucket.get('llm_wait_hints', 0)}; shell={bucket.get('shell_hints', 0)}; "
        f"coding={bucket.get('coding_hints', 0)}"
    )
