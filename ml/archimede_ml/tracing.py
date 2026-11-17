"""Langfuse-like security tracing SDK for Archimede harnesses.

Posts traces/spans to a local Archimede daemon (default http://127.0.0.1:7432).
Security flags are evaluated server-side from span attributes and host telemetry.
"""

from __future__ import annotations

import contextlib
import contextvars
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import httpx

_current_trace: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "archimede_trace_id", default=None
)
_current_span: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "archimede_span_id", default=None
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ArchimedeClient:
    base_url: str = "http://127.0.0.1:7432"
    agent: Optional[str] = None
    harness: Optional[str] = None
    timeout: float = 5.0

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url.rstrip("/"), timeout=self.timeout)

    def create_trace(
        self,
        *,
        name: Optional[str] = None,
        trace_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        tid = trace_id or str(uuid.uuid4())
        payload = {
            "trace_id": tid,
            "name": name,
            "agent": self.agent,
            "harness": self.harness,
            "session_id": session_id,
            "user_id": user_id,
            "metadata": metadata or {},
            "start_ts": _now(),
        }
        with self._client() as client:
            r = client.post("/v1/traces", json=payload)
            r.raise_for_status()
        return tid

    def post_span(self, span: dict[str, Any]) -> None:
        with self._client() as client:
            r = client.post("/v1/spans", json=span)
            r.raise_for_status()

    def post_spans(self, spans: list[dict[str, Any]]) -> None:
        with self._client() as client:
            r = client.post("/v1/spans", json={"spans": spans})
            r.raise_for_status()


@dataclass
class _SpanCtx:
    client: ArchimedeClient
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: str
    model: Optional[str] = None
    input_summary: Optional[str] = None
    output_summary: Optional[str] = None
    attrs: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    token_usage: Optional[dict[str, int]] = None
    start_ts: str = field(default_factory=_now)

    def end(
        self,
        *,
        output_summary: Optional[str] = None,
        status: Optional[str] = None,
        token_usage: Optional[dict[str, int]] = None,
        attrs: Optional[dict[str, Any]] = None,
    ) -> None:
        if output_summary is not None:
            self.output_summary = output_summary
        if status is not None:
            self.status = status
        if token_usage is not None:
            self.token_usage = token_usage
        if attrs:
            self.attrs.update(attrs)
        payload = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind,
            "agent": self.client.agent,
            "harness": self.client.harness,
            "model": self.model,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "attrs": self.attrs,
            "start_ts": self.start_ts,
            "end_ts": _now(),
            "status": self.status,
            "token_usage": self.token_usage,
        }
        self.client.post_span(payload)


@contextlib.contextmanager
def trace(
    client: ArchimedeClient,
    name: str = "trace",
    *,
    metadata: Optional[dict[str, Any]] = None,
    session_id: Optional[str] = None,
) -> Iterator[str]:
    """Open a trace and set it as the current context."""
    tid = client.create_trace(name=name, metadata=metadata, session_id=session_id)
    token = _current_trace.set(tid)
    try:
        yield tid
    finally:
        _current_trace.reset(token)


@contextlib.contextmanager
def span(
    client: ArchimedeClient,
    name: str,
    *,
    kind: str = "custom",
    trace_id: Optional[str] = None,
    model: Optional[str] = None,
    input_summary: Optional[str] = None,
    attrs: Optional[dict[str, Any]] = None,
) -> Iterator[_SpanCtx]:
    """Generic span context manager."""
    tid = trace_id or _current_trace.get() or client.create_trace(name=name)
    parent = _current_span.get()
    ctx = _SpanCtx(
        client=client,
        trace_id=tid,
        span_id=str(uuid.uuid4()),
        parent_span_id=parent,
        name=name,
        kind=kind,
        model=model,
        input_summary=input_summary,
        attrs=dict(attrs or {}),
    )
    token = _current_span.set(ctx.span_id)
    try:
        yield ctx
        ctx.end()
    except Exception as exc:  # noqa: BLE001
        ctx.end(status="error", output_summary=str(exc)[:500])
        raise
    finally:
        _current_span.reset(token)


@contextlib.contextmanager
def generation(
    client: ArchimedeClient,
    name: str = "generation",
    *,
    model: Optional[str] = None,
    input_summary: Optional[str] = None,
    attrs: Optional[dict[str, Any]] = None,
) -> Iterator[_SpanCtx]:
    with span(
        client,
        name,
        kind="llm",
        model=model,
        input_summary=input_summary,
        attrs=attrs,
    ) as ctx:
        yield ctx


@contextlib.contextmanager
def tool(
    client: ArchimedeClient,
    name: str,
    *,
    input_summary: Optional[str] = None,
    attrs: Optional[dict[str, Any]] = None,
) -> Iterator[_SpanCtx]:
    tool_attrs = {"tool": name, **(attrs or {})}
    with span(
        client,
        name,
        kind="tool",
        input_summary=input_summary,
        attrs=tool_attrs,
    ) as ctx:
        yield ctx
