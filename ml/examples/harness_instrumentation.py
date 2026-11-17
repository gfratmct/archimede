#!/usr/bin/env python3
"""Minimal custom harness instrumentation against a local Archimede daemon.

Start the daemon first:
  cargo run -p archimede -- --config configs/archimede.yaml daemon

Then:
  cd ml && pip install -e . && python examples/harness_instrumentation.py
"""

from __future__ import annotations

from archimede_ml.tracing import ArchimedeClient, generation, tool, trace


def main() -> None:
    client = ArchimedeClient(
        base_url="http://127.0.0.1:7432",
        agent="custom-harness",
        harness="example",
    )

    with trace(client, name="demo-run", metadata={"purpose": "security-obs-mvp"}):
        with generation(
            client,
            name="plan",
            model="local-demo",
            input_summary="plan a safe code edit",
        ) as gen:
            gen.end(output_summary="will edit README only", token_usage={"input": 12, "output": 8})

        with tool(client, name="read_file", input_summary="README.md") as t:
            t.end(output_summary="ok")

        # This can trip UnauthorizedTool if deny_tools includes "bash" in config.
        with tool(client, name="bash", input_summary="echo hello") as t:
            t.end(output_summary="hello")

    print("spans posted; check: archimede traces && archimede flags")


if __name__ == "__main__":
    main()
