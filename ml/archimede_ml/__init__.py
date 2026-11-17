"""Archimede ML: validate/fine-tune models and instrument harness traces."""

from archimede_ml.tracing import ArchimedeClient, generation, span, tool, trace

__version__ = "0.1.0"
__all__ = [
    "ArchimedeClient",
    "generation",
    "span",
    "tool",
    "trace",
    "__version__",
]
