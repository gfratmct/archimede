# archimede-ml

Python package and scripts for validating / fine-tuning Archimede’s System-One classifier and Timestral forecasts.

## Install

```bash
pip install -e ".[dev]"
# Optional:
pip install -e ".[timestral,onnx]"
pip install git+https://github.com/mistralai/timestral.git
```

## Commands

```bash
archimede-ml validate-systemone --dataset ../tests/fixtures/labeled_buckets.jsonl --rules-only
archimede-ml validate-forecast --series-file ../tests/fixtures/exec_series.json
archimede-ml finetune-ruleset --dataset ../tests/fixtures/labeled_buckets.jsonl
```

Or run the scripts under `scripts/` directly.
