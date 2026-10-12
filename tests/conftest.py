import json
from pathlib import Path

import pytest

EXAMPLES_PATH = Path(__file__).resolve().parents[2] / "docs" / "protocol-examples.json"


def load_examples():
    data = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))
    return {example["id"]: example for example in data["examples"]}


def example_bytes(example_id):
    example = load_examples()[example_id]
    if "hex" not in example:
        raise ValueError(f"example {example_id} has no hex field")
    return bytes.fromhex(example["hex"])


@pytest.fixture
def examples():
    return load_examples()
