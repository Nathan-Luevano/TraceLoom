from pathlib import Path

import pytest


@pytest.fixture
def fixture_dataset_root() -> Path:
    return Path(__file__).parent / "fixtures" / "dataset"
