from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from tracerloom.detection.alert import Alert
from tracerloom.events.model import NormalizedEvent


class Detector(Protocol):
    rule_id: str

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]: ...
