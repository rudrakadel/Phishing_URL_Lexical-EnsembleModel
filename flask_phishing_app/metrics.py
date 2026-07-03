from __future__ import annotations

from collections import defaultdict
from threading import Lock


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, float] = defaultdict(float)
        self._timers: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "sum": 0.0, "max": 0.0})
        self._gauges: dict[str, float] = {}

    def increment(self, name: str, amount: float = 1.0) -> None:
        with self._lock:
            self._counters[name] += amount

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            timer = self._timers[name]
            timer["count"] += 1
            timer["sum"] += value
            timer["max"] = max(timer["max"], value)

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name} {value}")
            for name, value in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name} {value}")
            for name, values in sorted(self._timers.items()):
                lines.append(f"# TYPE {name}_seconds summary")
                lines.append(f"{name}_seconds_count {values['count']}")
                lines.append(f"{name}_seconds_sum {values['sum']}")
                lines.append(f"{name}_seconds_max {values['max']}")
        return "\n".join(lines) + "\n"
