"""Fakes for Kafka unit tests. No broker is required."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


class FakeKafkaError:
    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self) -> str:
        return self.message


@dataclass
class FakeMessage:
    _topic: str
    _partition: int
    _offset: int
    _value: bytes | None
    _error: Any = None

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def value(self) -> bytes | None:
        return self._value

    def error(self) -> Any:
        return self._error


@dataclass
class FakeProducer:
    """Records produce() calls and optionally fails delivery."""

    published: list[dict[str, Any]] = field(default_factory=list)
    fail_with: str | None = None
    raise_on_produce: Exception | None = None
    remaining_after_flush: int = 0

    def produce(
        self,
        topic: str,
        value: bytes | str | None = None,
        key: bytes | str | None = None,
        on_delivery: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if self.raise_on_produce is not None:
            raise self.raise_on_produce
        self.published.append({"topic": topic, "value": value, "key": key})
        if on_delivery is not None:
            err = FakeKafkaError(self.fail_with) if self.fail_with else None
            on_delivery(err, None)

    def poll(self, timeout: float) -> int:
        return 0

    def flush(self, timeout: float | None = None) -> int:
        return self.remaining_after_flush


@dataclass
class FakeConsumer:
    """Yields a predefined list of messages, then None forever."""

    messages: list[FakeMessage]
    committed: list[FakeMessage] = field(default_factory=list)
    subscribed: list[str] = field(default_factory=list)
    closed: bool = False
    _index: int = 0

    def subscribe(self, topics: list[str]) -> None:
        self.subscribed = list(topics)

    def poll(self, timeout: float) -> FakeMessage | None:
        if self._index >= len(self.messages):
            return None
        message = self.messages[self._index]
        self._index += 1
        return message

    def commit(self, message: Any = None, asynchronous: bool = False) -> None:
        if message is not None:
            self.committed.append(message)

    def close(self) -> None:
        self.closed = True
