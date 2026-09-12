from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Notification:
    subject: str
    body: str


class Notifier(Protocol):
    name: str

    async def send(self, notification: Notification) -> bool: ...
