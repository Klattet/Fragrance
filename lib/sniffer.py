from typing import Self, Optional, Generator, Any
from threading import Timer

from pyshark import LiveCapture

__all__ = "Sniffer",

class Sniffer:

    __slots__ = "capture", "interface", "monitor", "count", "timeout", "iterator", "activated_at", "yielded_count"

    def __init__(self, interface: Optional[str] = None, monitor: bool = False, count: Optional[int] = None, timeout: Optional[float] = None) -> None:
        """
        A class that makes it easy to iterate over sniffed packets.
        """
        self.capture: LiveCapture = LiveCapture(
            interface = interface,
            monitor_mode = monitor
        )
        self.interface: str = interface
        self.monitor: bool = monitor
        self.count: Optional[int] = count
        self.timeout: Optional[float] = timeout

    def activate(self) -> None:
        self.capture.sniff(packet_count = self.count, timeout = self.timeout)

    def close(self) -> None:
        self.capture.close()

    def __enter__(self) -> Self:
        self.activate()
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self.close()

    def __iter__(self) -> Generator[Any, Any, None]:
        generator: Generator[Any, Any, None] = self.capture.sniff_continuously(packet_count = self.count)
        if self.timeout is not None:
            timer: Timer = Timer(self.timeout, generator.close)
            timer.start()
        yield from generator
