from typing import Self

from cypcap import create, PcapIf, Pcap, Direction, Pkthdr

__all__ = "Sniffer",

class Sniffer:

    __slots__ = "device", "promiscuous", "monitor", "count", "timeout", "counter"

    def __init__(self, device: str | PcapIf, promiscuous: bool = False, monitor: bool = False, count: int = 0, timeout: float = 0.0) -> None:
        """
        A class that makes it easy to iterate over sniffed packets.
        """
        self.device: Pcap = create(device)
        self.promiscuous: bool = promiscuous
        self.monitor: bool = monitor
        self.count: int = count
        self.timeout: float = timeout

        self.counter: int = 0

        if self.monitor and not self.device.can_set_rfmon():
            raise ValueError(f"{self.device.source} does not support monitor mode.")

        self.device.set_promisc(self.promiscuous)
        self.device.set_rfmon(self.monitor)
        self.device.set_immediate_mode(True)

        if 0.0 < self.timeout:
            self.device.set_timeout(self.timeout)


    def activate(self) -> None:
        self.device.activate()
        self.device.setdirection(Direction.INOUT)

    def close(self) -> None:
        self.device.close()

    def __enter__(self) -> Self:
        self.activate()
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self.close()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[Pkthdr, bytes]:
        if 0 < self.count <= self.counter:
            raise StopIteration("Limit reached.")

        self.counter += 1

        return next(self.device)

    def datalink_types(self) -> tuple[int, ...]:
        return tuple(sorted(map(int, self.device.list_datalinks())))
