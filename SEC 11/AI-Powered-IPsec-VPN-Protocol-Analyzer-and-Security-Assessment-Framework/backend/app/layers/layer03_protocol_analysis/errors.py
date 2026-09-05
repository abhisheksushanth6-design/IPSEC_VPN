"""Parser error types."""


class CaptureFormatError(ValueError):
    """The capture file is not a supported pcap or pcapng file."""


class TruncatedError(ValueError):
    """A header extends past the end of the available bytes."""

    def __init__(self, protocol: str, needed: int, available: int) -> None:
        self.protocol = protocol
        super().__init__(f"{protocol} header needs {needed} bytes, {available} available")
