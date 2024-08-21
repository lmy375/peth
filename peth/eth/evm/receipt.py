from typing import Optional

import eth_abi

from .trace import Trace


class Receipt(object):
    """
    Transcation result or EVM execution result.

    Default success.
    """

    def __init__(self, error=None) -> None:
        self.error = error
        self.reverted = False
        self.returndata = b""
        self.stack = []
        self.memory = bytearray(0)
        self.trace = Trace()
        self.event_logs = []
        self.created_contract = None  # Only used in contract creation.

        # for debug.
        self.tx = None

    @property
    def stack_top(self) -> Optional[int]:
        if self.stack:
            return self.stack[-1]

    @property
    def success(self) -> bool:
        return self.error is None and not self.reverted

    def __str__(self) -> str:
        buf = ""
        if self.tx:
            buf += f"[TX {self.tx.depth}-{self.tx.id}] "

        if self.reverted:
            buf += "Revert"

        elif self.error:
            buf += "Error"
        else:
            buf += "Success"

        if self.created_contract:
            buf += f" create: {self.created_contract}"

        if self.returndata:
            if self.reverted:
                try:
                    buf += (
                        " message: "
                        + eth_abi.decode_single("(string)", self.returndata[4:])[0]
                    )
                except Exception:
                    buf += f" revert({len(self.returndata)}): {self.returndata[:40].hex()}..."
            else:
                buf += f" returndata({len(self.returndata)}): {self.returndata[:40].hex()}..."

        return buf
