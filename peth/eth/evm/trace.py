import json
from typing import List, Optional

from ..opcodes import OpCode


class Step(object):
    def __init__(
        self,
        pc: int,
        op: str,
        depth: int = 0,
        stack: Optional[List[int]] = None,
        msg: Optional[str] = None,
    ) -> None:
        self.pc = pc
        self.op = op
        self.depth = depth
        self.stack = stack
        self.msg = msg

    def __str__(self):
        depth_pc = f"[{self.depth}-{self.pc}]"
        stack = ",".join(hex(i) for i in self.stack[::-1])  # reverse.
        return "%-10s %-20s %-100s %-10s" % (depth_pc, self.op, self.msg, stack)

    def print(self, full=False):
        depth_pc = f"[{self.depth}-{self.pc}]"
        s = "%-10s %-20s %-100s" % (depth_pc, self.op, self.msg)
        if full:
            stack = ",".join(hex(i) for i in self.stack[::-1])
            s += " %-10s" % stack
        print(s)

    @classmethod
    def fromJSON(cls, d):
        pc = d["pc"]
        op = d["op"]
        depth = d["depth"]
        stack = None
        if "stack" in d:
            stack = [int(i, 16) for i in d["stack"]]
        msg = None
        return cls(pc, op, depth, stack, msg)

    def same_as(self, other: "Step", check_stack=True) -> bool:
        if self.depth != other.depth or self.pc != other.pc or self.op != other.op:
            return False

        if self.msg and other.msg and self.msg != other.msg:
            return False

        if check_stack and self.stack and other.stack and self.stack != other.stack:
            return False

        return True


class Trace(object):
    def __init__(self) -> None:
        self.steps: List[Step] = []

    def pre_trace(
        self, pc: int, op: int, depth: int, stack: List[int], msg: Optional[str] = None
    ):
        self.steps.append(Step(pc, op, depth, stack, msg))

    @property
    def current_step(self) -> Step:
        if self.steps:
            return self.steps[-1]
        else:
            return None

    def post_trace(self, pc: int, msg: str):
        """
        Used in evm. Do this after interpreting the instruction, so
        we are able to collect the result here.

        This should be used with `pre_trace` in pairs.
        """
        step = self.current_step
        assert pc == step.pc
        step.msg = msg

    def add_sub_trace(self, other: "Trace") -> None:
        self.steps += other.steps

    def compare(self, other: "Trace", outputfile: Optional[str] = None) -> bool:
        self_size = len(self.steps)
        other_size = len(other.steps)

        if outputfile is None and self_size != other_size:
            # When we don't care about the detail, we can return earlier.
            return False

        if outputfile:
            f = open(outputfile, "w")
            f.write(
                "%-10s %-10s %-20s %-100s %-10s\n"
                % ("Index", "PC", "OpCode", "Message", "Stack")
            )

        for i, (this, that) in enumerate(zip(self.steps, other.steps)):

            if not this.same_as(that, False):  #
                break

            if this.same_as(that):
                if outputfile:
                    f.write("%-10s %s\n" % (i, this))
            else:
                if outputfile:
                    f.write(">>>> %-10s %s\n" % (i, this))
                    f.write(">>>> %-10s %s\n" % (i, that))

        if outputfile:
            # print more lines.
            f.write("\n" + "=" * 100 + "\n\n")

            end = min(i + 200, self_size, other_size)
            for j in range(i, end):
                this = self.steps[j]
                that = other.steps[j]
                if this.same_as(that):
                    f.write("%-10s %s\n" % (i, this))
                else:
                    f.write(">>>> %-10s %s\n" % (i, this))
                    f.write(">>>> %-10s %s\n" % (i, that))

            if self_size != other_size:
                f.write(f"Different size: {self_size} vs {other_size}")

            f.close()

        return self_size == other_size

    def compare_debug_trace_transaction(
        self, tracefile: str, outputfile: Optional[str] = None
    ):
        trace = json.load(open(tracefile))["structLogs"]
        other = Trace()
        for d in trace:
            other.steps.append(Step.fromJSON(d))

        return self.compare(other, outputfile)

    def print(self, level=2):
        for step in self.steps:
            if OpCode.from_mnemonic(step.op).print_level <= level:
                step.print()
