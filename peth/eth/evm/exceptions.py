class VMExecutionError(Exception):
    pass


class InvalidJumpDestination(VMExecutionError):
    pass


class InvalidHandlerError(VMExecutionError):
    pass


class TransactionRevert(Exception):
    pass
