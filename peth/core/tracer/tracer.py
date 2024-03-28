import os
import time

from web3 import Web3

JS_DIR = os.path.join(os.path.dirname(__file__), "js")


class GethTracer(object):

    def __init__(self, url: str, tracer: str, timeout: int = 60) -> None:
        """
        url: http/ws/ipc URL
        tracer: Geth tracer name or JS tracer file.
        timeout: Trace timeout in seconds.
        """
        if url.startswith("http"):
            self.provider = Web3.HTTPProvider(url, {"timeout": timeout})
        elif url.startswith("ws"):
            self.provider = Web3.WebsocketProvider(url, websocket_timeout=timeout)
        elif url.endswith("ipc"):
            self.provider = Web3.IPCProvider(url, timeout)
        else:
            raise NotImplementedError(
                "Unknown url type. HTTP/IPC/WS required. %s" % url
            )

        self.timeout = timeout
        self.web3 = Web3(self.provider)

        # from web3.middleware import geth_poa_middleware
        # # inject the poa compatibility middleware to the innermost layer (0th layer)
        # self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        if os.path.exists(tracer):
            self.tracer = open(tracer).read()
        elif os.path.exists(os.path.join(JS_DIR, tracer)):
            self.tracer = open(os.path.join(JS_DIR, tracer)).read()
        else:
            self.tracer = tracer

    def _request(self, method, args, retry_limit=2):
        retries = 1
        while True:
            try:
                return self.provider.make_request(method, args)
            except Exception as e:
                if retries > retry_limit:
                    raise Exception from e

                print(
                    "[!] Error: %s, Retry %s %s/%s with 1s delay."
                    % (str(e)[:100], method, retries, retry_limit)
                )
                time.sleep(1)
                retries += 1

    def _get_block_number(self, retry_limit=100):
        retries = 1
        while True:
            try:
                return self.web3.eth.get_block_number()
            except Exception as e:
                if retries > retry_limit:
                    raise Exception from e

                print(
                    "[!] Error: %s, Retry eth.get_block_number %s/%s with 1s delay."
                    % (e, retries, retry_limit)
                )
                time.sleep(1)
                retries += 1

    def trace_call(self, tx, block_number="latest"):
        if type(block_number) is int:
            block_number = hex(block_number)

        normalized_tx = {}
        for key, value in tx.items():
            if type(value) is float:
                value = int(value)

            if type(value) is int:
                value = hex(value)

            if type(value) is bytes:
                value = "0x" + value.hex()

            normalized_tx[key] = value

        r = self._request(
            "debug_traceCall",
            [
                normalized_tx,
                block_number,
                {"tracer": self.tracer, "timeout": "%ds" % self.timeout},
            ],
        )
        assert "result" in r, "[!] Error response. %s" % r
        return r["result"]

    def trace_transaction(self, txid):
        r = self._request(
            "debug_traceTransaction",
            [txid, {"tracer": self.tracer, "timeout": "%ds" % self.timeout}],
        )
        assert "result" in r, "[!] Error response. %s" % r
        return r["result"]

    def trace_block(self, block_number: int):
        r = self._request(
            "debug_traceBlockByNumber",
            [
                hex(block_number),
                {"tracer": self.tracer, "timeout": "%ds" % self.timeout},
            ],
        )
        assert "result" in r, "[!] Error response. %s" % r
        return r["result"]

    def enumerate_blocks(self, callback, block_start: int = 0, block_end: int = 2**63):

        if block_start:
            block_number = block_start
        else:
            block_number = self._get_block_number()

        new_number = block_number

        total_time = 0
        total_block = 0
        while block_number <= block_end:
            total_block += 1

            start = time.time()

            # callback(block_number)
            try:
                callback(block_number)
            except Exception as e:
                print("[!] error in callback(%s): %s" % (block_number, str(e)[:100]))

            end = time.time()
            total_time += end - start
            print(
                time.asctime(),
                "Block %s processed in %0.2fs (total block %s, avg %0.2fs)         \r"
                % (block_number, end - start, total_block, total_time / total_block),
                end="",
                flush=True,
            )

            # Get next block number.
            while True:
                if new_number > block_number:
                    block_number += 1
                    break

                new_number = self._get_block_number()
                if new_number > block_number:
                    block_number += 1
                    break
                else:
                    time.sleep(1)

    def can_replay_tx(self, tx, block_number="latest", sender=None) -> bool:
        """
        tx: a dict-like object with key
        """
        if type(tx) is str:
            tx = self.web3.eth.get_transaction(tx)
            block_number = tx.blockNumber - 1

        if sender is None:
            # Just a random selected new address with no ETH.
            sender = "0x4459cD4ef34A3DCeC05b32e4f76A6e4306176e6f"

        tx = {
            "from": sender,
            "to": tx["to"],
            "data": tx["input"],
            "value": tx["value"],
        }
        try:
            self.web3.eth.call(tx, block_number)
            return True
        except Exception:  # revert or other errors.
            return False

    def find_replayable_tx(self, block_number: int = 0):
        def check_replayable(block_number):
            txs = self.web3.eth.get_block(block_number, True).transactions

            for pos, tx in enumerate(txs):

                if tx.input[:10] in (
                    "0x095ea7b3",  # approve
                    "0xa22cb465",  # setApprovalForAll
                ):
                    continue

                if tx.to is None:  # create contract.
                    continue

                if tx.gas == 21000:  # ETH transfer.
                    continue

                if self.can_replay_tx(tx, block_number - 1):
                    # Can replay at prev block?
                    print(pos, tx.hash.hex())

        self.enumerate_blocks(check_replayable, block_number)
