from .utils import get_erc20_name, get_sig, hex_to_address


class PropertyDictWrapper(object):
    """
    Covert getattr to getitem.
    Make python dict as JSObject.
    NOTE: Only used for access, NOT for writing, as we return cloned instance.

    TODO: Maybe we should use a wrapper instead of directly extending dict.
    """

    def __init__(self, raw={}):
        # We can't use `self.raw = raw` here as we had override `__setattr__`
        self.__dict__["raw"] = raw

    def __getattr__(self, key):
        value = self.raw.get(key, None)
        return PropertyDictWrapper.convert(value)

    def __setattr__(self, key, value):
        self.raw[key] = value

    def __delattr__(self, name):
        del self.raw[name]

    def __contains__(self, item):
        return item in self.raw

    def __getitem__(self, key):
        return self.__getattr__(key)

    def __setitem__(self, key, value):
        self.__setattr__(key, value)

    def __delitem__(self, key):
        self.__delattr__(key)

    def __repr__(self):
        return repr(self.raw)

    @classmethod
    def convert(cls, value):
        if type(value) is dict:
            return cls(value)
        elif type(value) is list:
            # Change it in place.
            for i, item in enumerate(value):
                value[i] = cls.convert(item)
            return value
        else:
            return value


class TxTrace(PropertyDictWrapper):

    # This should keep consistent with `logType` definition in tracer.js
    CALL = "call"
    EVENT = "event"
    EQ = "eq"
    SHA3 = "sha3"
    SLOAD = "sload"
    SSTORE = "sstore"
    CALLER = "caller"
    ORIGIN = "origin"

    def __init__(self, chain, *args, **kwargs):
        """
        Trace should be dict like:
        {
            "from": ..,
            "to": ..,
            "value": ..,
            "input": ..,
            "logs": [
                {
                    "from": ..,
                    ...
                },
                ...
            ]
        }
        """
        super().__init__(*args, **kwargs)
        self._add_ref()

        self.chain = chain

    def _add_ref(self):
        """
        Add parent/subcalls reference for facilitate our further analysis.
        """

        def set_ref(item, depth):
            if item.logType != TxTrace.CALL:
                return

            item.subcalls = []
            for i in item.logs:
                i.parent = item
                if i.logType == TxTrace.CALL:
                    item.subcalls.append(i)

        self.visit(set_ref, None, False)

    # Visitors.

    def visit_logs(self, item, onentry=None, onexit=None, depth=0, skip_revert=True):
        """
        Visit log tree with DFS with `onentry` `onexit` callback.

        If `onentry` returns True, visitor skips sub nodes.
        """

        # Skip reverted call.
        if skip_revert and item.error:
            return

        skip_subs = False
        if onentry:
            skip_subs = onentry(item, depth)

        # Visit sub nodes if call node.
        if item.logType == TxTrace.CALL and not skip_subs:
            for i in item.logs:
                self.visit_logs(i, onentry, onexit, depth + 1, skip_revert)

        # Say bye to time.
        if onexit:
            onexit(item, depth)

    def visit(self, onentry=None, onexit=None, skip_revert=True):
        """
        Visit from root.
        """
        self.visit_logs(self, onentry, onexit, 0, skip_revert)

    # Assets calculation.

    def asset_transfers(self):

        trans = []  # asset, from, to, amount

        def parse_trans(item, depth):
            if item.logType == TxTrace.CALL:
                if item.error:
                    return
                amount = int(item.value, 16)
                if amount == 0:
                    return

                trans.append(
                    (
                        "ETH",
                        hex_to_address(item["from"]),
                        hex_to_address(item.to),
                        amount,
                    )
                )

                # Trick for WETH9.
                # https://etherscan.io/address/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code
                # No Transfer event emitted in deposit/withdraw.
                if "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" in (
                    hex_to_address(item["from"]),
                    hex_to_address(item["to"]),
                ):
                    trans.append(
                        (
                            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                            hex_to_address(item.to),
                            hex_to_address(item["from"]),
                            amount,
                        )
                    )

            elif item.logType == TxTrace.EVENT:
                if not item.topics:
                    return
                if (
                    item.topics[0]
                    != "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                ):  # Transfer event.
                    return

                if len(item.topics) != 3:  # NFT transfer.
                    return

                src = hex_to_address(item.topics[1])
                dst = hex_to_address(item.topics[2])
                if item.data == "0x":
                    amount = 0
                else:
                    amount = int(item.data, 16)  # heximal

                if amount == 0:
                    return

                trans.append(
                    (
                        item.address,
                        src,
                        dst,
                        amount,
                    )
                )

        self.visit(onentry=parse_trans, skip_revert=True)
        return trans

    def asset_changes(self):
        accounts = {}  # account => (asset => changes)

        def apply_change(changes, asset, value):
            if asset not in changes:
                changes[asset] = value
            else:
                changes[asset] += value

            if changes[asset] == 0:
                del changes[asset]

        trans = self.asset_transfers()
        for asset, frm, to, value in trans:
            if frm not in accounts:
                accounts[frm] = {}
            apply_change(accounts[frm], asset, -value)
            if to not in accounts:
                accounts[to] = {}
            apply_change(accounts[to], asset, value)

        return accounts

    def print_asset_transfers(self):
        trans = self.asset_transfers()
        for asset, frm, to, value in trans:
            if asset != "ETH":
                name = get_erc20_name(asset, self.chain)
            else:
                name = "ETH"
            print("%s %s %s %s" % (frm, to, "%s(%s)" % (name, asset), value))

    def print_asset_changes(self, accounts=None):
        if accounts is None:
            accounts = self.asset_changes()

        for account, assets in accounts.items():
            print(account)
            for asset, change in assets.items():
                if asset != "ETH":
                    name = get_erc20_name(asset, self.chain)
                else:
                    name = "ETH"
                print("\t", "%s(%s)" % (name, asset), change)

    # Formatted printing.

    def print_call(self, item, depth=0):
        s = "  " * depth
        s += "%s %s > %s %s" % (
            item.type,
            item["from"],
            item.to,
            get_sig(item.input, True),
        )

        value = int(item.value, 16)
        if value:
            s += " %s wei" % value

        error = item.error
        if error:
            s += " REVERT: " + error

        print(s)

    def print_event(self, item, depth=0):
        s = "  " * depth + "Event "
        if item.topics:
            s += item.topics[0]
            s += " %s topics" % (len(item.topics))
            s += " %s bytes data" % ((len(item.data) - 2) // 2)  # remove 0x.
        else:
            s += item.data
        print(s)

    def print_sha3(self, item, depth=0):
        s = "  " * depth + "SHA3 "
        s += "%s > %s" % (item.data, item.hash)
        print(s)

    def print_sstore(self, item, depth=0):
        s = "  " * depth + "SSTORE "
        s += "[%s] %s <= %s" % (item.key, item.oldValue, item.newValue)
        print(s)

    def print_sload(self, item, depth=0):
        s = "  " * depth + "SLOAD "
        s += "[%s] => %s" % (item.key, item.value)
        print(s)

    def print_eq(self, item, depth=0):
        s = "  " * depth + "EQ "
        s += "%s == %s" % (item.v1, item.v2)
        print(s)

    def print_caller(self, item, depth=0):
        s = "  " * depth + "CALLER "
        s += "%s" % (item.caller)
        print(s)

    def print_origin(self, item, depth=0):
        s = "  " * depth + "ORIGIN "
        s += "%s" % (item.origin)
        print(s)

    def print_default(self, item, depth=0):
        s = "  " * depth + "%s " % item.logType
        print(s)

    def print_item(self, item, depth=0):
        typ = item.logType

        if typ is None:
            import IPython

            IPython.embed()

        handler = getattr(self, "print_" + typ, None)
        if handler:
            handler(item, depth)
        else:
            self.print_default(item, depth)

    def print(self, skip_revert=False):
        self.visit(onentry=self.print_item, skip_revert=skip_revert)
