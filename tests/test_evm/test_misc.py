from peth.eth.evm.utils import generate_contract_address, generate_safe_contract_address


def test_gen_address():
    sender = "0x6AC7EA33F8831EA9DCC53393AAA88B25A785DBF0"
    assert (
        generate_contract_address(sender, 0)
        == "0xCD234A471B72BA2F1CCF0A70FCABA648A5EECD8D".lower()
    )
    assert (
        generate_contract_address(sender, 1)
        == "0x343C43A37D37DFF08AE8C4A11544C718ABB4FCF8".lower()
    )
    assert (
        generate_contract_address(sender, 2)
        == "0xF778B86FA74E846C4F0A1FBD1335FE81C00A0C91".lower()
    )
    assert (
        generate_contract_address(sender, 3)
        == "0xFFFD933A0BC612844EAF0C6FE3E5B8E9B6C1D19C".lower()
    )


def test_gen_address_2():
    sender = "0x00000000000000000000000000000000DEADBEEF"
    assert (
        generate_safe_contract_address(
            sender,
            0x00000000000000000000000000000000000000000000000000000000CAFEBABE,
            b"\xde\xad\xbe\xef",
        )
        == "0x60F3F640A8508FC6A86D45DF051962668E1E8AC7".lower()
    )
