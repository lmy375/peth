from peth.console import PethConsole


def test_parse_args_tuple():
    console = PethConsole(None)
    result = console._parse_args("1 foo", ("number", "string"))
    assert result == [1, "foo"]
