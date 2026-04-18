from bubblepwn.modules.base import parse_flags


def test_bare_positional():
    flags, pos = parse_flags(["probe"])
    assert flags == {}
    assert pos == ["probe"]


def test_key_value_space():
    flags, pos = parse_flags(["--type", "user"])
    assert flags == {"type": "user"}
    assert pos == []


def test_key_value_equals():
    flags, pos = parse_flags(["--type=user"])
    assert flags == {"type": "user"}
    assert pos == []


def test_boolean_flag():
    flags, pos = parse_flags(["--field-leak"])
    assert flags == {"field_leak": True}


def test_dash_to_underscore():
    flags, _ = parse_flags(["--batch-size", "500"])
    assert flags == {"batch_size": "500"}


def test_mixed_positional_and_flags():
    flags, pos = parse_flags(["dumpone", "user", "--max", "100", "--auth"])
    assert pos == ["dumpone", "user"]
    assert flags == {"max": "100", "auth": True}


def test_two_flags_in_a_row_without_value():
    # When --a is followed by --b, --a is treated as a bool (no value captured)
    flags, _ = parse_flags(["--a", "--b"])
    assert flags == {"a": True, "b": True}
