from sertifikatsok import utils
from sertifikatsok.enums import SearchAttribute


def test_create_ldap_filter_one_param():
    params = [(SearchAttribute.CSN, "123")]
    filter = utils.create_ldap_filter(params)
    assert filter == "(certificateSerialNumber=123)"


def test_create_ldap_filter_one_param_escape():
    params = [(SearchAttribute.CN, "Beste virksomheten (*)")]
    filter = utils.create_ldap_filter(params)
    assert filter == r"(cn=Beste virksomheten \28\2A\29)"


def test_create_ldap_filter_several_params():
    params = [(SearchAttribute.CSN, "123"), (SearchAttribute.CSN, "345")]
    filter = utils.create_ldap_filter(params)
    assert filter == "(|(certificateSerialNumber=123)(certificateSerialNumber=345))"


def test_create_ldap_filter_several_params_escape():
    params = [
        (SearchAttribute.CN, "("),
        (SearchAttribute.OU, "*"),
        (SearchAttribute.O, ")"),
    ]
    filter = utils.create_ldap_filter(params)
    assert filter == r"(|(cn=\28)(ou=\2A)(o=\29))"


def test_convert_hex_serial_to_int_hex_continuous():
    hex = "13fd31a62aa611afb68982"
    int = "24165265156868740537026946"
    assert utils.convert_hex_serial_to_int(hex) == int


def test_convert_hex_serial_to_int_hex_spaces():
    hex = "13 fd 31 a6 2a a6 11 af b6 89 82"
    int = "24165265156868740537026946"
    assert utils.convert_hex_serial_to_int(hex) == int


def test_convert_hex_serial_to_int_hex_colon():
    hex = "13:fd:31:a6:2a:a6:11:af:b6:89:82"
    int = "24165265156868740537026946"
    assert utils.convert_hex_serial_to_int(hex) == int
