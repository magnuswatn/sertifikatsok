from sertifikatsok import utils
from sertifikatsok.enums import SearchAttribute


def test_create_ldap_filter_one_param() -> None:
    params = [(SearchAttribute.CSN, "123")]
    filter = utils.create_ldap_filter(params)
    assert filter == "(certificateSerialNumber=123)"


def test_create_ldap_filter_one_param_escape() -> None:
    params = [(SearchAttribute.CN, "Beste virksomheten (*)")]
    filter = utils.create_ldap_filter(params)
    assert filter == r"(cn=Beste virksomheten \28\2A\29)"


def test_create_ldap_filter_several_params() -> None:
    params = [(SearchAttribute.CSN, "123"), (SearchAttribute.CSN, "345")]
    filter = utils.create_ldap_filter(params)
    assert filter == "(|(certificateSerialNumber=123)(certificateSerialNumber=345))"


def test_create_ldap_filter_several_params_escape() -> None:
    params = [
        (SearchAttribute.CN, "("),
        (SearchAttribute.OU, "*"),
        (SearchAttribute.O, ")"),
    ]
    filter = utils.create_ldap_filter(params)
    assert filter == r"(|(cn=\28)(ou=\2A)(o=\29))"
