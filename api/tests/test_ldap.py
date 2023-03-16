from sertifikatsok.enums import CertificateAuthority, SearchAttribute
from sertifikatsok.ldap import LdapFilter, LdapServer

NORMAL_CA = LdapServer("", "", CertificateAuthority.BUYPASS, [])

DOUBLE_TROUBLE_CA = LdapServer(
    "", "", CertificateAuthority.BUYPASS, [], need_double_csn_search=True
)


def test_ldap_filter_one_param() -> None:
    params = [(SearchAttribute.OU, "123")]
    filter = LdapFilter.create_from_params(params)
    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == "(ou=123)"
    )


def test_ldap_filter_one_param_escape() -> None:
    params = [(SearchAttribute.CN, "Beste virksomheten (*)")]
    filter = LdapFilter.create_from_params(params)
    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == r"(cn=Beste virksomheten \28\2A\29)"
    )


def test_ldap_filter_several_params() -> None:
    params = [(SearchAttribute.SN, "123"), (SearchAttribute.SN, "345")]
    filter = LdapFilter.create_from_params(params)

    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == "(|(serialNumber=123)(serialNumber=345))"
    )


def test_ldap_filter_several_params_escape() -> None:
    params = [
        (SearchAttribute.CN, "("),
        (SearchAttribute.OU, "*"),
        (SearchAttribute.O, ")"),
    ]
    filter = LdapFilter.create_from_params(params)
    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == r"(|(cn=\28)(ou=\2A)(o=\29))"
    )


def test_ldap_filter_several_csn_params_hex() -> None:
    # When created like this, they should not get double
    params = [
        (SearchAttribute.CSN, "F1F457DB1710C37"),
        (SearchAttribute.CSN, "F1C25FCD50BE077"),
    ]
    filter = LdapFilter.create_from_params(params)

    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == "(|(certificateSerialNumber=F1F457DB1710C37)(certificateSerialNumber=F1C25FCD50BE077))"
    )


def test_ldap_filter_create_for_one_cert_serial() -> None:
    filter = LdapFilter.create_for_cert_serials([31232453421313341])

    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == "(certificateSerialNumber=31232453421313341)"
    )
    assert (
        filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == "(|(certificateSerialNumber=31232453421313341)(certificateSerialNumber=6ef5c03ba42d3d))"
    )


def test_ldap_filter_create_for_several_cert_serial() -> None:
    filter = LdapFilter.create_for_cert_serials([123, 345])

    assert (
        str(filter)
        == filter.get_for_ldap_server(NORMAL_CA)
        == "(|(certificateSerialNumber=123)(certificateSerialNumber=345))"
    )
    assert (
        filter.get_for_ldap_server(DOUBLE_TROUBLE_CA)
        == "(|(certificateSerialNumber=123)(certificateSerialNumber=7b)"
        "(certificateSerialNumber=345)(certificateSerialNumber=159))"
    )
