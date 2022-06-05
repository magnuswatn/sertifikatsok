import pytest
from bonsai import LDAPSearchScope

from sertifikatsok.enums import (
    CertificateAuthority,
    CertType,
    Environment,
    SearchAttribute,
)
from sertifikatsok.errors import ClientError
from sertifikatsok.search import LdapSearchParams, SearchParams


class TestLdapSearchParams:
    def test_should_auto_detect_url_buypass(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.ldap_servers) == 1
        assert ldap_search_params.ldap_servers[0].hostname == "ldap.buypass.no"
        assert (
            ldap_search_params.ldap_servers[0].base
            == "dc=Buypass,dc=no,CN=Buypass Class 3"
        )
        assert ldap_search_params.ldap_servers[0].ca == CertificateAuthority.BUYPASS
        assert (
            ldap_search_params.ldap_query
            == "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))"
        )

    def test_should_auto_detect_url_commfides(self):
        search_params = SearchParams(
            Environment.TEST,
            CertType.PERSONAL,
            "ldap://ldap.test.commfides.com/ou=Natural-Person-G3,dc=commfides,dc=com?usercertificate;binary?sub?(certificateSerialNumber=130F751161B26168)",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.ldap_servers) == 1
        assert ldap_search_params.ldap_servers[0].hostname == "ldap.test.commfides.com"
        assert (
            ldap_search_params.ldap_servers[0].base
            == "ou=Natural-Person-G3,dc=commfides,dc=com"
        )
        assert ldap_search_params.ldap_servers[0].ca == CertificateAuthority.COMMFIDES
        assert (
            ldap_search_params.ldap_query
            == "(certificateSerialNumber=130F751161B26168)"
        )

    def test_should_auto_detect_url_and_warn_about_wrong_env(self):
        search_params = SearchParams(
            Environment.TEST,
            CertType.ENTERPRISE,
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        # mismatch between env and url
        assert "ERR-008" in ldap_search_params.limitations
        assert ldap_search_params.ldap_servers[0].hostname == "ldap.buypass.no"
        assert (
            ldap_search_params.ldap_servers[0].base
            == "dc=Buypass,dc=no,CN=Buypass Class 3"
        )
        assert ldap_search_params.ldap_servers[0].ca == CertificateAuthority.BUYPASS
        assert (
            ldap_search_params.ldap_query
            == "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))"
        )

    def test_should_reject_invalid_url(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "ldap://localhost/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        with pytest.raises(ClientError) as error:
            LdapSearchParams.create(search_params)

        assert error.value.args[0] == "Unsupported hostname in ldap url"

    def test_should_auto_detect_hex_serial(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "0e:79:c3:78:6b:2f:0f:af:33:fa:fb",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert len(ldap_search_params.ldap_servers) == 2
        assert (
            ldap_search_params.ldap_query
            == "(certificateSerialNumber=17499973611207260349135611)"
        )

    def test_should_auto_detect_org_nr(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "995 546 973",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert len(ldap_search_params.ldap_servers) == 2
        assert (
            ldap_search_params.ldap_query
            == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
        )

    def test_should_auto_detect_personal_serial_number(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "9578-4505-00001pdEkL7",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert (
            len(ldap_search_params.ldap_servers) == 1
            and CertificateAuthority.COMMFIDES == ldap_search_params.ldap_servers[0].ca
        )
        assert (
            ldap_search_params.ldap_query
            == "(|(serialNumber=9578-4505-00001pdEkL7)(serialNumber=UN:NO-9578-4505-00001pdEkL7))"
        )

    def test_should_auto_detect_email(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "fornavn@etternavn.no",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert "ERR-006" in ldap_search_params.limitations
        assert (
            len(ldap_search_params.ldap_servers) == 1
            and CertificateAuthority.BUYPASS == ldap_search_params.ldap_servers[0].ca
        )
        assert ldap_search_params.ldap_query == "(mail=fornavn@etternavn.no)"

    def test_should_fallback_to_cn(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "Min supertjeneste",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert len(ldap_search_params.ldap_servers) == 2
        assert ldap_search_params.ldap_query == "(cn=Min supertjeneste)"

    def test_should_respect_attribute(self):
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "Min superunderenhet",
            SearchAttribute.OU,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert len(ldap_search_params.ldap_servers) == 2
        assert ldap_search_params.ldap_query == "(ou=Min superunderenhet)"
