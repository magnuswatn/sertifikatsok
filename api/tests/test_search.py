from sertifikatsok.enums import (
    CertificateAuthority,
    CertType,
    Environment,
    SearchAttribute,
)
from bonsai import LDAPSearchScope
from sertifikatsok.search import LdapSearchParams, SearchParams


class TestLdapSearchParams:
    def test_should_auto_detect_url(self):
        search_params = SearchParams(
            Environment.TEST,
            CertType.ENTERPRISE,
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert "ERR-007" in ldap_search_params.limitations
        assert (
            len(ldap_search_params.ca_s) == 1
            and CertificateAuthority.BUYPASS in ldap_search_params.ca_s
        )
        assert (
            ldap_search_params.ldap_query
            == "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))"
        )

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
        assert len(ldap_search_params.ca_s) == 2
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
        assert len(ldap_search_params.ca_s) == 2
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
            len(ldap_search_params.ca_s) == 1
            and CertificateAuthority.COMMFIDES in ldap_search_params.ca_s
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
            len(ldap_search_params.ca_s) == 1
            and CertificateAuthority.BUYPASS in ldap_search_params.ca_s
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
        assert len(ldap_search_params.ca_s) == 2
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
        assert len(ldap_search_params.ca_s) == 2
        assert ldap_search_params.ldap_query == "(ou=Min superunderenhet)"
