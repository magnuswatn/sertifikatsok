import pytest
from bonsai import LDAPSearchScope

from sertifikatsok.db import Database
from sertifikatsok.enums import (
    CertificateAuthority,
    CertType,
    Environment,
    SearchAttribute,
    SearchType,
)
from sertifikatsok.errors import ClientError
from sertifikatsok.search import LdapSearchParams, SearchParams


class TestLdapSearchParams:
    @pytest.fixture
    def database(self) -> Database:
        return Database.connect_to_database(":memory:")

    def test_should_auto_detect_url_buypass(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
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
        assert ldap_search_params.search_type == SearchType.LDAP_URL

    def test_should_auto_detect_url_commfides(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.TEST,
            CertType.PERSONAL,
            "ldap://ldap.test.commfides.com/ou=Natural-Person-G3,dc=commfides,dc=com?usercertificate;binary?sub?(certificateSerialNumber=130F751161B26168)",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
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
        assert ldap_search_params.search_type == SearchType.LDAP_URL

    def test_should_auto_detect_url_and_warn_about_wrong_env(
        self, database: Database
    ) -> None:
        search_params = SearchParams(
            Environment.TEST,
            CertType.ENTERPRISE,
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
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
        assert ldap_search_params.search_type == SearchType.LDAP_URL

    def test_should_reject_invalid_url(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "ldap://localhost/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        with pytest.raises(ClientError) as error:
            LdapSearchParams.create(search_params, database)

        assert error.value.args[0] == "Unsupported hostname in ldap url"

    def test_should_auto_detect_url_with_garbage_prefix(
        self, database: Database
    ) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "Sertifikatpeker: ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
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
        assert ldap_search_params.search_type == SearchType.LDAP_URL

    @pytest.mark.parametrize(
        ["serial", "filter"],
        [
            (
                "13:fd:31:a6:2a:a6:11:af:b6:89:82",  # hex with colons
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "13fd:31a6:2aa6:11af:b68982",  # hex with colons but weirdly spaced
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "13 fd 31 a6 2a a6 11 af b6 89 82",  # hex with spaces
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "13fd 31a6 2aa6 11af b68982",  # hex with spaces but weirdly spaced
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "13	fd	31	a6	2a	a6	11	af	b6	89	82",  # hex with tabs (wtf)
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "13fd31a62aa611afb68982",  # hex continuous
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            (
                "24165265156868740537026946",  # int
                "(certificateSerialNumber=24165265156868740537026946)",
            ),
            # Different versions of several int serial numbers
            (
                "24165265156868740537026946 24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946	24165265156868740537026947",  # tab instead of space
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946    24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946;24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946,24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946,,,24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946,24165265156868740537026947,",  # trailing comma
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946, 24165265156868740537026947",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947))",
            ),
            (
                "24165265156868740537026946 24165265156868740537026947 24165265156868740537026948",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947)(certificateSerialNumber=24165265156868740537026948))",
            ),
            (
                "24165265156868740537026946, 24165265156868740537026947,24165265156868740537026948",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947)(certificateSerialNumber=24165265156868740537026948))",
            ),
            (
                "24165265156868740537026946, 24165265156868740537026947 24165265156868740537026948",
                "(|(certificateSerialNumber=24165265156868740537026946)(certificateSerialNumber=24165265156868740537026947)(certificateSerialNumber=24165265156868740537026948))",
            ),
            # Diferent versions of serveral hex serial numbers
            (
                "248ff6242c64b12716a7 248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7	248eea0ae8b8ac87eccf",  # tab instead of space
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7    248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7;248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7,248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7,,,248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7,248eea0ae8b8ac87eccf,",  # trailing comma
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248ff6242c64b12716a7 248eea0ae8b8ac87eccf 248eea0ae8b8ac87ecdf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743)(certificateSerialNumber=172641495589408492481759))",
            ),
            (
                "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf,248eea0ae8b8ac87ecdf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743)(certificateSerialNumber=172641495589408492481759))",
            ),
            (
                "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf 248eea0ae8b8ac87ecdf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743)(certificateSerialNumber=172641495589408492481759))",
            ),
            # upper case
            (
                "248FF6242C64B12716A7 248EEA0AE8B8AC87ECCF",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248FF6242C64B12716A7	248EEA0AE8B8AC87ECCF",  # tab instead of space
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248FF6242C64B12716A7    248EEA0AE8B8AC87ECCF",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248FF6242C64B12716A7;248EEA0AE8B8AC87ECCF",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
            (
                "248FF6242C64B12716A7,248eea0ae8b8ac87eccf",
                "(|(certificateSerialNumber=172660814135891165910695)(certificateSerialNumber=172641495589408492481743))",
            ),
        ],
    )
    def test_should_auto_detect_cert_serial(
        self, serial: str, filter: str, database: Database
    ) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            serial,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.PERSONAL in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert ldap_search_params.ldap_query == filter
        assert ldap_search_params.search_type == SearchType.CERT_SERIAL

    @pytest.mark.parametrize(
        "thumbprint",
        [
            "38a6dcc494484553c8291fce2ab8d5b5311caa02",  # sha1
            "38A6DCC494484553C8291FCE2AB8D5B5311CAA02",  # sha1
            "f9d1af62d004d4da648929bc7dde552685979d6e6a78dc8f9b64eb08e9c4ccb7",  # sha2
            "F9D1AF62D004D4DA648929BC7DDE552685979D6E6A78DC8F9B64EB08E9C4CCB7",  # sha2
        ],
    )
    def test_should_auto_detect_thumbprint(
        self, thumbprint: str, database: Database
    ) -> None:

        database.insert_certificates(
            [("mordi=213,dc=MagnusCA,dc=watn,dc=no", [b"hei"])], "ldap.buypass.no"
        )

        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            thumbprint,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert len(ldap_search_params.ldap_servers) == 1
        assert ldap_search_params.ldap_query == ""
        assert (
            ldap_search_params.ldap_servers[0].base
            == "mordi=213,dc=MagnusCA,dc=watn,dc=no"
        )
        assert ldap_search_params.search_type == SearchType.THUMBPRINT

    @pytest.mark.parametrize(
        "thumbprint",
        [
            "38a6dcc494484553c8291fce2ab8d5b5311caa02",  # sha1
            "f9d1af62d004d4da648929bc7dde552685979d6e6a78dc8f9b64eb08e9c4ccb8",  # sha2
        ],
    )
    def test_should_warn_when_thumbprint_yielded_no_match(
        self, thumbprint: str, database: Database
    ) -> None:

        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            thumbprint,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.ldap_servers) == 0
        assert len(ldap_search_params.limitations) == 1
        assert ldap_search_params.limitations == ["ERR-010"]

    def test_should_auto_detect_thumbprint_handle_unknown(
        self, database: Database
    ) -> None:

        database.insert_certificates(
            [("mordi=213,dc=MagnusCA,dc=watn,dc=no", [b"hei"])], "ldap.buypass.no"
        )

        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "38a6dcc494484553c8291fce2ab8d5b5311caa01",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 1
        assert len(ldap_search_params.ldap_servers) == 0
        assert ldap_search_params.ldap_query == ""
        assert ldap_search_params.search_type == SearchType.THUMBPRINT

    @pytest.mark.parametrize("orgnr", ["995546973", "995 546 973", "NTRNO-995546973"])
    def test_should_auto_detect_org_nr_not_in_db(
        self, database: Database, orgnr: str
    ) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            orgnr,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.ENTERPRISE in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert (
            ldap_search_params.ldap_query
            == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
        )
        assert ldap_search_params.organization is None
        assert ldap_search_params.search_type == SearchType.ORG_NR

    @pytest.mark.parametrize("orgnr", ["991 056 505", "991056505", "NTRNO-991056505"])
    def test_should_auto_detect_org_nr_child(
        self, database: Database, orgnr: str
    ) -> None:

        database._connection.execute(
            """
            INSERT OR REPLACE INTO organization (orgnr, name, is_child, parent_orgnr)
            VALUES ('991056505', 'APOTEK 1 ULRIKSDAL', TRUE, '983044778')
            """
        )
        database._connection.commit()

        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            orgnr,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.ENTERPRISE in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert (
            ldap_search_params.ldap_query
            == "(&(|(serialNumber=983044778)(organizationIdentifier=NTRNO-983044778))"
            "(ou=*991056505*))"
        )
        assert ldap_search_params.organization is not None
        assert ldap_search_params.organization.name == "APOTEK 1 ULRIKSDAL"
        assert ldap_search_params.organization.orgnr == "991056505"
        assert ldap_search_params.organization.parent_orgnr == "983044778"
        assert ldap_search_params.search_type == SearchType.ORG_NR

    @pytest.mark.parametrize("orgnr", ["995 5469 73", "995546973", "NTRNO-995546973"])
    def test_should_auto_detect_org_nr_main(
        self, database: Database, orgnr: str
    ) -> None:

        database._connection.execute(
            """
            INSERT OR REPLACE INTO organization (orgnr, name, is_child)
            VALUES ('995546973', 'WATN IT SYSTEM Magnus Horsgård Watn', FALSE)
            """
        )
        database._connection.commit()

        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            orgnr,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.ENTERPRISE in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert (
            ldap_search_params.ldap_query
            == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
        )
        assert ldap_search_params.organization is not None
        assert (
            ldap_search_params.organization.name
            == "WATN IT SYSTEM Magnus Horsgård Watn"
        )
        assert ldap_search_params.organization.orgnr == "995546973"
        assert ldap_search_params.organization.parent_orgnr is None
        assert ldap_search_params.search_type == SearchType.ORG_NR

    @pytest.mark.parametrize("orgnr", ["995 5469 73", "995546973", "NTRNO-995546973"])
    def test_should_auto_detect_org_nr_main_with_parent(
        self, database: Database, orgnr: str
    ) -> None:

        database._connection.execute(
            """
            INSERT OR REPLACE INTO organization (orgnr, name, is_child, parent_orgnr)
            VALUES ('995546973', 'WATN IT SYSTEM Magnus Horsgård Watn', FALSE, '12345689')
            """
        )
        database._connection.commit()

        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            orgnr,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.ENTERPRISE in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert (
            ldap_search_params.ldap_query
            == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
        )
        assert ldap_search_params.organization is not None
        assert (
            ldap_search_params.organization.name
            == "WATN IT SYSTEM Magnus Horsgård Watn"
        )
        assert ldap_search_params.organization.orgnr == "995546973"
        assert ldap_search_params.organization.parent_orgnr == "12345689"
        assert ldap_search_params.search_type == SearchType.ORG_NR

    @pytest.mark.parametrize(
        "serial",
        [
            "9578-4500-00001pdEkL7",
            "9578-4501-00001pdEkL7",
            "9578-4502-00001pdEkL7",
            "9578-4503-00001pdEkL7",
            "9578-4504-000011pFauG",
            "9578-4505-00001pdEkL7",
            "9578-4506-00001pdEkL7",
            "9578-4507-00001pdEkL7",
            "9578-4508-00001pdEkL7",
            "9578-4509-00001cbmjW2",
            "9578-4510-00003sIhOo0",
            "UN:NO-9578-4501-00001pdEkL7",
            "UN:NO-9578-4505-00001pdEkL7",
            "UN:NO-9578-4510-00003sIhOo0",
        ],
    )
    def test_should_auto_detect_personal_serial_number_commfides(
        self, database: Database, serial: str
    ) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            serial,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert all(
            CertType.PERSONAL in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert all(
            CertificateAuthority.COMMFIDES == ldap_server.ca
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert (
            ldap_search_params.ldap_query
            == f"(|(serialNumber={serial})(serialNumber=UN:NO-{serial}))"
            or (
                ldap_search_params.ldap_query
                == f"(|(serialNumber={serial[6:]})(serialNumber={serial}))"
            )
        )
        assert ldap_search_params.search_type == SearchType.PERSONAL_SERIAL

    @pytest.mark.parametrize(
        "serial", ["9578-4050-127091783", "UN:NO-9578-4050-127091783"]
    )
    def test_should_auto_detect_personal_serial_number_buypass(
        self, database: Database, serial: str
    ) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            serial,
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert all(
            CertType.PERSONAL in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert all(
            CertificateAuthority.BUYPASS == ldap_server.ca
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert (
            ldap_search_params.ldap_query == "(|(serialNumber=9578-4050-127091783)"
            "(serialNumber=UN:NO-9578-4050-127091783))"
        )
        assert ldap_search_params.search_type == SearchType.PERSONAL_SERIAL

    def test_should_auto_detect_email(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "fornavn@etternavn.no",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert "ERR-006" in ldap_search_params.limitations
        assert all(
            CertType.PERSONAL in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert all(
            CertificateAuthority.BUYPASS == ldap_server.ca
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert ldap_search_params.ldap_query == "(mail=fornavn@etternavn.no)"
        assert ldap_search_params.search_type == SearchType.EMAIL

    def test_should_fallback_to_cn(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.PERSONAL,
            "Min supertjeneste",
            None,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.PERSONAL in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert ldap_search_params.ldap_query == "(cn=Min supertjeneste)"
        assert ldap_search_params.search_type == SearchType.FALLBACK

    def test_should_respect_attribute(self, database: Database) -> None:
        search_params = SearchParams(
            Environment.PROD,
            CertType.ENTERPRISE,
            "Min superunderenhet",
            SearchAttribute.OU,
        )

        ldap_search_params = LdapSearchParams.create(search_params, database)
        assert ldap_search_params.scope == LDAPSearchScope.SUB
        assert len(ldap_search_params.limitations) == 0
        assert all(
            CertType.ENTERPRISE in ldap_server.cert_types
            for ldap_server in ldap_search_params.ldap_servers
        )
        assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
            {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
        )
        assert ldap_search_params.ldap_query == "(ou=Min superunderenhet)"
        assert ldap_search_params.search_type == SearchType.CUSTOM
