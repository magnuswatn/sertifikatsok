from itertools import permutations

import pytest

from ruldap3 import Scope
from sertifikatsok.constants import MAX_SERIAL_NUMBER_COUNT
from sertifikatsok.db import Database
from sertifikatsok.enums import (
    CertificateAuthority,
    CertType,
    Environment,
    SearchAttribute,
    SearchType,
)
from sertifikatsok.errors import ClientError
from sertifikatsok.ldap import LdapCertificateEntry, LdapFilter, LdapServer
from sertifikatsok.search import LdapSearchParams, SearchParams


@pytest.fixture
def database() -> Database:
    return Database.connect_to_database(":memory:")


@pytest.mark.parametrize(
    [
        "ldap_url",
        "expected_scope",
        "expected_hostname",
        "expected_base",
        "expected_ca",
        "expected_query",
    ],
    [
        (
            "ldap://ldap.buypass.no",
            Scope.BASE,
            "ldap.buypass.no",
            "",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/",
            Scope.BASE,
            "ldap.buypass.no",
            "",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/?",
            Scope.BASE,
            "ldap.buypass.no",
            "",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no?",
            Scope.BASE,
            "ldap.buypass.no",
            "",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203",
            Scope.BASE,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203????",
            Scope.BASE,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203??sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?*?sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?%2A?sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?%2A?sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?%2A?sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?*?sub??",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
            "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
        ),
        (
            "ldap://ldap.test.commfides.com/ou=Natural-Person-G3,dc=commfides,dc=com?usercertificate;binary?sub?(certificateSerialNumber=130F751161B26168)",
            Scope.SUB,
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA?usercertificate;binary?sub?sn=817920632",
            Scope.SUB,
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA",
            CertificateAuthority.BUYPASS,
            "sn=817920632",
        ),
        (
            "ldap://ldap.test4.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20Test4%20CA%203?usercertificate;binary?sub?(|(certificateSerialNumber=6037264911774452840947791)(certificateSerialNumber=6037281003928955883830016)(certificateSerialNumber=2702531723605056595025380)(certificateSerialNumber=2702541841969098455178190))",
            Scope.SUB,
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            "(|(certificateSerialNumber=6037264911774452840947791)(certificateSerialNumber=6037281003928955883830016)(certificateSerialNumber=2702531723605056595025380)(certificateSerialNumber=2702541841969098455178190))",
        ),
        (
            "ldap://ldap.commfides.com/ou=Enterprise,dc=commfides,dc=com?usercertificate;binary?sub?(|(certificateSerialNumber=4ccf299b219b43c24d5887ab626010d01ee3e609)(certificateSerialNumber=449371eda29b8802af8a3cb3639381c09d805e09)(certificateSerialNumber=298409dc176f1b9e6f07e9fed71dc44194785833))",
            Scope.SUB,
            "ldap.commfides.com",
            "ou=Enterprise,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            "(|(certificateSerialNumber=4ccf299b219b43c24d5887ab626010d01ee3e609)(certificateSerialNumber=449371eda29b8802af8a3cb3639381c09d805e09)(certificateSerialNumber=298409dc176f1b9e6f07e9fed71dc44194785833))",
        ),
        (
            "ldap://ldap.test4.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20Test4%20CA%203?usercertificate;binary?sub?(cn=Silje%20Fos%20Port)",
            Scope.SUB,
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            "(cn=Silje Fos Port)",
        ),
        (
            "ldap://ldap.test.commfides.com/ou=Natural-Person-G3,dc=commfides,dc=com?userCertificate;binary?sub?(certificateSerialNumber=130F751161B26168)",
            Scope.SUB,
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
        (
            "ldap://ldap.test.commfides.com/ou=Natural-Person-G3,dc=commfides,dc=com?userCertificate;binary,certificateSerialNumber?sub?(certificateSerialNumber=130F751161B26168)",
            Scope.SUB,
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
        (
            "ldap://ldap.test.commfides.com:389/ou=Natural-Person-G3,dc=commfides,dc=com?userCertificate;binary,certificateSerialNumber?sub?(certificateSerialNumber=130F751161B26168)",
            Scope.SUB,
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
        (
            "ldap://ldap.test4.buypass.no/pssUniqueIdentifier%3D185003%2Cdc%3DBuypass%2Cdc%3Dno%2CCN%3DBuypass%20Class%203%20Test4%20CA%203?usercertificate%3Bbinary??(objectClass=*)",
            Scope.BASE,
            "ldap.test4.buypass.no",
            "pssUniqueIdentifier=185003,dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "LDAP://LDAP.TEST4.BUYPASS.NO/pssUniqueIdentifier%3D185003%2Cdc%3DBuypass%2Cdc%3Dno%2CCN%3DBuypass%20Class%203%20Test4%20CA%203?usercertificate;binary?SUB?(objectClass=*)",
            Scope.SUB,
            "ldap.test4.buypass.no",
            "pssUniqueIdentifier=185003,dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            "(objectClass=*)",
        ),
        (
            "ldap://ldap.test.commfides.com?userCertificate;binary,certificateSerialNumber?sub?(certificateSerialNumber=130F751161B26168)",
            Scope.SUB,
            "ldap.test.commfides.com",
            "",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
        (
            "ldap://ldap.test.commfides.com?userCertificate;binary,certificateSerialNumber?sub?(certificateSerialNumber=130F751161B26168)?e-bindname=cn=Manager%2cdc=example%2cdc=com",
            Scope.SUB,
            "ldap.test.commfides.com",
            "",
            CertificateAuthority.COMMFIDES,
            "(certificateSerialNumber=130F751161B26168)",
        ),
    ],
)
def test_should_auto_detect_url(
    database: Database,
    ldap_url: str,
    expected_scope: Scope,
    expected_hostname: str,
    expected_base: str,
    expected_ca: CertificateAuthority,
    expected_query: str,
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        ldap_url,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == expected_scope
    assert len(ldap_search_params.ldap_servers) == 1
    assert ldap_search_params.ldap_servers[0].hostname == expected_hostname
    assert ldap_search_params.ldap_servers[0].base == expected_base
    assert ldap_search_params.ldap_servers[0].ca == expected_ca
    assert str(ldap_search_params.ldap_query) == expected_query
    assert ldap_search_params.search_type == SearchType.LDAP_URL


def test_should_auto_detect_url_and_warn_about_wrong_env(database: Database) -> None:
    search_params = SearchParams(
        Environment.TEST,
        CertType.ENTERPRISE,
        "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    # mismatch between env and url
    assert "ERR-008" in ldap_search_params.limitations
    assert ldap_search_params.ldap_servers[0].hostname == "ldap.buypass.no"
    assert (
        ldap_search_params.ldap_servers[0].base == "dc=Buypass,dc=no,CN=Buypass Class 3"
    )
    assert ldap_search_params.ldap_servers[0].ca == CertificateAuthority.BUYPASS
    assert (
        str(ldap_search_params.ldap_query)
        == "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))"
    )
    assert ldap_search_params.search_type == SearchType.LDAP_URL


@pytest.mark.parametrize(
    ("query", "errormsg"),
    [
        (
            "ldap:///dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Hostname is required in ldap url",
        ),
        (
            "ldap://localhost/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Disallowed hostname in ldap url",
        ),
        (
            "ldap://ldap.buypass.no:mordi/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid port in ldap url",
        ),
        (
            "ldap://ldap.buypass.no:388/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Unsupported port in ldap url",
        ),
        (
            "ldap://ldap.test.commfides.com?userCertificate;binary,certificateSerialNumber?sub?(certificateSerialNumber=130F751161B26168)?e-bindname=cn=Manager%2cdc=example%2cdc=com???",
            "Malformed query in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?certificateRevocationList;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid attribute\\(s\\) in ldap url: 'usercertificate;binary' is required",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?supersub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid scope in url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051)))",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?((|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?certificateSerialNumber=912052)",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051)).",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?((certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?((|certificateSerialNumber=912052)(certificateSerialNumber=912051))",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.test4.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20Test4%20CA%203?usercertificate;binary?sub?(|(certificateSerialNumber=2702531723605056595025380)(certificateSerialNumber=2702541841969098455178190))'",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.commfides.com/ou=Person-High,dc=commfides,dc=com?usercertificate;binary?sub?(|(certificateSerialNumber=6785900982646169401)(certificateSerialNumber=5124756047439246454)(certificateSerialNumber=1158136303048187837)%29)",
            "Invalid filter in ldap url",
        ),
        (
            "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))?!e-bindname=cn=Manager%2cdc=example%2cdc=com",
            "Unsupported critical extension in ldap url",
        ),
    ],
)
def test_should_reject_invalid_url(
    database: Database, query: str, errormsg: str
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        query,
        None,
    )

    with pytest.raises(ClientError) as error:
        LdapSearchParams.create(search_params, database)

    assert error.match(errormsg)


def test_should_auto_detect_url_with_garbage_prefix(database: Database) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        "Sertifikatpeker: ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203?usercertificate;binary?sub?(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))",
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.ldap_servers) == 1
    assert ldap_search_params.ldap_servers[0].hostname == "ldap.buypass.no"
    assert (
        ldap_search_params.ldap_servers[0].base == "dc=Buypass,dc=no,CN=Buypass Class 3"
    )
    assert ldap_search_params.ldap_servers[0].ca == CertificateAuthority.BUYPASS
    assert (
        str(ldap_search_params.ldap_query)
        == "(|(certificateSerialNumber=912052)(certificateSerialNumber=912051))"
    )
    assert ldap_search_params.search_type == SearchType.LDAP_URL


@pytest.mark.parametrize(
    ["serial", "expected_searched_for_serial_numbers"],
    [
        (
            "13:fd:31:a6:2a:a6:11:af:b6:89:82",  # hex with colons
            ["24165265156868740537026946"],
        ),
        (
            "13fd:31a6:2aa6:11af:b68982",  # hex with colons but weirdly spaced
            ["24165265156868740537026946"],
        ),
        (
            "13 fd 31 a6 2a a6 11 af b6 89 82",  # hex with spaces
            ["24165265156868740537026946"],
        ),
        (
            "13fd 31a6 2aa6 11af b68982",  # hex with spaces but weirdly spaced
            ["24165265156868740537026946"],
        ),
        (
            "13	fd	31	a6	2a	a6	11	af	b6	89	82",  # hex with tabs (wtf)
            ["24165265156868740537026946"],
        ),
        (
            "13fd31a62aa611afb68982",  # hex continuous
            ["24165265156868740537026946"],
        ),
        (
            "24165265156868740537026946",  # int
            ["24165265156868740537026946"],
        ),
        # Different versions of several int serial numbers
        (
            "24165265156868740537026946 24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946	24165265156868740537026947",  # tab instead of space
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946    24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946;24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946,24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946,,,24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946,24165265156868740537026947,",  # trailing comma
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946, 24165265156868740537026947",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        (
            "24165265156868740537026946 24165265156868740537026947 24165265156868740537026948",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
                "24165265156868740537026948",
            ],
        ),
        (
            "24165265156868740537026946, 24165265156868740537026947,24165265156868740537026948",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
                "24165265156868740537026948",
            ],
        ),
        (
            "24165265156868740537026946, 24165265156868740537026947 24165265156868740537026948",
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
                "24165265156868740537026948",
            ],
        ),
        (
            "24165265156868740537026946, 24165265156868740537026947 24165265156868740537026946",  # duplicates
            [
                "24165265156868740537026946",
                "24165265156868740537026947",
            ],
        ),
        # Diferent versions of serveral hex serial numbers
        (
            "248ff6242c64b12716a7 248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7	248eea0ae8b8ac87eccf",  # tab instead of space
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7    248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7;248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7,248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7,,,248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7,248eea0ae8b8ac87eccf,",  # trailing comma
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248ff6242c64b12716a7 248eea0ae8b8ac87eccf 248eea0ae8b8ac87ecdf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
                "172641495589408492481759",
            ],
        ),
        (
            "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf,248eea0ae8b8ac87ecdf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
                "172641495589408492481759",
            ],
        ),
        (
            "248ff6242c64b12716a7, 248eea0ae8b8ac87eccf 248eea0ae8b8ac87ecdf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
                "172641495589408492481759",
            ],
        ),
        (
            "248ff6242c64b12716a7, 248ff6242c64b12716a7 248ff6242c64b12716a7",  # duplicates
            [
                "172660814135891165910695",
            ],
        ),
        # upper case
        (
            "248FF6242C64B12716A7 248EEA0AE8B8AC87ECCF",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248FF6242C64B12716A7	248EEA0AE8B8AC87ECCF",  # tab instead of space
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248FF6242C64B12716A7    248EEA0AE8B8AC87ECCF",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248FF6242C64B12716A7;248EEA0AE8B8AC87ECCF",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
        (
            "248FF6242C64B12716A7,248eea0ae8b8ac87eccf",
            [
                "172660814135891165910695",
                "172641495589408492481743",
            ],
        ),
    ],
)
def test_should_auto_detect_cert_serial(
    serial: str,
    expected_searched_for_serial_numbers: list[str],
    database: Database,
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        serial,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    # Since the serial numbers are deduped in a set, the order
    # is not guaranteed. So we need to check every possible variant
    # of the order. But it should match one of those.
    assert ldap_search_params.ldap_query in [
        LdapFilter.create_for_cert_serials(
            [int(serial_number) for serial_number in permutation]
        )
        for permutation in permutations(expected_searched_for_serial_numbers)
    ]
    assert ldap_search_params.search_type == SearchType.CERT_SERIAL


def test_should_reject_too_many_cert_serials(database: Database) -> None:
    query = ",".join(
        [f"2416526515686874053702694{x}" for x in range(MAX_SERIAL_NUMBER_COUNT + 1)]
    )

    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        query,
        None,
    )

    with pytest.raises(ClientError) as error:
        LdapSearchParams.create(search_params, database)

    assert error.match("Too many serial numbers in search")


@pytest.mark.parametrize(
    "thumbprint",
    [
        # sha1
        "38a6dcc494484553c8291fce2ab8d5b5311caa02",
        "38A6DCC494484553C8291FCE2AB8D5B5311CAA02",
        "38:a6:dc:c4:94:48:45:53:c8:29:1f:ce:2a:b8:d5:b5:31:1c:aa:02",
        "38 a6 dc c4 94 48 45 53 c8 29 1f ce 2a b8 d5 b5 31 1c aa 02",
        # sha2
        "f9d1af62d004d4da648929bc7dde552685979d6e6a78dc8f9b64eb08e9c4ccb7",
        "f9:d1:af:62:d0:04:d4:da:64:89:29:bc:7d:de:55:26:85:97:9d:6e:6a:78:dc:8f:9b:64:eb:08:e9:c4:cc:b7",
        "f9 d1 af 62 d0 04 d4 da 64 89 29 bc 7d de 55 26 85 97 9d 6e 6a 78 dc 8f 9b 64 eb 08 e9 c4 cc b7",
        "F9D1AF62D004D4DA648929BC7DDE552685979D6E6A78DC8F9B64EB08E9C4CCB7",
    ],
)
def test_should_auto_detect_thumbprint(thumbprint: str, database: Database) -> None:
    database.insert_certificates(
        [
            LdapCertificateEntry(
                "mordi=213,dc=MagnusCA,dc=watn,dc=no",
                b"hei",
                cert_serial=None,
                ldap_server=LdapServer(
                    "ldap.buypass.no",
                    "dc=MagnusCA,dc=watn,dc=no",
                    CertificateAuthority.BUYPASS,
                    [],
                ),
            )
        ],
        "ldap.buypass.no",
    )

    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        thumbprint,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert len(ldap_search_params.ldap_servers) == 1
    assert str(ldap_search_params.ldap_query) == "(objectClass=*)"
    assert (
        ldap_search_params.ldap_servers[0].base == "mordi=213,dc=MagnusCA,dc=watn,dc=no"
    )
    assert ldap_search_params.search_type == SearchType.THUMBPRINT


@pytest.mark.parametrize(
    "thumbprint",
    [
        # sha1
        "38a6dcc494484553c8291fce2ab8d5b5311caa02",
        "38A6DCC494484553C8291FCE2AB8D5B5311CAA02",
        "38:a6:dc:c4:94:48:45:53:c8:29:1f:ce:2a:b8:d5:b5:31:1c:aa:02",
        "38 a6 dc c4 94 48 45 53 c8 29 1f ce 2a b8 d5 b5 31 1c aa 02",
        # sha2
        "f9d1af62d004d4da648929bc7dde552685979d6e6a78dc8f9b64eb08e9c4ccb7",
        "f9:d1:af:62:d0:04:d4:da:64:89:29:bc:7d:de:55:26:85:97:9d:6e:6a:78:dc:8f:9b:64:eb:08:e9:c4:cc:b7",
        "f9 d1 af 62 d0 04 d4 da 64 89 29 bc 7d de 55 26 85 97 9d 6e 6a 78 dc 8f 9b 64 eb 08 e9 c4 cc b7",
        "F9D1AF62D004D4DA648929BC7DDE552685979D6E6A78DC8F9B64EB08E9C4CCB7",
    ],
)
def test_should_search_for_sn_when_thumbprint_yielded_no_match(
    thumbprint: str, database: Database
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        thumbprint,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.ldap_servers) == 5
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert ldap_search_params.ldap_query in [
        # the sha1 one
        LdapFilter.create_for_cert_serials(
            [323424638464440995430880998016818972657434012162]
        ),
        # the sha2 one
        LdapFilter.create_for_cert_serials(
            [
                112996380803364418972622033757955332609174229588838720641324396341116998569143
            ]
        ),
    ]
    assert ldap_search_params.search_type == SearchType.THUMBPRINT_OR_CERT_SERIAL


@pytest.mark.parametrize("orgnr", ["995546973", "995 546 973", "NTRNO-995546973"])
def test_should_auto_detect_org_nr_not_in_db(database: Database, orgnr: str) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        orgnr,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.ENTERPRISE in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert (
        str(ldap_search_params.ldap_query)
        == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
    )
    assert ldap_search_params.organization is None
    assert ldap_search_params.search_type == SearchType.ORG_NR


@pytest.mark.parametrize("orgnr", ["991 056 505", "991056505", "NTRNO-991056505"])
def test_should_auto_detect_org_nr_child(database: Database, orgnr: str) -> None:
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
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.ENTERPRISE in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert (
        str(ldap_search_params.ldap_query)
        == "(&(|(serialNumber=983044778)(organizationIdentifier=NTRNO-983044778))"
        "(ou=*991056505*))"
    )
    assert ldap_search_params.organization is not None
    assert ldap_search_params.organization.name == "APOTEK 1 ULRIKSDAL"
    assert ldap_search_params.organization.orgnr == "991056505"
    assert ldap_search_params.organization.parent_orgnr == "983044778"
    assert ldap_search_params.search_type == SearchType.ORG_NR


@pytest.mark.parametrize("orgnr", ["995 5469 73", "995546973", "NTRNO-995546973"])
def test_should_auto_detect_org_nr_main(database: Database, orgnr: str) -> None:
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
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.ENTERPRISE in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert (
        str(ldap_search_params.ldap_query)
        == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
    )
    assert ldap_search_params.organization is not None
    assert ldap_search_params.organization.name == "WATN IT SYSTEM Magnus Horsgård Watn"
    assert ldap_search_params.organization.orgnr == "995546973"
    assert ldap_search_params.organization.parent_orgnr is None
    assert ldap_search_params.search_type == SearchType.ORG_NR


@pytest.mark.parametrize(
    "orgnr",
    [
        "995 546 973",
        "995  546  973",  # double rainbow!
        "995 5469 73",
        "995546973",
        "NTRNO-995546973",
        "995	546	973",  # tabs
        "995		546	973",  # tabs
    ],
)
def test_should_auto_detect_org_nr_main_with_parent(
    database: Database, orgnr: str
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
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.ENTERPRISE in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert (
        str(ldap_search_params.ldap_query)
        == "(|(serialNumber=995546973)(organizationIdentifier=NTRNO-995546973))"
    )
    assert ldap_search_params.organization is not None
    assert ldap_search_params.organization.name == "WATN IT SYSTEM Magnus Horsgård Watn"
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
    database: Database, serial: str
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        serial,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert all(
        ldap_server.ca == CertificateAuthority.COMMFIDES
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert str(
        ldap_search_params.ldap_query
    ) == f"(|(serialNumber={serial})(serialNumber=UN:NO-{serial}))" or (
        str(ldap_search_params.ldap_query)
        == f"(|(serialNumber={serial[6:]})(serialNumber={serial}))"
    )
    assert ldap_search_params.search_type == SearchType.PERSONAL_SERIAL


@pytest.mark.parametrize("serial", ["9578-4050-127091783", "UN:NO-9578-4050-127091783"])
def test_should_auto_detect_personal_serial_number_buypass(
    database: Database, serial: str
) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        serial,
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert all(
        ldap_server.ca == CertificateAuthority.BUYPASS
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert (
        str(ldap_search_params.ldap_query) == "(|(serialNumber=9578-4050-127091783)"
        "(serialNumber=UN:NO-9578-4050-127091783)(serialNumber=127091783))"
    )
    assert ldap_search_params.search_type == SearchType.PERSONAL_SERIAL


def test_should_auto_detect_email(database: Database) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        "fornavn@etternavn.no",
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert "ERR-006" in ldap_search_params.limitations
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert str(ldap_search_params.ldap_query) == "(mail=fornavn@etternavn.no)"
    assert ldap_search_params.search_type == SearchType.EMAIL


def test_should_handle_rfc4514_looking_string(database: Database) -> None:
    search_params = SearchParams(
        Environment.TEST,
        CertType.PERSONAL,
        "givenName=Silje Fos,surname=Port",
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert not ldap_search_params.limitations
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert (
        str(ldap_search_params.ldap_query) == "(&(givenName=Silje Fos)(surname=Port))"
    )
    assert ldap_search_params.search_type == SearchType.DISTINGUISHED_NAME


def test_should_fallback_to_cn(database: Database) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.PERSONAL,
        "Min supertjeneste",
        None,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.PERSONAL in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert str(ldap_search_params.ldap_query) == "(cn=Min supertjeneste)"
    assert ldap_search_params.search_type == SearchType.FALLBACK


def test_should_respect_attribute(database: Database) -> None:
    search_params = SearchParams(
        Environment.PROD,
        CertType.ENTERPRISE,
        "Min superunderenhet",
        SearchAttribute.OU,
    )

    ldap_search_params = LdapSearchParams.create(search_params, database)
    assert ldap_search_params.scope == Scope.SUB
    assert len(ldap_search_params.limitations) == 0
    assert all(
        CertType.ENTERPRISE in ldap_server.cert_types
        for ldap_server in ldap_search_params.ldap_servers
    )
    assert {CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES}.issubset(
        {ldap_server.ca for ldap_server in ldap_search_params.ldap_servers}
    )
    assert str(ldap_search_params.ldap_query) == "(ou=Min superunderenhet)"
    assert ldap_search_params.search_type == SearchType.CUSTOM
