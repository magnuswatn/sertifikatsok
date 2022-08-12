from typing import List

from attr import frozen

from .enums import CertificateAuthority, CertType, Environment


@frozen
class LdapServer:
    hostname: str
    base: str
    ca: CertificateAuthority
    cert_types: List[CertType]

    def __str__(self):
        # Used for logging.
        return f"{self.hostname}: {self.base}"


LDAP_SERVERS = {
    Environment.TEST: [
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 1",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 ST Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 HT Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 HT Person",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Enterprise,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Person-High,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Legal-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
        ),
    ],
    Environment.PROD: [
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA 1",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA 3",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 ST Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 HT Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 HT Person",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Enterprise,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Person-High,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Legal-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
        ),
    ],
}
