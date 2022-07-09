from attr import frozen

from .enums import CertificateAuthority, Environment


@frozen
class LdapServer:
    hostname: str
    base: str
    ca: CertificateAuthority

    def __repr__(self):
        # This is used in the performance log,
        # to identify which ldap server we are
        # searching against.
        return self.hostname


LDAP_SERVERS = {
    Environment.TEST: [
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4",
            CertificateAuthority.BUYPASS,
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
        ),
    ],
    Environment.PROD: [
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3",
            CertificateAuthority.BUYPASS,
        ),
        LdapServer(
            "ldap.commfides.com",
            "dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
        ),
    ],
}
