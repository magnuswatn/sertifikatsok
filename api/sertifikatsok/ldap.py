from attr import frozen

from .enums import CertificateAuthority


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
