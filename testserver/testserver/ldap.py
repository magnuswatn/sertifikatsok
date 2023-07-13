from collections import defaultdict
from typing import Self

from cryptography.hazmat.primitives.serialization import Encoding
from ldaptor.inmemory import ReadOnlyInMemoryLDAPEntry  # type: ignore
from ldaptor.protocols.ldap.ldapserver import BaseLDAPServer, LDAPServer  # type: ignore
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory

from testserver import LdapOU
from testserver.ca import LdapPublishedCertificate
from testserver.config import CertificateAuthority


class LDAPServerFactory(ServerFactory):
    protocol = LDAPServer

    def __init__(
        self, root: ReadOnlyInMemoryLDAPEntry, commfides_root: ReadOnlyInMemoryLDAPEntry
    ):
        self.root = root
        self.commfides_root = commfides_root
        self.debug = False

    @classmethod
    def create(cls) -> Self:
        root = ReadOnlyInMemoryLDAPEntry("", {})

        commfides_root = root.addChild(
            "dc=com",
            {},
        ).addChild(
            "dc=commfides",
            {
                "objectClass": ["dcObject", "organization"],
                "dc": ["commfides"],
                "o": ["commfides.com"],
                "description": ["Parent Object for Commfides LDAP Directory"],
            },
        )

        return cls(root, commfides_root)

    def add_commfides_ca(self, ca: CertificateAuthority) -> None:
        ca_ou = self.commfides_root.addChild(f"ou={ca.ldap_name}", {})

        sorted_certs: dict[LdapOU, list[LdapPublishedCertificate]] = defaultdict(list)
        for issued_cert in ca.impl.issued_certs:
            assert issued_cert.cert_role
            sorted_certs[issued_cert.cert_role].append(issued_cert)

        for role in LdapOU:
            role_ou = ca_ou.addChild(
                f"ou={role.value}",
                {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": [role.value],
                    "description": [f"Parent Object for all {role.value} Certificates"],
                },
            )
            for cert in sorted_certs[role]:
                role_ou.addChild(rdn=cert.rdn, attributes=cert.ldap_attrs)

    def add_buypass_ca(self, ca: CertificateAuthority) -> None:
        ldap_attrs = {
            "objectClass": ["certificationAuthority", "cRLDistributionPoint"],
            "cn": [ca.name],
            "cACertificate;binary": [ca.impl.cert.public_bytes(Encoding.DER)],
            "certificateRevocationList;binary": [ca.impl.get_crl()],
        }

        main = self.root.addChild(f"CN={ca.name}", ldap_attrs)
        no = main.addChild("dc=no", ldap_attrs)
        ca_root = no.addChild("dc=Buypass", ldap_attrs)

        for issued_cert in ca.impl.issued_certs:
            ca_root.addChild(rdn=issued_cert.rdn, attributes=issued_cert.ldap_attrs)

    def buildProtocol(self, addr: IAddress) -> BaseLDAPServer:
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        return proto
