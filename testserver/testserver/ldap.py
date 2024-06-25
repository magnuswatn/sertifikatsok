import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Self

from cryptography.hazmat.primitives.serialization import Encoding
from ldaptor.inmemory import ReadOnlyInMemoryLDAPEntry  # type: ignore
from ldaptor.protocols.ldap.ldaperrors import (  # type: ignore
    LDAPNoSuchAttribute,
    LDAPOperationsError,
)
from ldaptor.protocols.ldap.ldapserver import BaseLDAPServer, LDAPServer  # type: ignore
from ldaptor.protocols.pureldap import (  # type: ignore
    LDAPAttributeDescription,
    LDAPAttributeValueAssertion,
    LDAPFilter,
    LDAPFilterSet,
    LDAPProtocolResponse,
    LDAPSearchRequest,
)
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory

from testserver import LdapOU
from testserver.ca import LdapPublishedCertificate
from testserver.config import CertificateAuthority

logger = logging.getLogger(__name__)


class SertifikatsokLDAPServer(LDAPServer):  # type: ignore
    def handle_LDAPSearchRequest(
        self, request: LDAPSearchRequest, controls: Any, reply: Callable
    ) -> Any:
        logger.info(
            "Received search request for base '%s'", request.baseObject.decode()
        )
        buypass_request = b"Buypass" in request.baseObject

        self.check_for_magic_filter(
            request.filter, request.baseObject, is_buypass_request=buypass_request
        )

        if buypass_request:
            # Buypass returns `no such attribute` for querys
            # that filters `certificateSerialNumber` on something
            # not a number. Let's do the same, since we have
            # special handling because of it.
            self.check_for_malformed_cert_sn(request.filter)

        # Buypass return max 20 results per query,
        # so let's ignore all results after we have
        # returned 20, if we're emulating Buypass.
        reply_count = 0

        def _buypass_reply(resp: LDAPProtocolResponse) -> Any:
            nonlocal reply_count
            if reply_count >= 20:
                return
            reply_count += 1
            return reply(resp)

        return super().handle_LDAPSearchRequest(
            request, controls, _buypass_reply if buypass_request else reply
        )

    def check_for_magic_filter(
        self, filter: Any, base_object: bytes, *, is_buypass_request: bool
    ) -> None:
        if isinstance(filter, LDAPFilterSet):
            for attr in filter:
                self.check_for_magic_filter(
                    attr, base_object, is_buypass_request=is_buypass_request
                )
            return

        if isinstance(filter, LDAPFilter):
            self.check_for_magic_filter(
                filter.value, base_object, is_buypass_request=is_buypass_request
            )
            return

        if not isinstance(filter, LDAPAttributeValueAssertion):
            return

        attribute_desc = filter.attributeDesc.value.lower().decode()
        assertion_value = filter.assertionValue.value.lower().decode()

        if attribute_desc == "ou" and assertion_value == "fail":
            raise LDAPOperationsError("You asked me to fail (general fail)")

        if is_buypass_request:
            suffix = base_object[-4:].lower().decode()

            if assertion_value in ("buypassfail", f"buypassfail-{suffix}"):
                raise LDAPOperationsError("You asked me to fail (buypassfail)")
        else:
            if attribute_desc == "serialnumber" and (
                assertion_value in ("9578-4506-fail", "un:no-9578-4506-fail")
            ):
                raise LDAPOperationsError("You asked me to fail (commfidesfail)")

    def check_for_malformed_cert_sn(self, filter: Any) -> None:
        if isinstance(filter, LDAPFilterSet):
            for attr in filter:
                self.check_for_malformed_cert_sn(attr)
            return

        if isinstance(filter, LDAPFilter):
            self.check_for_malformed_cert_sn(filter.value)
            return

        if isinstance(filter, LDAPAttributeDescription):
            return

        if isinstance(filter, LDAPAttributeValueAssertion):
            if filter.attributeDesc.value.lower() == b"certificateserialnumber":
                try:
                    int(filter.assertionValue.value)
                except ValueError as e:
                    raise LDAPNoSuchAttribute("Buypass no like this serial") from e
            return

        logger.warning("Unexpected filter class: %s: %s", type(filter), repr(filter))


class LDAPServerFactory(ServerFactory):
    protocol = SertifikatsokLDAPServer

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
