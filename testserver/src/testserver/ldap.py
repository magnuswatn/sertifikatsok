import logging
from collections import defaultdict
from collections.abc import Callable, Sequence
from secrets import randbelow
from typing import Any, Self

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    ExtensionNotFound,
    NameOID,
    ObjectIdentifier,
    RFC822Name,
    SubjectAlternativeName,
)
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
from testserver.ca import IssuedCertificate
from testserver.config import CertificateAuthority

logger = logging.getLogger(__name__)


class SertifikatsokLDAPServer(LDAPServer):  # type: ignore
    def handle_LDAPSearchRequest(
        self, request: LDAPSearchRequest, controls: Any, reply: Callable
    ) -> Any:
        logger.info(
            "Received search request for base '%s'",
            request.baseObject.decode(),  # type: ignore
        )
        buypass_request = b"Buypass" in request.baseObject  # type: ignore

        self.check_for_magic_filter(
            request.filter,
            request.baseObject,  # type: ignore
            is_buypass_request=buypass_request,
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
                filter.value,  # type: ignore
                base_object,
                is_buypass_request=is_buypass_request,
            )
            return

        if not isinstance(filter, LDAPAttributeValueAssertion):
            return

        attribute_desc = filter.attributeDesc.value.lower().decode()
        assertion_value = filter.assertionValue.value.lower().decode()  # type: ignore

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
            self.check_for_malformed_cert_sn(filter.value)  # type: ignore
            return

        if isinstance(filter, LDAPAttributeDescription):
            return

        if isinstance(filter, LDAPAttributeValueAssertion):
            if filter.attributeDesc.value.lower() == b"certificateserialnumber":
                try:
                    int(filter.assertionValue.value)  # type: ignore
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

        sorted_certs: dict[LdapOU, list[IssuedCertificate]] = defaultdict(list)
        for issued_cert in ca.cert_database.issued_certs.values():
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
                cert_ldap_attrs: dict[str, Sequence[str | bytes]] = {
                    "userCertificate;binary": [
                        cert.certificate.public_bytes(Encoding.DER)
                    ],
                    "certificateSerialNumber": [str(cert.certificate.serial_number)],
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "inetOrgPerson",
                        "inetOrgPersonWithCertSerno",
                    ],
                }

                subject_attrs: list[tuple[ObjectIdentifier, str]] = [
                    (NameOID.COMMON_NAME, "cn"),
                    (NameOID.ORGANIZATIONAL_UNIT_NAME, "ou"),
                    (NameOID.GIVEN_NAME, "givenName"),
                    (NameOID.SURNAME, "sn"),
                    (NameOID.SERIAL_NUMBER, "serialNumber"),
                    (NameOID.ORGANIZATION_NAME, "o"),
                ]
                for name_oid, ldap_attr in subject_attrs:
                    # do not include attr when no value
                    if subject_val := cert.certificate.subject.get_attributes_for_oid(
                        name_oid
                    ):
                        cert_ldap_attrs[ldap_attr] = [subject_val[0].value]

                try:
                    sans = cert.certificate.extensions.get_extension_for_class(
                        SubjectAlternativeName
                    )
                    cert_ldap_attrs["mail"] = [
                        sans.value.get_values_for_type(RFC822Name)[0]
                    ]
                except ExtensionNotFound:
                    pass

                assert cert.enterprise_cert is not None
                if cert.enterprise_cert:
                    # generate a random "uid" for rdn
                    uid = str(randbelow(9999999999999))
                    cert_ldap_attrs["uid"] = [uid]
                    rdn = f"uid={uid}"
                else:
                    # use serial number
                    assert "serialNumber" in cert_ldap_attrs
                    [serial_number] = cert_ldap_attrs["serialNumber"]
                    assert isinstance(serial_number, str)
                    rdn = f"serialNumber={serial_number}"

                role_ou.addChild(rdn=rdn, attributes=cert_ldap_attrs)

    def add_buypass_ca(self, ca: CertificateAuthority) -> None:
        ca_cert_bytes = ca.impl.cert.public_bytes(Encoding.DER)
        crl_bytes = ca.impl.get_crl()
        ldap_attrs = {
            "objectClass": ["certificationAuthority", "cRLDistributionPoint"],
            "cn": [ca.name],
            "cACertificate;binary": [ca_cert_bytes],
            "certificateRevocationList;binary": [crl_bytes],
        }

        main = self.root.addChild(f"CN={ca.name}", ldap_attrs)
        no = main.addChild("dc=no", ldap_attrs)
        ca_root = no.addChild("dc=Buypass", ldap_attrs)

        _last_pss_identifier = randbelow(99999)
        for issued_cert in ca.cert_database.issued_certs.values():
            pss_unique_id = _last_pss_identifier
            _last_pss_identifier += 1

            cert_ldap_attrs: dict[str, Sequence[str | bytes]] = {
                "userCertificate;binary": [
                    issued_cert.certificate.public_bytes(Encoding.DER)
                ],
                "certificateSerialNumber": [str(issued_cert.certificate.serial_number)],
                "pssUniqueIdentifier": [str(pss_unique_id)],
                "cACertificate;binary": [ca_cert_bytes],
                "certificateRevocationList;binary": [crl_bytes],
                "objectClass": ["top"],
            }

            subject_attrs: list[tuple[ObjectIdentifier, str]] = [
                (NameOID.COMMON_NAME, "displayName"),
                (NameOID.COMMON_NAME, "cn"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "ou"),
                (NameOID.GIVEN_NAME, "givenname"),
                (NameOID.SURNAME, "surname"),
                (NameOID.SERIAL_NUMBER, "serialNumber"),
                (NameOID.ORGANIZATION_IDENTIFIER, "organizationidentifier"),
                (NameOID.ORGANIZATION_NAME, "o"),
            ]
            for name_oid, ldap_attr in subject_attrs:
                # include attr even when no value
                cert_ldap_attrs[ldap_attr] = (
                    [subject_val[0].value]
                    if (
                        subject_val
                        := issued_cert.certificate.subject.get_attributes_for_oid(
                            name_oid
                        )
                    )
                    else [""]
                )

            try:
                sans = issued_cert.certificate.extensions.get_extension_for_class(
                    SubjectAlternativeName
                )
                email = sans.value.get_values_for_type(RFC822Name)[0]
            except ExtensionNotFound:
                email = ""
            cert_ldap_attrs["mail"] = [email]

            rdn = f"pssUniqueIdentifier={pss_unique_id}"

            ca_root.addChild(rdn=rdn, attributes=cert_ldap_attrs)

    def buildProtocol(self, addr: IAddress) -> BaseLDAPServer:
        proto = self.protocol()  # type: ignore
        proto.debug = self.debug  # type: ignore
        proto.factory = self
        return proto  # type: ignore
