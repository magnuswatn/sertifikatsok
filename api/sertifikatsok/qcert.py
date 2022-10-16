from __future__ import annotations

import logging
import urllib.parse
from datetime import datetime
from operator import attrgetter
from typing import cast

from attrs import frozen
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

from .constants import (
    EXTENDED_KEY_USAGES,
    KEY_USAGES,
    KNOWN_CERT_TYPES,
    ORGANIZATION_IDENTIFIER,
    SUBJECT_FIELDS,
    UNDERENHET_REGEX,
)
from .crypto import CertValidator
from .enums import SEID, CertificateRoles, CertificateStatus, CertType, SearchAttribute
from .errors import MalformedCertificateError
from .ldap import LdapServer
from .utils import create_ldap_filter, get_subject_order

logger = logging.getLogger(__name__)


class QualifiedCertificate:
    """Represents a Norwegian Qualified Certificate"""

    def __init__(
        self,
        cert: x509.Certificate,
        cert_serial: str | None,
        ldap_server: LdapServer,
        cert_status: CertificateStatus,
        revocation_date: datetime | None,
    ):

        self.cert: x509.Certificate = cert
        self.cert_serial = cert_serial
        self.issuer = self.cert.issuer.rfc4514_string(SUBJECT_FIELDS)
        self.type, self.description, self.seid = self._get_type()
        self.roles = self._get_roles()
        self.ldap_server = ldap_server
        self.status = cert_status
        self.revocation_date = revocation_date

    @classmethod
    async def create(
        cls,
        raw_cert: bytes,
        cert_serial: str | None,
        ldap_server: LdapServer,
        cert_validator: CertValidator,
    ) -> QualifiedCertificate:

        cert = x509.load_der_x509_certificate(raw_cert)
        # access the subject, so that we fail here if it's malformed,
        # instead of at a "random" place later on.
        # See https://github.com/magnuswatn/sertifikatsok/issues/132
        cert.subject

        cert_status, revocation_date = await cert_validator.validate_cert(cert)

        return cls(cert, cert_serial, ldap_server, cert_status, revocation_date)

    def _get_type(self) -> tuple[CertType, str, SEID]:
        """Returns the type of certificate, based on issuer and Policy OID"""
        cert_policies = cast(
            x509.CertificatePolicies,
            self.cert.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            ).value,
        )

        for policy in cert_policies:
            try:
                oid: str = policy.policy_identifier.dotted_string
                return KNOWN_CERT_TYPES[(self.issuer, oid)]
            except KeyError:
                pass

        oids = [policy.policy_identifier.dotted_string for policy in cert_policies]

        logger.warn("Unknown certificate type. OIDs=%s Issuer='%s'", oids, self.issuer)

        return (CertType.UNKNOWN, ", ".join(oids), SEID.UNKNOWN)

    def _get_roles(self) -> list[CertificateRoles]:
        """
        A set of Norwegian qualified certificates should have certificates
        intended for:

        *) Encryption
        *) Signature
        *) Authentication

        Several roles can be placed on one certificate (Buypass does this).

        This function returns which role(s) this certificate has.
        """
        cert_roles = []
        key_usage = cast(
            x509.KeyUsage,
            self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
        )

        if key_usage.digital_signature:
            cert_roles.append(CertificateRoles.AUTH)
        if key_usage.content_commitment:
            cert_roles.append(CertificateRoles.SIGN)
        if key_usage.data_encipherment or key_usage.key_encipherment:
            cert_roles.append(CertificateRoles.CRYPT)
        return cert_roles

    def print_subject(self, full: bool = False) -> str:
        """
        Returns the subject of the cert as a string.
        If it's an Personal Commfides certificate the serialNumber
        field is skipped, unless 'full' is True.

        This is becuase Commfides generates random serialNumbers
        for all Person certificates, so they are not very useful
        and also different within a set.
        """

        if full:
            return self.cert.subject.rfc4514_string(SUBJECT_FIELDS)

        if self.type == CertType.PERSONAL and "Commfides" in self.issuer:
            # Create new subject without the serialNumber field
            # for personal certs from Commfides
            subject_name = x509.Name(
                [
                    name
                    for name in self.cert.subject
                    if name.oid != NameOID.SERIAL_NUMBER
                ]
            )
        else:
            subject_name = self.cert.subject

        subject = []
        for field in subject_name:
            subject.append(
                "{}={}".format(
                    SUBJECT_FIELDS.get(field.oid, field.oid.dotted_string),
                    cast(str, field.value),
                )
            )

        # If not full (e.g. used for pretty printing),
        # we order the fields in an uniform order
        subject.sort(key=get_subject_order)
        return ", ".join(list(subject))

    def get_orgnumber(self) -> tuple[str | None, bool]:
        """
        Gets the organization number from the cert,
        and returns the organization number and if it's an "underenhet".
        """
        if self.type != CertType.ENTERPRISE:
            return None, False

        serial_number_attr = self.cert.subject.get_attributes_for_oid(
            NameOID.SERIAL_NUMBER
        )
        organization_identifier_attr = self.cert.subject.get_attributes_for_oid(
            ORGANIZATION_IDENTIFIER
        )

        if organization_identifier_attr:
            organization_identifier = cast(str, organization_identifier_attr[0].value)
            if organization_identifier.startswith("NTRNO-"):
                org_number = organization_identifier[6:]
            else:
                logger.warn(
                    "Semantic Identifier is not NTRNO: %s", organization_identifier
                )
                return None, False
        elif serial_number_attr:
            org_number = cast(str, serial_number_attr[0].value)
        else:
            logger.error(
                "Malformed cert: %s", self.cert.public_bytes(Encoding.PEM).decode()
            )
            raise MalformedCertificateError("Missing org number in subject")

        try:
            ou_field = cast(
                str,
                self.cert.subject.get_attributes_for_oid(
                    NameOID.ORGANIZATIONAL_UNIT_NAME
                )[0].value,
            )
        except IndexError:
            return org_number, False

        ou_number = UNDERENHET_REGEX.search(ou_field)

        if ou_number and org_number != ou_number[0]:
            return ou_number[0], True

        return org_number, False

    def get_key_info(self) -> str | None:
        pub_key = self.cert.public_key()
        if isinstance(pub_key, RSAPublicKey):
            return f"RSA ({pub_key.key_size} bits)"
        if isinstance(pub_key, EllipticCurvePublicKey):
            return f"ECC ({pub_key.curve.name})"
        logger.warn(f"Unexpected key type: {pub_key}")
        return None

    def get_key_usages(self) -> str:
        """Returns a string with the key usages from the cert"""
        key_usages = []
        for key_usage in KEY_USAGES:
            if getattr(
                self.cert.extensions.get_extension_for_oid(
                    ExtensionOID.KEY_USAGE
                ).value,
                key_usage[0],
            ):
                key_usages.append(key_usage[1])
        return ", ".join(key_usages)

    def get_extended_key_usages(self) -> str | None:
        """Returns a string with the extended key usages from the cert"""
        try:
            cert_eku = cast(
                x509.ExtendedKeyUsage,
                self.cert.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                ).value,
            )
        except x509.ExtensionNotFound:
            return None

        ekus = []
        for eku in cert_eku:
            try:
                ekus.append(EXTENDED_KEY_USAGES[eku.dotted_string])
            except KeyError:
                logger.warn("Unknown EKU. OID=%s", eku.dotted_string)
                ekus.append(eku.dotted_string)

        return ", ".join(ekus)


@frozen
class QualifiedCertificateSet:
    """Represents a set of Norwegian qualified certificates"""

    certs: list[QualifiedCertificate]
    main_cert: QualifiedCertificate
    status: CertificateStatus
    revocation_date: datetime | None
    org_number: str | None
    underenhet: bool
    seid2: bool

    @classmethod
    def create(cls, certs: list[QualifiedCertificate]) -> QualifiedCertificateSet:

        # Commfides issues encryption certs with longer validity than
        # the rest of the certificates in the set, so we shouldn't use
        # that to check the validity of the set. Therefore we try to find
        # a non-encryption cert to use as the "main cert" of the set.
        main_cert = cls._get_non_encryption_cert(certs)

        status = main_cert.status
        revocation_date = None
        # Just to be sure we don't label a set
        # with a revoked cert in it as OK
        for cert in certs:
            if cert.status == CertificateStatus.REVOKED:
                status = cert.status
                revocation_date = cert.revocation_date

        org_number, underenhet = main_cert.get_orgnumber()
        seid2 = main_cert.seid == SEID.SEID2
        return cls(
            certs, main_cert, status, revocation_date, org_number, underenhet, seid2
        )

    @classmethod
    def create_sets_from_certs(
        cls, certs: list[QualifiedCertificate]
    ) -> list[QualifiedCertificateSet]:
        """
        This creates a list of QualifiedCertificateSet
        from a list of QualifiedCertificate.

        This is quite hard as there isn't anything that ties the certs together.
        But the subjects should be the same (except the serialNumber on non-Enterprise
        certs from Commfides) and they should be issued at the same time
        (except encryption certificates from Commfides)... *sigh*
        """
        if not certs:
            return []

        cert_sets: list[QualifiedCertificateSet] = []

        cert_set: list[QualifiedCertificate] = []
        cert_set_roles: list[CertificateRoles] = []

        for cert in sorted(certs, key=attrgetter("cert.not_valid_before")):

            if not cert_set:
                cert_set_roles = cert.roles.copy()
            elif (
                # Certificates in a set should have the same subject,
                # so if they differ they are not from the same set
                (cert_set[0].print_subject() != cert.print_subject())
                or
                # Certificates in a set should have the same type description
                (cert_set[0].description != cert.description)
                or
                # Commfides seems to issue the Encryption certificates
                # at a different time than the rest of the certificates
                # in the set, but they should be issued within a couple
                # of weeks of each other.
                (
                    (
                        cert.cert.not_valid_before - cert_set[0].cert.not_valid_before
                    ).days
                    > 14
                )
                or
                # A set can't contain several certs of the same type
                [i for i in cert.roles if i in cert_set_roles]
            ):
                cert_sets.append(cls.create(cert_set))
                cert_set = []
                cert_set_roles = cert.roles.copy()
            else:
                cert_set_roles += cert.roles

            cert_set.append(cert)

        cert_sets.append(cls.create(cert_set))
        return cert_sets

    @staticmethod
    def _get_non_encryption_cert(
        certs: list[QualifiedCertificate],
    ) -> QualifiedCertificate:
        """
        This tries to find an non-encryption certificate in the
        certificate set and return that.

        If none is found, the first cert in the set is returned.
        """
        for cert in certs:
            if CertificateRoles.CRYPT not in cert.roles:
                return cert
        return certs[0]

    @property
    def valid_to(self) -> str:
        return self.main_cert.cert.not_valid_after.isoformat()

    @property
    def valid_from(self) -> str:
        return self.main_cert.cert.not_valid_before.isoformat()

    @property
    def typ(self) -> CertType:
        return self.main_cert.type

    @property
    def issuer(self) -> str:
        return self.main_cert.issuer

    @property
    def subject(self) -> str:
        return self.main_cert.print_subject()

    @property
    def ldap(self) -> str:
        """Creates an LDAP url (RFC 1959) for the certificate set"""

        ldap_filter = create_ldap_filter(
            [
                (SearchAttribute.CSN, str(cert.cert_serial))
                for cert in self.certs
                if cert.cert_serial
            ]
        )
        ldap_url = "ldap://{}/{}?usercertificate;binary?sub?{}".format(
            self.certs[0].ldap_server.hostname,
            urllib.parse.quote(self.certs[0].ldap_server.base, safe="=,"),
            ldap_filter,
        )
        return ldap_url
