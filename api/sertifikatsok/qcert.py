from __future__ import annotations

import logging
import urllib.parse
from datetime import datetime
from operator import attrgetter
from typing import List, Optional, Tuple, cast

import attr
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
from .enums import CertificateRoles, CertificateStatus, CertType, SearchAttribute
from .errors import MalformedCertificateError
from .utils import create_ldap_filter, get_subject_order, stringify_x509_name

logger = logging.getLogger(__name__)


class QualifiedCertificate:
    """Represents a Norwegian Qualified Certificate"""

    def __init__(
        self,
        cert: x509.Certificate,
        ldap_params: Tuple[str, str],
        cert_status: CertificateStatus,
        revocation_date: Optional[datetime],
    ):

        self.cert: x509.Certificate = cert
        self.issuer = stringify_x509_name(self.cert.issuer)
        self.type, self.description = self._get_type()
        self.roles = self._get_roles()
        self.ldap_params = ldap_params
        self.status = cert_status
        self.revocation_date = revocation_date

    @classmethod
    async def create(cls, raw_cert: bytes, ldap_params, cert_validator: CertValidator):

        cert = x509.load_der_x509_certificate(raw_cert)
        cert_status, revocation_date = await cert_validator.validate_cert(cert)

        return cls(cert, ldap_params, cert_status, revocation_date)

    def _get_type(self) -> Tuple[CertType, str]:
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

        return (CertType.UNKNOWN, ", ".join(oids))

    def _get_roles(self) -> List[CertificateRoles]:
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
        subject = []
        for field in self.cert.subject:
            if field.oid.dotted_string == "2.5.4.5" and not full:
                # Skip serialNumber if Personal cert from Commfides
                if "Commfides" in self.issuer and self.type == CertType.PERSONAL:
                    continue
            try:
                subject.append(
                    "{}={}".format(SUBJECT_FIELDS[field.oid.dotted_string], field.value)
                )
            except KeyError:
                # If we don't recognize the field, we just print the dotted string
                subject.append("{}={}".format(field.oid.dotted_string, field.value))

        # If not full (e.g. used for pretty printing),
        # we order the fields in an uniform order
        if not full:
            subject.sort(key=get_subject_order)
        return ", ".join(list(subject))

    def get_orgnumber(self) -> Tuple[Optional[str], bool, bool]:
        """
        Gets the organization number from the cert,
        and returns the organization number, if it's an "underenhet"
        and if it's a SEIDv2 cert.
        """
        if self.type != CertType.ENTERPRISE:
            return None, False, False

        serial_number_attr = self.cert.subject.get_attributes_for_oid(
            NameOID.SERIAL_NUMBER
        )
        organization_identifier_attr = self.cert.subject.get_attributes_for_oid(
            ORGANIZATION_IDENTIFIER
        )

        if organization_identifier_attr:
            organization_identifier = organization_identifier_attr[0].value
            if organization_identifier.startswith("NTRNO-"):
                org_number = organization_identifier[6:]
                seid2 = True
            else:
                logger.warn(
                    "Semantic Identifier is not NTRNO: %s", organization_identifier
                )
                return None, False, True
        elif serial_number_attr:
            org_number = serial_number_attr[0].value
            seid2 = False
        else:
            logger.error(
                "Malformed cert: %s", self.cert.public_bytes(Encoding.PEM).decode()
            )
            raise MalformedCertificateError("Missing org number in subject")

        try:
            ou_field = self.cert.subject.get_attributes_for_oid(
                NameOID.ORGANIZATIONAL_UNIT_NAME
            )[0].value
        except IndexError:
            return org_number, False, seid2

        ou_number = UNDERENHET_REGEX.search(ou_field)

        if ou_number and org_number != ou_number[0]:
            return ou_number[0], True, seid2

        return org_number, False, seid2

    def get_key_info(self) -> Optional[str]:
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

    def get_extended_key_usages(self) -> Optional[str]:
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


@attr.frozen
class QualifiedCertificateSet:
    """Represents a set of Norwegian qualified certificates"""

    certs: List[QualifiedCertificate] = attr.ib()
    main_cert: QualifiedCertificate = attr.ib()
    status: CertificateStatus = attr.ib()
    revocation_date: Optional[datetime] = attr.ib()
    org_number: Optional[str] = attr.ib()
    underenhet: bool = attr.ib()
    seid2: bool = attr.ib()

    @classmethod
    def create(cls, certs) -> QualifiedCertificateSet:

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

        org_number, underenhet, seid2 = main_cert.get_orgnumber()
        return cls(
            certs, main_cert, status, revocation_date, org_number, underenhet, seid2
        )

    @classmethod
    def create_sets_from_certs(
        cls, certs: List[QualifiedCertificate]
    ) -> List[QualifiedCertificateSet]:
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

        cert_sets: List[QualifiedCertificateSet] = []

        cert_set: List[QualifiedCertificate] = []
        cert_set_roles: List[CertificateRoles] = []

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
                # in the set, but they should be issued within three days
                # of each other.
                (
                    (
                        cert.cert.not_valid_before - cert_set[0].cert.not_valid_before
                    ).days
                    not in range(-3, 4)
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
    def _get_non_encryption_cert(certs) -> QualifiedCertificate:
        """
        This tries to find an non-encryption certificate in the
        certificate set and return that.

        If none is found, the first cert in the set is returned.
        """
        for cert in certs:
            key_usage = cert.cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            if not key_usage.data_encipherment:
                return cert
        return certs[0]

    @property
    def valid_to(self):
        return self.main_cert.cert.not_valid_after.isoformat()

    @property
    def valid_from(self):
        return self.main_cert.cert.not_valid_before.isoformat()

    @property
    def typ(self):
        return self.main_cert.type

    @property
    def issuer(self):
        return self.main_cert.issuer

    @property
    def subject(self):
        return self.main_cert.print_subject()

    @property
    def ldap(self) -> str:
        """Creates an LDAP url (RFC 1959) for the certificate set"""

        ldap_filter = create_ldap_filter(
            [(SearchAttribute.CSN, str(cert.cert.serial_number)) for cert in self.certs]
        )
        ldap_url = "ldap://{}/{}?usercertificate;binary?sub?{}".format(
            self.certs[0].ldap_params[0],
            urllib.parse.quote(self.certs[0].ldap_params[1], safe="=,"),
            ldap_filter,
        )
        return ldap_url
