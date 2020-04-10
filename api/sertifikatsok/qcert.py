import urllib.parse
import logging
from datetime import datetime
from typing import Optional, List, Tuple

import attr

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature


from .utils import get_subject_order, stringify_x509_name
from .constants import (
    KNOWN_CERT_TYPES,
    UNDERENHET_REGEX,
    SUBJECT_FIELDS,
    KEY_USAGES,
    EXTENDED_KEY_USAGES,
)
from .enums import CertType, CertificateStatus, CertificateRoles

logger = logging.getLogger(__name__)


class QualifiedCertificate:
    """Represents a Norwegian Qualified Certificate"""

    def __init__(self, cert, dn, ldap_params):
        self.cert = x509.load_der_x509_certificate(cert, default_backend())

        self.issuer = stringify_x509_name(self.cert.issuer)
        self.type, self.description = self._get_type()
        self.roles = self._get_roles()
        self.dn = dn
        self.ldap_params = ldap_params
        self.status = CertificateStatus.UNKNOWN
        self.revocation_date = None

    @classmethod
    async def create(cls, raw_cert, dn, ldap_params, crl_retriever, cert_retriever):

        cert = cls(raw_cert, dn, ldap_params)

        issuer = cert_retriever.retrieve(cert.issuer)
        if not issuer:
            # TODO: Should this be UNKNOWN? We don't
            # trust the issuer, but others might...
            cert.status = CertificateStatus.INVALID
        elif not cert._validate_against_issuer(issuer):
            cert.status = CertificateStatus.INVALID
        elif not cert._check_date():
            cert.status = CertificateStatus.EXPIRED
        else:
            crl = await crl_retriever.retrieve(cert._get_http_cdp(), issuer)
            if not crl:
                cert.status = CertificateStatus.UNKNOWN
            else:
                revoked_cert = crl.get_revoked_certificate_by_serial_number(
                    cert.cert.serial_number
                )
                if revoked_cert:
                    cert.status = CertificateStatus.REVOKED
                    cert.revocation_date = revoked_cert.revocation_date
                else:
                    cert.status = CertificateStatus.OK
        return cert

    def _check_date(self):
        """Returns whether the certificate is valid wrt. the dates"""
        return (
            self.cert.not_valid_after > datetime.utcnow()
            and self.cert.not_valid_before < datetime.utcnow()
        )

    def _validate_against_issuer(self, issuer: x509.Certificate) -> bool:
        """Validates a certificate against it's (alleged) issuer"""

        if not self.cert.issuer == issuer.subject:
            return False
        try:
            issuer.public_key().verify(
                self.cert.signature,
                self.cert.tbs_certificate_bytes,
                PKCS1v15(),
                self.cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False
        else:
            return True

    def _get_type(self) -> Tuple[CertType, str]:
        """Returns the type of certificate, based on issuer and Policy OID"""
        cert_policies = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("2.5.29.32")
        ).value

        for policy in cert_policies:
            try:
                oid = policy.policy_identifier.dotted_string
                return KNOWN_CERT_TYPES[(self.issuer, oid)]
            except KeyError:
                pass

        oids = [policy.policy_identifier.dotted_string for policy in cert_policies]

        logger.warn("Unknown certificate type. OIDs=%s Issuer='%s'", oids, self.issuer)

        return (CertType.UNKNOWN, ", ".join(oids))

    def _get_http_cdp(self) -> Optional[str]:
        """
        Returns the first CRL Distribution Point from the cert with
        http scheme, if any.
        """
        cdps = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("2.5.29.31")
        ).value
        for cdp in cdps:
            url = urllib.parse.urlparse(cdp.full_name[0].value)
            if url.scheme == "http":
                return cdp.full_name[0].value
        return None

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
        key_usage = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
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

    def get_orgnumber(self) -> Tuple[Optional[str], bool]:
        """
        Gets the organization number from the cert,
        and returns the organization number + if it's an "underenhet"
        """
        if self.type != CertType.ENTERPRISE:
            return None, False

        serial_number = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[
            0
        ].value

        try:
            ou_field = self.cert.subject.get_attributes_for_oid(
                NameOID.ORGANIZATIONAL_UNIT_NAME
            )[0].value
        except IndexError:
            return serial_number, False

        ou_number = UNDERENHET_REGEX.search(ou_field)

        if ou_number and serial_number != ou_number[0]:
            return ou_number[0], True

        return serial_number, False

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
            cert_eku = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value
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


@attr.s(frozen=True, slots=True)
class QualifiedCertificateSet:
    """Represents a set of Norwegian qualified certificates"""

    certs = attr.ib()
    main_cert = attr.ib()
    status = attr.ib()
    revocation_date = attr.ib()
    org_number = attr.ib()
    underenhet = attr.ib()

    @classmethod
    def create(cls, certs):

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
        return cls(certs, main_cert, status, revocation_date, org_number, underenhet)

    @classmethod
    def create_sets_from_certs(
        cls, certs: List[QualifiedCertificate]
    ) -> List["QualifiedCertificateSet"]:
        """
        This creates a list of QualifiedCertificateSet
        from a list of QualifiedCertificate.

        This is quite hard as there isn't anything that ties the certs together.
        But they (usually?) come right after each other from the LDAP server,
        and the subjects should be the same (except the serialNumber on non-Enterprise
        certs from Commfides) and they should be issued at the same time
        (except encryption certificates from Commfides)... *sigh*
        """
        if not certs:
            return []

        cert_sets: List[QualifiedCertificateSet] = []
        cert_set: List[QualifiedCertificate] = []
        cert_set_roles: List[CertificateRoles] = []

        counter = 0
        while counter < len(certs):

            cert = certs[counter]

            if not cert_set:
                cert_set_roles = cert.roles.copy()
            elif (
                # Certificates in a set should have the same subject,
                # so if they differ they are not from the same set
                (cert_set[0].print_subject() != cert.print_subject())
                or
                # Certificats in a set should have the same type description
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
            counter += 1

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
        filter_parts = []
        for cert in self.certs:
            filter_parts.append(f"certificateSerialNumber={cert.cert.serial_number}")
        ldap_filter = ")(".join(filter_parts)
        ldap_url = "ldap://{}/{}?usercertificate;binary?sub?(|({}))".format(
            self.certs[0].ldap_params[0],
            urllib.parse.quote(self.certs[0].ldap_params[1], safe="=,"),
            ldap_filter,
        )
        return ldap_url
