from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated

from attrs import frozen
from cryptography.hazmat import asn1
from cryptography.x509 import (
    Certificate,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    Extensions,
    KeyUsage,
    Name,
    ObjectIdentifier,
    load_der_x509_certificate,
)

logger = logging.getLogger(__name__)


@asn1.sequence
class Asn1Extension:
    extnID: ObjectIdentifier
    critical: Annotated[bool, asn1.Default(value=False)]
    extnValue: bytes


@asn1.sequence
class Asn1TbsCertificate:
    version: Annotated[int, asn1.Explicit(0), asn1.Default(0)]
    serialNumber: asn1.TLV
    signature: asn1.TLV
    issuer: asn1.TLV
    validity: asn1.TLV
    subject: asn1.TLV
    subjectPublicKeyInfo: asn1.TLV
    issuerUniqueID: Annotated[bytes | None, asn1.Implicit(1)]
    subjectUniqueID: Annotated[bytes | None, asn1.Implicit(2)]
    extensions: Annotated[list[Asn1Extension] | None, asn1.Explicit(3)]


@asn1.sequence
class Asn1Certificate:
    tbsCertificate: Asn1TbsCertificate
    signatureAlgorithm: asn1.TLV
    signature: asn1.BitString


EMPTY_NAME = asn1.decode_der(asn1.TLV, Name([]).public_bytes())


@frozen
class MaybeInvalidCertificate:
    """
    Wrapper around x509.Certificate that makes it easier
    to deal with malformed certificates.
    """

    cert: Certificate
    invalid: bool
    issuer: Name
    subject: Name | None
    extensions: Extensions | None

    @classmethod
    def create(cls, raw_cert: bytes) -> MaybeInvalidCertificate:
        invalid = False

        try:
            cert = load_der_x509_certificate(raw_cert)
        except ValueError:
            logger.info(
                "ValueError while parsing certificate, reparsing without subject",
                exc_info=True,
            )
            invalid = True
            # This is most likely because of a malformed subject. Try to
            # replace the subject with an empty one, and re-parse it.
            # This will, of course, invalidate the signature, but we label
            # malformed certs as invalid anyways, so it shouldn't matter.
            asn1_cert = asn1.decode_der(Asn1Certificate, raw_cert)
            asn1_cert.tbsCertificate.subject = EMPTY_NAME
            cert = load_der_x509_certificate(asn1.encode_der(asn1_cert))
            subject = None
        else:
            subject = cert.subject

        try:
            extensions = cert.extensions
        except ValueError:
            logger.info(
                "ValueError while parsing certificate extensions", exc_info=True
            )
            invalid = True
            extensions = None

        return cls(cert, invalid, cert.issuer, subject, extensions)

    @property
    def not_valid_after(self) -> datetime:
        return self.cert.not_valid_after_utc

    @property
    def not_valid_before(self) -> datetime:
        return self.cert.not_valid_before_utc

    @property
    def key_usage(self) -> KeyUsage | None:
        if self.extensions is None:
            return None
        return self.extensions.get_extension_for_class(KeyUsage).value

    @property
    def extended_key_usage(self) -> ExtendedKeyUsage | None:
        if self.extensions is None:
            return None
        return self.extensions.get_extension_for_class(ExtendedKeyUsage).value

    @property
    def cert_policies(self) -> CertificatePolicies | None:
        if self.extensions is None:
            return None
        return self.extensions.get_extension_for_class(CertificatePolicies).value

    @property
    def cdp(self) -> CRLDistributionPoints | None:
        if self.extensions is None:
            return None
        return self.extensions.get_extension_for_class(CRLDistributionPoints).value
