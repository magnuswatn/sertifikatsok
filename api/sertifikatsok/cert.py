from __future__ import annotations

import logging
from datetime import datetime

from attr import frozen
from cryptography.x509 import (
    Certificate,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    Extensions,
    KeyUsage,
    Name,
    load_der_x509_certificate,
)

logger = logging.getLogger(__name__)


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
        cert = load_der_x509_certificate(raw_cert)

        try:
            subject = cert.subject
        except ValueError:
            logger.info("ValueError while parsing certificate subject", exc_info=True)
            invalid = True
            subject = None

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
        return self.cert.not_valid_after

    @property
    def not_valid_before(self) -> datetime:
        return self.cert.not_valid_before

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
