from __future__ import annotations

import logging
import string
from collections.abc import Iterable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from secrets import choice, randbelow, randbits
from typing import Literal, Self

from attrs import field, frozen, mutable
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    RSAPublicNumbers,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, Hash
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    AccessDescription,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CertificateBuilder,
    CertificatePolicies,
    CertificateRevocationListBuilder,
    CRLDistributionPoints,
    CRLNumber,
    CRLReason,
    DistributionPoint,
    ExtendedKeyUsage,
    ExtensionNotFound,
    ExtensionType,
    KeyUsage,
    Name,
    NameAttribute,
    ObjectIdentifier,
    OCSPNoCheck,
    OCSPNonce,
    PolicyInformation,
    ReasonFlags,
    RevokedCertificate,
    RevokedCertificateBuilder,
    RFC822Name,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
    ocsp,
    random_serial_number,
)
from cryptography.x509.ocsp import OCSPCertStatus
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)
from yarl import URL

from testserver import Enterprise, Env, LdapOU, OcspType, Person

logger = logging.getLogger(__name__)

SUPPORTED_HASH_ALGORITHMS = [SHA1(), SHA256()]  # noqa: S303


def get_key_usage(
    *,
    digital_signature: bool = False,
    content_commitment: bool = False,
    key_encipherment: bool = False,
    data_encipherment: bool = False,
    key_agreement: bool = False,
) -> KeyUsage:
    assert any(
        [
            digital_signature,
            content_commitment,
            key_encipherment,
            data_encipherment,
            key_agreement,
        ]
    )
    return KeyUsage(
        digital_signature=digital_signature,
        content_commitment=content_commitment,
        key_encipherment=key_encipherment,
        data_encipherment=data_encipherment,
        key_agreement=key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def generate_dummy_rsa_public_key(key_size: int) -> RSAPublicKey:
    # We need our integer to be exactly the key size,
    # so we need to make sure that the most significant bit
    # is 1, not 0.
    ksmo = key_size - 1
    n = randbits(ksmo) + (1 << ksmo)

    return RSAPublicNumbers(e=65537, n=n).public_key()


@frozen
class IssuedCertificate:
    certificate: Certificate
    cert_role: LdapOU | None
    enterprise_cert: bool | None


@mutable
class IssuedCertificateDatabase:
    issued_certs: dict[int, IssuedCertificate] = field(factory=dict)
    revoked_certs: dict[int, RevokedCertificate] = field(factory=dict)

    def add_issued_certs(self, certs: Iterable[IssuedCertificate]) -> None:
        for cert in certs:
            assert cert.certificate.serial_number not in self.issued_certs
            self.issued_certs[cert.certificate.serial_number] = cert

    def add_revoked_cert(self, cert: RevokedCertificate) -> None:
        assert cert.serial_number not in self.revoked_certs
        self.revoked_certs[cert.serial_number] = cert


class CertIssuingImpl:
    def __init__(
        self,
        cert: Certificate,
        private_key: RSAPrivateKey,
        cdp: list[URL],
        ocsp: URL,
        seid_v: Literal[1, 2],
        env: Env,
        cert_database: IssuedCertificateDatabase,
    ) -> None:
        self.cert = cert
        self.private_key = private_key
        self.seid_v = seid_v
        self.cdp = cdp
        self.cert_database = cert_database
        self.ocsp = ocsp
        self.env = env

    def _get_cert_builder(self) -> CertificateBuilder:
        return (
            CertificateBuilder()
            .issuer_name(self.cert.subject)
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(
                AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self.cert.extensions.get_extension_for_class(
                        SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )
            .add_extension(
                # I would argue that it should be two UniformResourceIdentifiers
                # in one DistributionPoint here, since both uris point to the
                # same CRL, but both CAs do it this way... ¯\_(ツ)_/¯
                CRLDistributionPoints(
                    [
                        DistributionPoint(
                            full_name=[UniformResourceIdentifier(str(cdp))],
                            relative_name=None,
                            crl_issuer=None,
                            reasons=None,
                        )
                        for cdp in self.cdp
                    ]
                ),
                critical=False,
            )
            .add_extension(
                AuthorityInformationAccess(
                    [
                        AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            UniformResourceIdentifier(str(self.ocsp)),
                        )
                    ]
                ),
                critical=False,
            )
        )

    def issue_person_certs(
        self,
        person: Person,
        valid_from: datetime,
    ) -> list[IssuedCertificate]:
        raise NotImplementedError()

    def issue_enterprise_certs(
        self,
        enterprise: Enterprise,
        valid_from: datetime,
        common_name: str | None = None,
        ou: str | None = None,
    ) -> list[IssuedCertificate]:
        raise NotImplementedError()

    def get_crl(self) -> bytes:
        now = datetime.now(tz=UTC)
        builder = (
            CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=1))
            .add_extension(CRLNumber(randbelow(100000)), critical=False)
            .add_extension(
                AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self.cert.extensions.get_extension_for_class(
                        SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )
        )

        for cert in self.cert_database.revoked_certs.values():
            builder = builder.add_revoked_certificate(cert)
        return builder.sign(self.private_key, SHA256()).public_bytes(Encoding.DER)

    def revoke_cert(self, cert: Certificate, reason: ReasonFlags | None = None) -> None:
        builder = (
            RevokedCertificateBuilder()
            .revocation_date(datetime.now(tz=UTC))
            .serial_number(cert.serial_number)
        )

        if reason is not None:
            builder = builder.add_extension(CRLReason(reason), critical=False)

        self.cert_database.add_revoked_cert(builder.build())


class CommfidesCertIssuingImpl(CertIssuingImpl):
    def _get_personal_serial(self) -> str:
        prefix = choice(
            [
                "9578-4500",
                "9578-4501",
                "9578-4502",
                "9578-4503",
                "9578-4504",
                "9578-4505",
                "9578-4506",
                "9578-4507",
                "9578-4508",
                "9578-4509",
                "9578-4510",
            ]
        )
        suffix = "".join(
            choice(string.ascii_letters + string.digits) for _ in range(11)
        )
        if self.seid_v == 2:
            return f"UN-NO:{prefix}-{suffix}"
        return f"{prefix}-{suffix}"

    def _issue_certs(
        self,
        subject_attrs: list[NameAttribute],
        key_size: int,
        valid_from: datetime,
        extra_extensions: list[ExtensionType],
        *,
        enterprise_cert: bool,
    ) -> list[IssuedCertificate]:
        valid_to = min(
            valid_from + timedelta(days=365 * 3),
            self.cert.not_valid_after_utc,
        )

        if valid_from > valid_to:
            valid_from = valid_to - timedelta(days=365 * 3)

        builder = (
            self._get_cert_builder()
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
        )

        if extra_extensions:
            for ext in extra_extensions:
                builder = builder.add_extension(ext, critical=False)

        if self.seid_v == 2:
            if self.env == "test":
                base_poid = (
                    "2.16.578.1.29.913.2" if enterprise_cert else "2.16.578.1.29.912.1"
                )
            else:
                base_poid = (
                    "2.16.578.1.29.13.2" if enterprise_cert else "2.16.578.1.29.12.1"
                )
            sign_poid = f"{base_poid}00.1.0"
            krypt_pod = f"{base_poid}10.1.0"
            auth_poid = f"{base_poid}20.1.0"
        else:
            # seid 1
            if self.env == "test":
                base_poid = (
                    "2.16.578.1.29.913.1.1.0"
                    if enterprise_cert
                    else "2.16.578.1.29.912.1.1.0"
                )
            else:
                base_poid = (
                    "2.16.578.1.29.13.1.1.0"
                    if enterprise_cert
                    else "2.16.578.1.29.12.1.1.0"
                )
            sign_poid = krypt_pod = auth_poid = base_poid

        if enterprise_cert:
            sign_subject_attrs = krypt_subject_attrs = auth_subject_attrs = (
                subject_attrs
            )
        else:
            if self.seid_v == 1:
                # Commfides uses different personal serials for each
                # cert in a set for seid v1
                sign_subject_attrs = [
                    NameAttribute(NameOID.SERIAL_NUMBER, self._get_personal_serial()),
                    *subject_attrs,
                ]
                krypt_subject_attrs = [
                    NameAttribute(NameOID.SERIAL_NUMBER, self._get_personal_serial()),
                    *subject_attrs,
                ]
                auth_subject_attrs = [
                    NameAttribute(NameOID.SERIAL_NUMBER, self._get_personal_serial()),
                    *subject_attrs,
                ]
            else:
                # same across all certs for SEIDv2
                sign_subject_attrs = krypt_subject_attrs = auth_subject_attrs = [
                    NameAttribute(NameOID.SERIAL_NUMBER, self._get_personal_serial()),
                    *subject_attrs,
                ]

        # Cryptography's builders doesn't mutate
        # so it's fine to use the same builder for
        # all here.
        sign_cert = (
            builder.subject_name(Name(sign_subject_attrs))
            .add_extension(
                get_key_usage(content_commitment=True),
                critical=True,
            )
            .add_extension(
                CertificatePolicies(
                    [
                        PolicyInformation(
                            ObjectIdentifier(sign_poid),
                            policy_qualifiers=None,
                        )
                    ]
                ),
                critical=False,
            )
            .add_extension(
                ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ]
                ),
                critical=False,
            )
            .serial_number(random_serial_number())
            .public_key(generate_dummy_rsa_public_key(key_size))
            .sign(self.private_key, SHA256())
        )

        auth_cert = (
            builder.subject_name(Name(auth_subject_attrs))
            .add_extension(
                get_key_usage(
                    digital_signature=True,
                ),
                critical=True,
            )
            .add_extension(
                CertificatePolicies(
                    [
                        PolicyInformation(
                            ObjectIdentifier(auth_poid),
                            policy_qualifiers=None,
                        )
                    ]
                ),
                critical=False,
            )
            .add_extension(
                ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                        ExtendedKeyUsageOID.SMARTCARD_LOGON,
                    ]
                ),
                critical=False,
            )
            .serial_number(random_serial_number())
            .public_key(generate_dummy_rsa_public_key(key_size))
            .sign(self.private_key, SHA256())
        )

        krypt_cert = (
            builder.subject_name(Name(krypt_subject_attrs))
            .add_extension(
                get_key_usage(
                    key_encipherment=True,
                    data_encipherment=True,
                    # this is not allowed for RSA keys,
                    # but this is a Commfides cert, so
                    # no rules apply
                    key_agreement=True,
                ),
                critical=True,
            )
            .add_extension(
                CertificatePolicies(
                    [
                        PolicyInformation(
                            ObjectIdentifier(krypt_pod),
                            policy_qualifiers=None,
                        )
                    ]
                ),
                critical=False,
            )
            .add_extension(
                ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ]
                ),
                critical=False,
            )
            .serial_number(random_serial_number())
            .public_key(generate_dummy_rsa_public_key(key_size))
            .sign(self.private_key, SHA256())
        )

        auth_ldap_cert = IssuedCertificate(
            auth_cert, LdapOU.AUTH, enterprise_cert=enterprise_cert
        )
        sign_ldap_cert = IssuedCertificate(
            sign_cert, LdapOU.SIGN, enterprise_cert=enterprise_cert
        )
        krypt_ldap_cert = IssuedCertificate(
            krypt_cert, LdapOU.CRYPT, enterprise_cert=enterprise_cert
        )
        issued_certs = [auth_ldap_cert, sign_ldap_cert, krypt_ldap_cert]
        self.cert_database.add_issued_certs(issued_certs)
        return issued_certs

    def issue_person_certs(
        self,
        person: Person,
        valid_from: datetime,
    ) -> list[IssuedCertificate]:
        if self.seid_v == 1:
            subject_attrs = [
                NameAttribute(NameOID.COMMON_NAME, person.full_name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
        else:
            subject_attrs = [
                NameAttribute(NameOID.COMMON_NAME, person.full_name),
                NameAttribute(NameOID.GIVEN_NAME, person.given_name),
                NameAttribute(NameOID.SURNAME, person.family_name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]

        extra_extensions: list[ExtensionType] = []
        if person.email:
            extra_extensions.append(SubjectAlternativeName([RFC822Name(person.email)]))

        return self._issue_certs(
            subject_attrs,
            2048,
            valid_from,
            extra_extensions,
            enterprise_cert=False,
        )

    def issue_enterprise_certs(
        self,
        enterprise: Enterprise,
        valid_from: datetime,
        common_name: str | None = None,
        ou: str | None = None,
    ) -> list[IssuedCertificate]:
        if self.seid_v == 1:
            subject_attrs = [
                NameAttribute(NameOID.SERIAL_NUMBER, enterprise.org_nr),
                NameAttribute(NameOID.COMMON_NAME, common_name or enterprise.name),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou or enterprise.name),
                NameAttribute(NameOID.ORGANIZATION_NAME, enterprise.name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 2048
        else:
            subject_attrs = [
                NameAttribute(NameOID.SERIAL_NUMBER, enterprise.org_nr),
                NameAttribute(
                    NameOID.ORGANIZATION_IDENTIFIER, f"NTRNO-{enterprise.org_nr}"
                ),
                NameAttribute(NameOID.COMMON_NAME, common_name or enterprise.name),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou or enterprise.name),
                NameAttribute(NameOID.ORGANIZATION_NAME, enterprise.name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 3072

        return self._issue_certs(
            subject_attrs,
            key_size,
            valid_from,
            extra_extensions=[],
            enterprise_cert=True,
        )


class BuypassCertIssuingImpl(CertIssuingImpl):
    def _issue_certs(
        self,
        subject_attrs: list[NameAttribute],
        key_size: int,
        valid_from: datetime,
        policy_oid: str,
        extra_extensions: list[ExtensionType] | None = None,
        *,
        include_eku: bool,
    ) -> list[IssuedCertificate]:
        valid_to = min(
            valid_from + timedelta(days=365 * 3),
            self.cert.not_valid_after_utc,
        )

        # TODO: fix this
        if valid_from > valid_to:
            valid_from = valid_to - timedelta(days=365 * 3)

        builder = (
            self._get_cert_builder()
            .subject_name(Name(subject_attrs))
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(
                CertificatePolicies(
                    [
                        PolicyInformation(
                            ObjectIdentifier(policy_oid),
                            policy_qualifiers=None,
                        )
                    ]
                ),
                critical=False,
            )
        )
        if include_eku:
            builder = builder.add_extension(
                ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ]
                ),
                critical=False,
            )
        if extra_extensions:
            for ext in extra_extensions:
                builder = builder.add_extension(ext, critical=False)

        # Cryptography's builders doesn't mutate
        # so it's fine to use the same builder for
        # both here.
        sign_cert = (
            builder.add_extension(
                get_key_usage(content_commitment=True),
                critical=True,
            )
            .serial_number(random_serial_number())
            .public_key(generate_dummy_rsa_public_key(key_size))
            .sign(self.private_key, SHA256())
        )

        auth_cert = (
            builder.add_extension(
                get_key_usage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=bool(self.seid_v == 1),
                ),
                critical=True,
            )
            .serial_number(random_serial_number())
            .public_key(generate_dummy_rsa_public_key(key_size))
            .sign(self.private_key, SHA256())
        )

        auth_ldap_cert = IssuedCertificate(auth_cert, None, None)
        sign_ldap_cert = IssuedCertificate(sign_cert, None, None)
        issued_certs = [auth_ldap_cert, sign_ldap_cert]
        self.cert_database.add_issued_certs(issued_certs)
        return issued_certs

    def issue_person_certs(
        self,
        person: Person,
        valid_from: datetime,
    ) -> list[IssuedCertificate]:
        if self.seid_v == 1:
            subject_attrs = [
                NameAttribute(NameOID.SERIAL_NUMBER, person.buypass_id),
                NameAttribute(NameOID.COMMON_NAME, person.full_name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 2032
        else:
            subject_attrs = [
                NameAttribute(NameOID.SERIAL_NUMBER, f"UN:NO-{person.buypass_id}"),
                NameAttribute(NameOID.COMMON_NAME, person.full_name),
                NameAttribute(NameOID.GIVEN_NAME, person.given_name),
                NameAttribute(NameOID.SURNAME, person.family_name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 2048

        extra_extensions: list[ExtensionType] = []
        if person.email and self.seid_v == 1:
            # Buypass doesn't include email in SEIDv2 certs
            extra_extensions.append(SubjectAlternativeName([RFC822Name(person.email)]))

        if self.seid_v == 1 and self.env == "test":
            policy_oid = "2.16.578.1.26.1.0"
        else:
            policy_oid = "2.16.578.1.26.1.3.1"

        return self._issue_certs(
            subject_attrs,
            key_size,
            valid_from,
            policy_oid,
            extra_extensions,
            include_eku=self.seid_v == 1,
        )

    def issue_enterprise_certs(
        self,
        enterprise: Enterprise,
        valid_from: datetime,
        common_name: str | None = None,
        ou: str | None = None,
    ) -> list[IssuedCertificate]:
        if self.seid_v == 1:
            subject_attrs = [
                NameAttribute(NameOID.SERIAL_NUMBER, enterprise.org_nr),
                NameAttribute(NameOID.COMMON_NAME, common_name or enterprise.name),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou or enterprise.name),
                NameAttribute(NameOID.ORGANIZATION_NAME, enterprise.name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 2048
        else:
            subject_attrs = [
                NameAttribute(
                    NameOID.ORGANIZATION_IDENTIFIER, f"NTRNO-{enterprise.org_nr}"
                ),
                NameAttribute(NameOID.COMMON_NAME, common_name or enterprise.name),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou or enterprise.name),
                NameAttribute(NameOID.ORGANIZATION_NAME, enterprise.name),
                NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            ]
            key_size = 3072

        if self.seid_v == 1 and self.env == "test":
            policy_oid = "2.16.578.1.26.1.0.3.2"
        else:
            policy_oid = "2.16.578.1.26.1.3.2"

        return self._issue_certs(
            subject_attrs,
            key_size,
            valid_from,
            policy_oid,
            include_eku=self.seid_v == 1,
        )


@frozen
class CertificateAuthority:
    impl: CertIssuingImpl
    ldap_name: str | None
    ocsp_responder: OcspResponder
    cert_database: IssuedCertificateDatabase

    @property
    def name(self) -> str:
        cn_value = self.impl.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value
        assert isinstance(cn_value, str)
        return cn_value

    @classmethod
    def create_from_cache(
        cls,
        cdp: list[URL],
        ocsp_url: URL,
        ocsp_type: OcspType,
        ocsp_response_lifetime: timedelta | None,
        cached_cert: Certificate,
        cached_key: RSAPrivateKey,
        seid_v: Literal[1, 2],
        impl_class: type[CertIssuingImpl],
        ldap_name: str | None,
        delegated_responder: tuple[Certificate, RSAPrivateKey] | None,
        env: Env,
    ) -> Self:
        cert_database = IssuedCertificateDatabase()

        return cls(
            impl_class(
                cached_cert, cached_key, cdp, ocsp_url, seid_v, env, cert_database
            ),
            ldap_name,
            OcspResponder(
                *(delegated_responder or (cached_cert, cached_key)),
                cached_cert,
                ocsp_type,
                URL(ocsp_url),
                ocsp_response_lifetime,
                cert_database,
            ),
            cert_database,
        )

    @classmethod
    def create_from_original(
        cls,
        cdp: list[URL],
        ocsp_url: URL,
        ocsp_type: OcspType,
        ocsp_response_lifetime: timedelta | None,
        org_cert: Certificate,
        seid_v: Literal[1, 2],
        impl_class: type[CertIssuingImpl],
        ldap_name: str | None,
        env: Env,
        *,
        generate_delegated_responder: bool,
    ) -> Self:
        cert_database = IssuedCertificateDatabase()

        org_cert_pubkey = org_cert.public_key()
        assert isinstance(org_cert_pubkey, RSAPublicKey)
        private_key = generate_private_key(65537, org_cert_pubkey.key_size)

        builder = (
            CertificateBuilder()
            .subject_name(org_cert.subject)
            .issuer_name(org_cert.issuer)
            .not_valid_before(org_cert.not_valid_before_utc)
            .not_valid_after(org_cert.not_valid_after_utc)
            .serial_number(org_cert.serial_number)
            .public_key(private_key.public_key())
        )
        for ext in org_cert.extensions:
            builder = builder.add_extension(ext.value, ext.critical)

        signing_key = (
            generate_private_key(65537, len(org_cert.signature) * 8)
            if org_cert.issuer != org_cert.subject
            else private_key
        )

        certificate = builder.sign(
            private_key=signing_key,
            algorithm=SHA256(),
        )

        ocsp_responder = (
            OcspResponder.create_delegated_responder(
                certificate,
                private_key,
                ocsp_type,
                URL(ocsp_url),
                ocsp_response_lifetime,
                cert_database,
            )
            if generate_delegated_responder
            else OcspResponder(
                certificate,
                private_key,
                certificate,
                ocsp_type,
                URL(ocsp_url),
                ocsp_response_lifetime,
                cert_database,
            )
        )
        return cls(
            impl_class(
                certificate, private_key, cdp, ocsp_url, seid_v, env, cert_database
            ),
            ldap_name,
            ocsp_responder,
            cert_database,
        )


@frozen
class OcspResponder:
    cert: Certificate
    private_key: RSAPrivateKey
    ca_cert: Certificate
    type: OcspType
    url: URL
    response_lifetime: timedelta | None
    cert_database: IssuedCertificateDatabase

    @classmethod
    def create_delegated_responder(
        cls,
        certificate: Certificate,
        private_key: RSAPrivateKey,
        type: OcspType,
        url: URL,
        response_lifetime: timedelta | None,
        cert_database: IssuedCertificateDatabase,
    ) -> Self:
        not_valid_before = datetime.now(tz=UTC)
        not_valid_after = not_valid_before + timedelta(days=180)
        responder_private_key = generate_private_key(65537, 2048)

        responder_cert = (
            CertificateBuilder()
            .subject_name(
                Name([NameAttribute(NameOID.COMMON_NAME, "Delegated OCSP responder")])
            )
            .issuer_name(certificate.subject)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .serial_number(random_serial_number())
            .public_key(responder_private_key.public_key())
            .add_extension(
                ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=False,
            )
            .add_extension(OCSPNoCheck(), critical=False)
            .sign(
                private_key=private_key,
                algorithm=SHA256(),
            )
        )
        return cls(
            responder_cert,
            responder_private_key,
            certificate,
            type,
            url,
            response_lifetime,
            cert_database,
        )

    @staticmethod
    def _get_nonce_from_request(ocsp_req: ocsp.OCSPRequest):
        for extension in ocsp_req.extensions:
            if extension.oid == OCSPNonce.oid:
                if (nonce_length := len(extension.value.nonce)) > 30:
                    raise ValueError(f"Nonce in request too large ({nonce_length})")
                return extension.value.nonce
        return None

    def get_cert_status(
        self, cert_serial: int
    ) -> (
        tuple[Literal[OCSPCertStatus.GOOD], None, None]
        | tuple[Literal[OCSPCertStatus.UNKNOWN], None, None]
        | tuple[Literal[OCSPCertStatus.REVOKED], datetime, ReasonFlags]
    ):
        if cert_serial not in self.cert_database.issued_certs:
            return OCSPCertStatus.UNKNOWN, None, None

        if (
            revoked_cert := self.cert_database.revoked_certs.get(cert_serial)
        ) is not None:
            reason = ReasonFlags.unspecified
            with suppress(ExtensionNotFound):
                reason = revoked_cert.extensions.get_extension_for_class(
                    CRLReason
                ).value.reason
            return OCSPCertStatus.REVOKED, revoked_cert.revocation_date_utc, reason

        return OCSPCertStatus.GOOD, None, None

    def get_response(self, ocsp_request: ocsp.OCSPRequest) -> bytes:
        cert_status, revocation_time, revocation_reason = self.get_cert_status(
            ocsp_request.serial_number
        )
        if cert_status is OCSPCertStatus.UNKNOWN:
            raise ValueError(f"No issued cert with serial {ocsp_request.serial_number}")

        cert = self.cert_database.issued_certs[ocsp_request.serial_number]

        this_update = datetime.now(tz=UTC)
        next_update = (
            this_update + self.response_lifetime
            if self.response_lifetime is not None
            else None
        )

        resp_builder = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=cert.certificate,
                issuer=self.ca_cert,
                algorithm=ocsp_request.hash_algorithm,
                cert_status=cert_status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            )
            .responder_id(
                ocsp.OCSPResponderEncoding.HASH
                if self.type.is_key_hash
                else ocsp.OCSPResponderEncoding.NAME,
                self.cert,
            )
        )
        if self.type.is_delegated_responder:
            resp_builder = resp_builder.certificates([self.cert])

        if (nonce := self._get_nonce_from_request(ocsp_request)) is not None:
            resp_builder = resp_builder.add_extension(OCSPNonce(nonce), critical=False)

        ocsp_response = resp_builder.sign(self.private_key, SHA256())
        return ocsp_response.public_bytes(Encoding.DER)


@frozen
class CertificateId:
    hash_name: str
    name_hash: bytes
    key_hash: bytes

    @classmethod
    def from_ocsp_request(cls, ocsp_req: ocsp.OCSPRequest):
        return cls(
            ocsp_req.hash_algorithm.name,
            ocsp_req.issuer_name_hash,
            ocsp_req.issuer_key_hash,
        )


@frozen
class OcspResponders:
    responders: dict[CertificateId, OcspResponder]

    @classmethod
    def create(cls, ocsp_responders: list[OcspResponder]) -> Self:
        responders_mapping = {}
        for ocsp_responder in ocsp_responders:
            cert_ids = cls.get_cert_ids(ocsp_responder.ca_cert)
            for cert_id in cert_ids:
                responders_mapping[cert_id] = ocsp_responder
        return cls(responders_mapping)

    @staticmethod
    def get_cert_ids(issuer: Certificate) -> list[CertificateId]:
        ids = []
        for hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            name_hash = Hash(hash_algorithm)
            name_hash.update(issuer.subject.public_bytes())
            issuer_name_hash = name_hash.finalize()

            key_hash = Hash(hash_algorithm)
            key_hash.update(
                issuer.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
            )
            issuer_key_hash = key_hash.finalize()

            ids.append(
                CertificateId(hash_algorithm.name, issuer_name_hash, issuer_key_hash)
            )
        return ids
