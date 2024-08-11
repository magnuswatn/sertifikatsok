from __future__ import annotations

import logging
import string
from datetime import UTC, datetime, timedelta
from secrets import choice, randbelow, randbits
from typing import Literal, Self

from attrs import field, frozen
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    RSAPublicNumbers,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
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
    ExtensionType,
    KeyUsage,
    Name,
    NameAttribute,
    ObjectIdentifier,
    PolicyInformation,
    ReasonFlags,
    RevokedCertificate,
    RevokedCertificateBuilder,
    RFC822Name,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
    random_serial_number,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from testserver import Enterprise, Env, LdapOU, Person

logger = logging.getLogger(__name__)


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


class CertIssuingImpl:
    def __init__(
        self,
        cert: Certificate,
        private_key: RSAPrivateKey,
        cdp: list[str],
        seid_v: Literal[1, 2],
        env: Env,
    ) -> None:
        self.cert = cert
        self.private_key = private_key
        self.seid_v = seid_v
        self.cdp = cdp
        self.revoked_certs: list[RevokedCertificate] = []
        self.issued_certs: list[IssuedCertificate] = []
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
                            full_name=[UniformResourceIdentifier(cdp)],
                            relative_name=None,
                            crl_issuer=None,
                            reasons=None,
                        )
                        for cdp in self.cdp
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

        for cert in self.revoked_certs:
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

        self.revoked_certs.append(builder.build())


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
        self.issued_certs.extend(issued_certs)
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
        self.issued_certs.extend(issued_certs)
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

    issued_certs: list[IssuedCertificate] = field(factory=list)
    revoked_certs: list[RevokedCertificate] = field(factory=list)

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
        cdp: list[str],
        cached_cert: Certificate,
        cached_key: RSAPrivateKey,
        seid_v: Literal[1, 2],
        impl_class: type[CertIssuingImpl],
        ldap_name: str | None,
        env: Env,
    ) -> Self:
        return cls(impl_class(cached_cert, cached_key, cdp, seid_v, env), ldap_name)

    @classmethod
    def create_from_original(
        cls,
        cdp: list[str],
        org_cert: Certificate,
        seid_v: Literal[1, 2],
        impl_class: type[CertIssuingImpl],
        ldap_name: str | None,
        env: Env,
    ) -> Self:
        org_cert_pubkey = org_cert.public_key()
        assert isinstance(org_cert_pubkey, RSAPublicKey)
        private_key = generate_private_key(65537, org_cert_pubkey.key_size)

        builder = (
            CertificateBuilder()
            .subject_name(org_cert.subject)
            .issuer_name(org_cert.issuer)
            .not_valid_before(org_cert.not_valid_before)
            .not_valid_after(org_cert.not_valid_after)
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
        return cls(impl_class(certificate, private_key, cdp, seid_v, env), ldap_name)
