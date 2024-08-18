from __future__ import annotations

import datetime
from base64 import b64decode
from pathlib import Path
from urllib.parse import quote_plus

from attrs import frozen
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sertifikatsok.cert import MaybeInvalidCertificate
from sertifikatsok.utils import datetime_now_utc

ONE_DAY = datetime.timedelta(1, 0, 0)


def read_pem_file(path: str) -> bytes:
    pem_lines = Path(path).read_text().splitlines()
    base64_data = "".join(pem_lines[1:-1])
    return b64decode(base64_data.encode())


@frozen
class CertificateAuthority:
    name: str
    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @classmethod
    def create(
        cls, name: str, private_key: rsa.RSAPrivateKey | None = None
    ) -> CertificateAuthority:
        private_key = private_key or rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, name),
                    ]
                )
            )
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, name),
                    ]
                )
            )
            .not_valid_before(datetime_now_utc() - ONE_DAY)
            .not_valid_after(datetime_now_utc() + (ONE_DAY * 14))
            .serial_number(x509.random_serial_number())
            .public_key(private_key.public_key())
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
            )
        )
        return cls(name, cert, private_key)

    def generate_crl(
        self,
        revoked_certs: list[x509.Certificate],
        last_and_next_update: tuple[datetime.datetime, datetime.datetime] | None = None,
        extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    ) -> x509.CertificateRevocationList:
        if last_and_next_update is not None:
            last_update, next_update = last_and_next_update
        else:
            last_update = datetime_now_utc()
            next_update = last_update + ONE_DAY

        crl_builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, self.name),
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        if extra_extensions:
            for extval, critical in extra_extensions:
                crl_builder = crl_builder.add_extension(extval, critical)

        for revoked_cert in revoked_certs:
            crl_builder = crl_builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_cert.serial_number)
                .revocation_date(datetime_now_utc())
                .build()
            )

        return crl_builder.sign(
            private_key=self.key,
            algorithm=hashes.SHA256(),
        )

    def generate_ee_cert(
        self, name: str, *, expired: bool = False, crl_endpoint: str | None = None
    ) -> MaybeInvalidCertificate:
        date_skew = datetime.timedelta(days=-120 if expired else 0)
        if crl_endpoint is None:
            crl_endpoint = f"http://crl.watn.no/{quote_plus(self.name)}.crl"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cert = (
            x509.CertificateBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, self.name),
                    ]
                )
            )
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, name),
                    ]
                )
            )
            .not_valid_before(datetime_now_utc() - ONE_DAY + date_skew)
            .not_valid_after(datetime_now_utc() + (ONE_DAY * 3) + date_skew)
            .serial_number(x509.random_serial_number())
            .public_key(private_key.public_key())
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(crl_endpoint)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            )
            .sign(
                private_key=self.key,
                algorithm=hashes.SHA256(),
            )
        )
        return MaybeInvalidCertificate(
            cert,
            invalid=False,
            issuer=cert.issuer,
            subject=cert.subject,
            extensions=cert.extensions,
        )
