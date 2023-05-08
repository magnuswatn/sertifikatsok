from __future__ import annotations

import logging
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, cast

from attrs import field, frozen
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from httpx import AsyncClient, HTTPError

from .cert import MaybeInvalidCertificate
from .enums import CertificateStatus, Environment
from .errors import ConfigurationError, CouldNotGetValidCRLError
from .logging import performance_log

logger = logging.getLogger(__name__)


class CrlDownloaderProto(Protocol):
    async def download_crl(self, url: str) -> bytes:
        ...


class AppCrlRetrieverProto(Protocol):
    """
    Only returns validated CRLs.
    """

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        ...


class RequestCrlRetrieverProto(Protocol):
    """
    Cached CRLs are returned without validation,
    so objects should not be long-lived.
    """

    errors: list[str]

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList | None:
        ...


class CrlDownloader:
    HEADERS = {"user-agent": "sertifikatsok.no"}

    async def download_crl(self, url: str) -> bytes:
        async with AsyncClient() as client:
            return await self._download_crl_with_client(client, url)

    async def _download_crl_with_client(self, client: AsyncClient, url: str) -> bytes:
        logger.info("Downloading CRL %s", url)
        try:
            resp = await client.get(url, headers=self.HEADERS)
        except HTTPError as error:
            raise CouldNotGetValidCRLError() from error

        logger.debug("Finishined downloading CRL %s", url)

        if resp.status_code != 200:
            raise CouldNotGetValidCRLError(
                f"Got status code {resp.status_code} for url {url}"
            )

        if (content_type := resp.headers.get("Content-Type")) not in {
            "application/pkix-crl",
            "application/x-pkcs7-crl",
        }:
            raise CouldNotGetValidCRLError(
                f"Got content type: {content_type} for url {url}"
            )
        return resp.content


@frozen
class AppCrlRetriever:
    """
    CRL retriever for an app instance.

    Retrieves CRLs and caches them in the file system and in memory.

    Only returns valid CRLs.
    """

    crl_downloader: CrlDownloaderProto
    crls: dict[str, x509.CertificateRevocationList] = field(factory=dict)

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves the CRL from the specified url"""
        try:
            return self._get_cached_crl(url, issuer)
        except CouldNotGetValidCRLError as error:
            logger.debug("Could not get CRL '%s' from memory cache: %s", url, error)
            try:
                crl = self._get_from_file(url, issuer)
            except CouldNotGetValidCRLError as error:
                logger.debug("Could not get CRL '%s' from file: %s", url, error)
                crl = await self._download(url, issuer)

            self.crls[url] = crl
            return crl

    def get_retriever_for_request(self) -> RequestCrlRetriever:
        """
        Returns a retriever suitable for a single request,
        based on this retriever
        """
        return RequestCrlRetriever(self)

    def _get_cached_crl(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Returnes CRL from memory"""
        try:
            crl = self.crls[url]
        except KeyError:
            raise CouldNotGetValidCRLError(
                "Not in AppCrlRetriever memory cache"
            ) from None

        self._validate(crl, issuer)

        logger.debug("Returning CRL for %s from memory", url)
        return crl

    def _get_from_file(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves a CRL from disk"""
        try:
            crl_bytes = Path("crls", urllib.parse.quote_plus(url)).read_bytes()
        except FileNotFoundError:
            raise CouldNotGetValidCRLError("Not found on disk") from None

        try:
            crl = x509.load_der_x509_crl(crl_bytes)
        except ValueError as error:
            raise CouldNotGetValidCRLError(error) from error

        self._validate(crl, issuer)

        logger.debug("Returning CRL for %s from disk", url)
        return crl

    @performance_log(id_param=1)
    async def _download(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Downloads a crl from the specified url"""

        crl_bytes = await self.crl_downloader.download_crl(url)

        try:
            crl = x509.load_der_x509_crl(crl_bytes)
        except ValueError as error:
            raise CouldNotGetValidCRLError(error) from error

        self._validate(crl, issuer)

        Path("crls", urllib.parse.quote_plus(url)).write_bytes(crl_bytes)

        return crl

    @staticmethod
    def _validate(
        crl: x509.CertificateRevocationList, issuer: x509.Certificate
    ) -> None:
        """Validates a crl against an issuer certificate"""

        if crl.next_update is None:
            # rfc5280: Conforming CRL issuers MUST
            # include the nextUpdate field in all CRLs.
            raise CouldNotGetValidCRLError("CRL is missing next update field")

        now = datetime.utcnow()  # noqa: DTZ003
        if not (crl.next_update > now and crl.last_update < now):
            raise CouldNotGetValidCRLError(
                f"CRL failed date validation. "
                f"Last update: '{crl.last_update}' Next Update: '{crl.next_update}'"
            )

        if not crl.issuer == issuer.subject:
            raise CouldNotGetValidCRLError(
                f"CRL failed issuer validation. "
                f"Expected: {issuer.subject.rfc4514_string()} "
                f"Actual: {crl.issuer.rfc4514_string()}."
            )

        # cast because mypy. The type of key is checked
        # when it is loaded in CertRetriever.
        if not crl.is_signature_valid(cast(RSAPublicKey, issuer.public_key())):
            raise CouldNotGetValidCRLError("CRL failed signature validation")


@frozen
class RequestCrlRetriever:
    """
    CRL retriever for a single request.

    Cached CRLs are returned without validation,
    so objects should not be long-lived.
    """

    crl_retriever: AppCrlRetrieverProto
    crls: dict[tuple[str, x509.Name], x509.CertificateRevocationList | None] = field(
        factory=dict
    )
    errors: list[str] = field(factory=list)

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList | None:
        """Retrieves the CRL from the specified url."""
        try:
            return self.crls[url, issuer.subject]
        except KeyError:
            pass

        logger.debug(
            "CRL %s not in RequestCrlRetriever cache. Retrieving from AppCrlRetriever",
            url,
        )

        crl: x509.CertificateRevocationList | None
        try:
            crl = await self.crl_retriever.retrieve(url, issuer)
        except CouldNotGetValidCRLError:
            logger.exception("Could not retrieve CRL %s", url)
            self.errors.append("ERR-003")
            crl = None

        self.crls[url, issuer.subject] = crl
        return crl


@frozen
class CertRetriever:
    certs: dict[x509.Name, x509.Certificate]

    @classmethod
    def create(cls, env: Environment) -> CertRetriever:
        return cls(cls._load_all_certs(env))

    def retrieve(self, name: x509.Name) -> x509.Certificate | None:
        """
        Retrieves the CA certificate with the specified name
        """
        return self.certs.get(name)

    @staticmethod
    def _load_certificate(path: Path, certs: dict[x509.Name, x509.Certificate]) -> None:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        if not isinstance(cert.public_key(), RSAPublicKey):
            # If this is changed, the signature validation
            # in AppCrlRetriever and CertValidator must also be updated.
            raise ConfigurationError("Only CA certificates with RSA keys are supported")

        certs[cert.subject] = cert
        logger.debug(
            "Loaded trusted certificate '%s' from '%s'",
            cert.subject.rfc4514_string(),
            path,
        )

    @classmethod
    def _load_all_certs(cls, env: Environment) -> dict[x509.Name, x509.Certificate]:
        certs: dict[x509.Name, x509.Certificate] = {}
        for path in Path("certs", env.value).iterdir():
            if path.is_file():
                try:
                    cls._load_certificate(path, certs)
                except (OSError, ValueError):
                    logger.exception(
                        "Could not load '%s' as a trusted certificate", path
                    )
        logger.info(
            "Loaded %d trusted certificates from file for env %s", len(certs), env
        )
        return certs


@frozen
class CertValidator:
    _cert_retriever: CertRetriever
    _crl_retriever: RequestCrlRetrieverProto

    @property
    def errors(self) -> list[str]:
        return self._crl_retriever.errors

    async def validate_cert(
        self, cert: MaybeInvalidCertificate
    ) -> tuple[CertificateStatus, datetime | None]:
        status = CertificateStatus.UNKNOWN
        revocation_date = None

        issuer = self._cert_retriever.retrieve(cert.issuer)
        if issuer is None:  # noqa: SIM114
            # TODO: Should this be UNKNOWN? We don't
            # trust the issuer, but others might...
            status = CertificateStatus.INVALID
        elif not self._validate_cert_against_issuer(cert.cert, issuer):
            status = CertificateStatus.INVALID
        elif not self._check_date_on_cert(cert.cert):
            status = CertificateStatus.EXPIRED
        else:
            # This will mark certs without CDP as unknown.
            # This is technically wrong, but as we don't
            # support OCSP, and certs without any revocation
            # info should not occur in this eco system, it's
            # OK, me thinks.
            crl = await self._get_crl(cert, issuer)
            if crl is None:
                status = CertificateStatus.UNKNOWN
            else:
                revoked_cert = crl.get_revoked_certificate_by_serial_number(
                    cert.cert.serial_number
                )
                if revoked_cert is not None:
                    status = CertificateStatus.REVOKED
                    revocation_date = revoked_cert.revocation_date.replace(
                        tzinfo=timezone.utc
                    )
                else:
                    status = CertificateStatus.OK
        return status, revocation_date

    async def _get_crl(
        self, cert: MaybeInvalidCertificate, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList | None:
        """
        Will try to download a crl for the certificate from a HTTP endpoint, if any.
        """
        try:
            cdps = cert.cdp
        except x509.ExtensionNotFound:
            logger.warning(
                "Certificate without CDP extension: Subject: '%s' Issuer:'%s'",
                cert.subject.rfc4514_string() if cert.subject else "__INVALID__",
                cert.issuer.rfc4514_string(),
            )
            return None

        if not cdps:
            # cert with invalid extensions
            return None

        http_cdp = None
        cdp: x509.DistributionPoint
        for cdp in cdps:
            if cdp.full_name is not None:
                url = urllib.parse.urlparse(cdp.full_name[0].value)
                if url.scheme == "http":
                    http_cdp = cdp.full_name[0].value
                    break

        if http_cdp is None:
            return None

        return await self._crl_retriever.retrieve(http_cdp, issuer)

    @staticmethod
    def _check_date_on_cert(cert: x509.Certificate) -> bool:
        """Returns whether the certificate is valid wrt. the dates"""
        now = datetime.utcnow()  # noqa: DTZ003
        return cert.not_valid_after > now and cert.not_valid_before < now

    @staticmethod
    def _validate_cert_against_issuer(
        cert: x509.Certificate, issuer: x509.Certificate
    ) -> bool:
        """Validates a certificate against it's (alleged) issuer"""

        if cert.issuer != issuer.subject:
            return False
        try:
            # casts because mypy. The type of key is checked
            # when it is loaded in CertRetriever.
            cast(RSAPublicKey, issuer.public_key()).verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                cast(HashAlgorithm, cert.signature_hash_algorithm),
            )
        except InvalidSignature:
            return False
        return True
