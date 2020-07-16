import asyncio
import logging
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, cast

import attr
import aiohttp

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature

from .errors import CouldNotGetValidCRLError, ConfigurationError
from .enums import Environment
from .utils import stringify_x509_name
from .logging import performance_log

logger = logging.getLogger(__name__)


@attr.s(frozen=True, slots=True)
class AppCrlRetriever:
    """
    CRL retriever for an app instance.

    Retrieves CRLs and caches them in the file system and in memory.

    Only returns valid CRLs.
    """

    crls: Dict[str, x509.CertificateRevocationList] = attr.ib(factory=dict)

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

    def get_retriever_for_request(self):
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
            raise CouldNotGetValidCRLError("Not in AppCrlRetriever memory cache")

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
            raise CouldNotGetValidCRLError("Not found on disk")

        try:
            crl = x509.load_der_x509_crl(crl_bytes, default_backend())
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
        headers = {"user-agent": "sertifikatsok.no"}
        crl_timeout = aiohttp.ClientTimeout(total=5)

        logger.info("Downloading CRL %s", url)
        async with aiohttp.ClientSession(timeout=crl_timeout) as session:
            try:
                resp = await session.get(url, headers=headers)
                crl_bytes = await resp.read()
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                raise CouldNotGetValidCRLError() from error

        logger.debug("Finishined downloading CRL %s", url)

        if resp.status != 200:
            raise CouldNotGetValidCRLError(
                f"Got status code {resp.status} for url {url}"
            )

        if resp.headers["Content-Type"] not in (
            "application/pkix-crl",
            "application/x-pkcs7-crl",
        ):
            raise CouldNotGetValidCRLError(
                f"Got content type: {resp.headers['Content-Type']} for url {url}"
            )

        try:
            crl = x509.load_der_x509_crl(crl_bytes, default_backend())
        except ValueError as error:
            raise CouldNotGetValidCRLError(error) from error

        self._validate(crl, issuer)

        Path("crls", urllib.parse.quote_plus(url)).write_bytes(crl_bytes)

        return crl

    @staticmethod
    def _validate(crl: x509.CertificateRevocationList, issuer: x509.Certificate):
        """Validates a crl against a issuer certificate"""

        if not (
            crl.next_update > datetime.utcnow() and crl.last_update < datetime.utcnow()
        ):
            raise CouldNotGetValidCRLError(
                f"CRL failed date validation. "
                f"Last update: '{crl.last_update}' Next Update: '{crl.next_update}'"
            )

        if not crl.issuer == issuer.subject:
            raise CouldNotGetValidCRLError(
                f"CRL failed issuer validation. "
                f"Expected: {stringify_x509_name(issuer.subject)} "
                f"Actual: {stringify_x509_name(crl.issuer)}."
            )

        try:
            # cast because mypy. The type of key is checked
            # when it is loaded in CertRetriever.
            cast(RSAPublicKey, issuer.public_key()).verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        except InvalidSignature as error:
            raise CouldNotGetValidCRLError("CRL failed signature validation") from error


@attr.s(frozen=True, slots=True)
class RequestCrlRetriever:
    """
    CRL retriever for a single request.

    Cached CRLs are returned without validation,
    so objects should not be long-lived.
    """

    crl_retriever = attr.ib()
    crls: Dict[str, x509.CertificateRevocationList] = attr.ib(factory=dict)
    errors: List[str] = attr.ib(factory=list)

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves the CRL from the specified url."""
        try:
            return self.crls[url]
        except KeyError:
            pass

        logger.debug(
            "CRL %s not in RequestCrlRetriever cache. Retrieving from AppCrlRetriever",
            url,
        )

        try:
            crl = await self.crl_retriever.retrieve(url, issuer)
        except CouldNotGetValidCRLError:
            logger.exception("Could not retrieve CRL %s", url)
            self.errors.append("ERR-003")
            crl = None

        self.crls[url] = crl
        return crl


@attr.s(frozen=True, slots=True)
class CertRetriever:
    env: Environment = attr.ib()
    certs: Dict[x509.Name, x509.Certificate] = attr.ib()

    @classmethod
    def create(cls, env: Environment):
        return cls(env, cls._load_all_certs(env))

    def retrieve(self, name: x509.Name) -> Optional[x509.Certificate]:
        """
        Retrieves the CA certificate with the specified name
        """
        try:
            return self.certs[name]
        except KeyError:
            return None

    @staticmethod
    def _load_certificate(path: Path, certs: Dict[x509.Name, x509.Certificate]):
        cert = x509.load_pem_x509_certificate(path.read_bytes(), default_backend())
        if not isinstance(cert.public_key(), RSAPublicKey):
            # If this is changed, the signature validation
            # in AppCrlRetriever and QualifiedCertificate must also be updated.
            raise ConfigurationError("Only CA certificates with RSA keys are supported")

        certs[cert.subject] = cert
        logger.debug(
            "Loaded trusted certificate '%s' from '%s'",
            stringify_x509_name(cert.subject),
            path,
        )

    @classmethod
    def _load_all_certs(cls, env: Environment):
        certs: Dict[x509.Name, x509.Certificate] = {}
        for path in Path("certs", env.value).iterdir():
            if path.is_file():
                try:
                    cls._load_certificate(path, certs)
                except (IOError, ValueError):
                    logger.exception(
                        "Could not load '%s' as a trusted certificate", path
                    )
        logger.info(
            "Loaded %d trusted certificates from file for env %s", len(certs), env
        )
        return certs
