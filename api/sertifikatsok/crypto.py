import asyncio
import logging
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List

import aiohttp

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

from .errors import CouldNotGetValidCRLError
from .utils import stringify_x509_name
from .logging import performance_log

logger = logging.getLogger(__name__)


class AppCrlRetriever:
    """
    CRL retriever for an app instance.

    Retrieves CRLs and caches them in the file system and in memory.

    Only returns valid CRLs.
    """

    def __init__(self) -> None:
        self.crls: Dict[str, x509.CertificateRevocationList] = {}

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves the CRL from the specified url"""
        try:
            return self._get_cached_crl(url, issuer)
        except CouldNotGetValidCRLError:
            try:
                crl = self._get_from_file(url, issuer)
            except CouldNotGetValidCRLError:
                crl = await self._download(url, issuer)

            self.crls[url] = crl
            return crl

    def get_retriever_for_request(self):
        """
        Returns a retriever suitable for a single request,
        based on this retriever
        """
        return RequestCrlRetriever(self)

    def _get_cached_crl(self, url: str, issuer: str) -> x509.CertificateRevocationList:
        """Returnes CRL from memory"""
        try:
            crl = self.crls[url]
        except KeyError:
            logger.debug("CRL %s not found in AppCrlRetriever memory cache", url)
            raise CouldNotGetValidCRLError()

        if not self._validate(crl, issuer):
            logger.debug(
                "CRL %s from AppCrlRetriever memory cache not longer valid", url
            )
            raise CouldNotGetValidCRLError()

        logger.debug("Returning CRL for %s from memory", url)
        return crl

    def _get_from_file(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves a CRL from disk"""
        try:
            crl_bytes = Path("crls", urllib.parse.quote_plus(url)).read_bytes()
        except FileNotFoundError:
            logger.debug("CRL for %s not found on disk", url)
            raise CouldNotGetValidCRLError()

        crl = x509.load_der_x509_crl(crl_bytes, default_backend())

        if not self._validate(crl, issuer):
            logger.debug("CRL for %s from disk is no longer valid", url)
            raise CouldNotGetValidCRLError()

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

        crl = x509.load_der_x509_crl(crl_bytes, default_backend())

        if not self._validate(crl, issuer):
            raise CouldNotGetValidCRLError()

        Path("crls", urllib.parse.quote_plus(url)).write_bytes(crl_bytes)

        return crl

    @staticmethod
    def _validate(
        crl: x509.CertificateRevocationList, issuer: x509.Certificate
    ) -> bool:
        """Validates a crl against a issuer certificate"""

        if not (
            crl.next_update > datetime.utcnow() and crl.last_update < datetime.utcnow()
        ):
            logger.debug("CRL failed date validation")
            return False

        if not crl.issuer == issuer.subject:
            logger.debug("CRL failed issuer validation")
            return False

        try:
            issuer.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        except InvalidSignature:
            logger.debug("CRL failed signature validation")
            return False

        return True


class RequestCrlRetriever:
    """
    CRL retriever for a single request.

    Cached CRLs are returned without validation,
    so objects should not be long-lived.
    """

    def __init__(self, crl_retriever: AppCrlRetriever):
        self.crls: Dict[str, x509.CertificateRevocationList] = {}
        self.crl_retriever = crl_retriever
        self.errors: List[str] = []

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


class CertRetriever:
    def __init__(self, env: str) -> None:
        self.certs: Dict[str, x509.Certificate] = {}
        self._load_all_certs(env)

    def retrieve(self, name: str) -> x509.Certificate:
        """
        Retrieves the CA certificate with the specified name
        """
        try:
            return self.certs[name]
        except KeyError:
            return None

    def _load_certificate(self, path: Path):
        cert = x509.load_pem_x509_certificate(path.read_bytes(), default_backend())
        cert_name = stringify_x509_name(cert.subject)
        self.certs[cert_name] = cert
        logger.debug("Loaded trusted certificate %s from %s", cert_name, path)

    def _load_all_certs(self, env: str):
        count = 0
        for path in Path("certs", env).iterdir():
            if path.is_file():
                try:
                    self._load_certificate(path)
                except (IOError, ValueError):
                    logger.exception(
                        "Could not load '%s' as a trusted certificate", path
                    )
                else:
                    count += 1
        logger.info("Loaded %d trusted certificates from file for env %s", count, env)
