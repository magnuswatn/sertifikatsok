import asyncio
import logging
import urllib.parse
from datetime import datetime
from typing import Dict

import aiohttp

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

from .errors import CouldNotGetValidCRLError

logger = logging.getLogger(__name__)


class CrlRetriever:
    """Represents a Certificate Revocation List"""

    def __init__(self) -> None:
        self.crls: Dict[str, x509.CertificateRevocationList] = {}
        self.errors = []

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """
        Retrieves the CRL from the specified url

        The retrieved CRLs are cached on the object.
        """
        try:
            return self.crls[url]
        except KeyError:
            try:
                crl = self._get_from_file(url, issuer)
            except CouldNotGetValidCRLError:
                try:
                    crl = await self._download(url, issuer)
                except CouldNotGetValidCRLError:
                    logger.exception("Could not download CRL %s", url)
                    self.errors.append(
                        f"Kunne ikke hente ned CRL fra {url}. "
                        f"Revokeringsstatus er derfor ukjent for noen sertifikater."
                    )
                    crl = None

            self.crls[url] = crl
            return crl

    def _get_from_file(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList:
        """Retrieves a CRl from disk"""
        filename = "./crls/{}".format(urllib.parse.quote_plus(url))
        try:
            with open(filename, "rb") as open_file:
                crl_bytes = open_file.read()
        except FileNotFoundError:
            raise CouldNotGetValidCRLError

        crl = x509.load_der_x509_crl(crl_bytes, default_backend())

        if not self._validate(crl, issuer):
            raise CouldNotGetValidCRLError
        return crl

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
                raise CouldNotGetValidCRLError(f"Could not retrieve CRL: {error}")

        logger.debug("Finishined downloading CRL %s", url)

        if resp.status != 200:
            raise CouldNotGetValidCRLError(
                f"Got status code {resp.status_code} for url {url}"
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
            raise CouldNotGetValidCRLError

        filename = f"./crls/{urllib.parse.quote_plus(url)}"
        with open(filename, "wb") as open_file:
            open_file.write(crl_bytes)

        return crl

    @staticmethod
    def _validate(
        crl: x509.CertificateRevocationList, issuer: x509.Certificate
    ) -> bool:
        """Validates a crl against a issuer certificate"""

        if not (
            crl.next_update > datetime.utcnow() and crl.last_update < datetime.utcnow()
        ):
            return False
        if not crl.issuer == issuer.subject:
            return False
        try:
            issuer.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False
        return True


class CertRetriever:
    def __init__(self, env: str) -> None:
        self.env = env
        self.certs: Dict[str, x509.Certificate] = {}

    def retrieve(self, name: str) -> x509.Certificate:
        """
        Retrieves the CA certificates with the specified nam

        The retrieved certs are cached on the object.
        """
        try:
            return self.certs[name]
        except KeyError:
            cert = self._get_cert_from_disk(name)
            if cert:
                self.certs[name] = cert
            return cert

    def _get_cert_from_disk(self, name) -> x509.Certificate:
        """Retrieves the certificate from file, if we have it"""
        filename = f"./certs/{self.env}/{urllib.parse.quote_plus(name)}.pem"
        try:
            with open(filename, "rb") as open_file:
                cert_bytes = open_file.read()
        except FileNotFoundError:
            logger.warning("Could not find cert %s on disk", name)
            return None
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())
