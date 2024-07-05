import contextlib
import logging
import os
import urllib.parse
from base64 import b64decode
from datetime import UTC, datetime
from secrets import choice
from typing import Literal

import httpx
from attrs import frozen
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, Hash
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.ocsp import (
    OCSPRequest,
    OCSPRequestBuilder,
    OCSPResponse,
    OCSPResponseStatus,
    load_der_ocsp_response,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from sertifikatsok.cert import MaybeInvalidCertificate
from sertifikatsok.crypto import (
    AppCrlRetriever,
    CertRetriever,
)
from sertifikatsok.db import Database
from sertifikatsok.errors import ClientError, CouldNotGetValidCRLError
from sertifikatsok.utils import datetime_now_utc

logger = logging.getLogger(__name__)


@frozen
class BaseCrlError(Exception):
    pass


@frozen
class BaseOcspError(Exception):
    pass


@frozen
class OcspVerificationError(BaseOcspError):
    reason: str


@frozen
class OcspNetworkError(BaseOcspError):
    type: Literal["network_error"]


@frozen
class OcspHttpError(BaseOcspError):
    http_status_code: int


@frozen
class OcspStatusError(BaseOcspError):
    ocsp_status: str


@frozen
class OcspFailure:
    error: BaseOcspError


@frozen
class OcspRevocationInfo:
    status: str
    revoked_at: datetime | None
    reason: str | None
    produced_at: datetime
    this_update: datetime
    next_update: datetime | None


@frozen
class CrlRevocationInfo:
    revoked_at: datetime | None
    reason: str | None
    this_update: datetime
    next_update: datetime


@frozen
class CrlFailure:
    error: bool = True


@frozen
class RevocationInfoResponse:
    ocsp_result: OcspRevocationInfo | OcspFailure | None
    crl_result: CrlRevocationInfo | CrlFailure | None

    @property
    def cacheable(self) -> bool:
        return not (
            isinstance(self.crl_result, CrlFailure)
            or isinstance(self.ocsp_result, OcspFailure)
        )


def _get_key_hash(cert: x509.Certificate) -> bytes:
    hash = Hash(SHA1())  # noqa: S303
    hash.update(cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1))
    return hash.finalize()


def get_cdp_from_cert(cert: MaybeInvalidCertificate) -> str | None:
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

    cdp: x509.DistributionPoint
    for cdp in cdps:
        if cdp.full_name is not None:
            url = urllib.parse.urlparse(cdp.full_name[0].value)
            if url.scheme == "http":
                return cdp.full_name[0].value

    return None


def validate_successfull_ocsp_response(
    ocsp_req: OCSPRequest, ocsp_resp: OCSPResponse, issuer: x509.Certificate
) -> None:
    assert validate_ocsp_resp_against_request(ocsp_req, ocsp_resp)

    responder = None
    if ocsp_resp.responder_key_hash is not None:
        if ocsp_resp.responder_key_hash == _get_key_hash(issuer):
            # Directly signed by the issuing CA
            responder = issuer
        else:
            # Using a delegated responder
            for ocsp_resp_cert in ocsp_resp.certificates:
                if ocsp_resp.responder_key_hash == _get_key_hash(ocsp_resp_cert):
                    responder = ocsp_resp_cert
                    break
            else:
                raise OcspVerificationError(
                    "OCSP response was signed by a delegated responder, but the "
                    "delegated responder certificate was not included in the response"
                )

    elif ocsp_resp.responder_name is not None:
        if ocsp_resp.responder_name == issuer.subject:
            # Directly signed by the issuing CA
            responder = issuer
        else:
            # Using a delegated responder
            for ocsp_resp_cert in ocsp_resp.certificates:
                if ocsp_resp_cert.subject == ocsp_resp.responder_name:
                    responder = ocsp_resp_cert
                    break
            else:
                raise OcspVerificationError(
                    "OCSP response was signed by a delegated responder, but the "
                    "delegated responder certificate was not included in the response"
                )

    # Either `responder_key_hash` or `ocsp_resp.responder_name` should be set
    # as it's a CHOICE in the ASN.1 representation
    assert responder is not None

    ocsp_issuer_pubkey = responder.public_key()
    # TODO: Support ECDSA
    assert isinstance(ocsp_issuer_pubkey, RSAPublicKey)
    try:
        ocsp_issuer_pubkey.verify(
            ocsp_resp.signature,
            ocsp_resp.tbs_response_bytes,
            PKCS1v15(),
            ocsp_resp.hash_algorithm,
        )
    except InvalidSignature as e:
        raise OcspVerificationError("Signature on OCSP response was invalid") from e

    if responder != issuer:
        if responder.issuer != issuer.subject:
            raise OcspVerificationError(
                f"Expected the delegated signer certificate to be issueed by the "
                f"certificate issuer, but it was not. It was signed by: "
                f"{responder.issuer.rfc4514_string()}"
            )

        try:
            responder.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature) as e:
            raise OcspVerificationError(
                "Signature on delegated responder cert was invalid"
            ) from e

        try:
            ext_key_usage = responder.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            )
        except x509.ExtensionNotFound as e:
            raise OcspVerificationError(
                "Delegated responder certificate does not have EKU"
            ) from e

        if not any(e == ExtendedKeyUsageOID.OCSP_SIGNING for e in ext_key_usage.value):
            raise OcspVerificationError(
                "Delegated responder certificate is missing the OCSP signing EKU"
            )

    if (
        ocsp_resp.next_update is not None
        # TODO: replace with `next_update_utc` when available
        and ocsp_resp.next_update.replace(tzinfo=UTC) < datetime_now_utc()
    ):
        raise OcspVerificationError("Next update in OCSP response is in the past")


def validate_ocsp_resp_against_request(
    ocsp_req: OCSPRequest, ocsp_resp: OCSPResponse
) -> bool:
    if not isinstance(ocsp_resp.hash_algorithm, type(ocsp_req.hash_algorithm)):
        raise OcspVerificationError("Hash alg mismatch")

    if ocsp_resp.issuer_name_hash != ocsp_req.issuer_name_hash:
        raise OcspVerificationError("Issuer name mismatch")

    if ocsp_resp.issuer_key_hash != ocsp_req.issuer_key_hash:
        raise OcspVerificationError("Issuer key hash mismatch")

    if ocsp_resp.serial_number != ocsp_req.serial_number:
        raise OcspVerificationError("Serial number mismatch")

    req_nonce_extension = None
    with contextlib.suppress(x509.ExtensionNotFound):
        req_nonce_extension = ocsp_req.extensions.get_extension_for_class(
            x509.OCSPNonce
        )

    if req_nonce_extension is not None:
        try:
            resp_nonce_ext = ocsp_resp.extensions.get_extension_for_class(
                x509.OCSPNonce
            )
        except x509.ExtensionNotFound:
            return False

        if req_nonce_extension.value.nonce != resp_nonce_ext.value.nonce:
            return False

    return True


async def get_ocsp_status(
    cert: MaybeInvalidCertificate, issuer: x509.Certificate
) -> OcspRevocationInfo | None:
    if cert.extensions is None:
        # Invalid cert
        return None

    try:
        aia_ext = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
    except x509.ExtensionNotFound:
        return None

    ocsp_endpoints = []

    access_description: x509.AccessDescription
    for access_description in aia_ext.value:
        if access_description.access_method != AuthorityInformationAccessOID.OCSP:
            continue
        assert isinstance(
            access_description.access_location, x509.UniformResourceIdentifier
        )
        ocsp_endpoints.append(access_description.access_location.value)

    if not ocsp_endpoints:
        return None

    ocsp_req = (
        OCSPRequestBuilder()
        .add_certificate(cert.cert, issuer, SHA256())
        .add_extension(x509.OCSPNonce(os.urandom(32)), critical=False)
        .build()
    )

    chosen_ocsp_endpoint = choice(ocsp_endpoints)
    try:
        async with httpx.AsyncClient() as httpx_client:
            # We do a POST here, instead of a GET, because
            # we want a fresh response, not something
            # old fetched from cache. (The nonce should
            # make sure of this, but still).
            resp = await httpx_client.post(
                chosen_ocsp_endpoint,
                content=ocsp_req.public_bytes(Encoding.DER),
                headers={"Content-Type": "application/ocsp-request"},
            )
    except httpx.HTTPError as e:
        raise OcspNetworkError("network_error") from e

    if resp.is_error:
        raise OcspHttpError(http_status_code=resp.status_code)

    try:
        ocsp_resp = load_der_ocsp_response(resp.content)
    except ValueError as e:
        raise OcspVerificationError("Malformed OCSP response") from e

    if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise OcspStatusError(ocsp_resp.response_status.name)

    validate_successfull_ocsp_response(ocsp_req, ocsp_resp, issuer)

    return OcspRevocationInfo(
        status=ocsp_resp.certificate_status.name,
        revoked_at=ocsp_resp.revocation_time,
        reason=(
            ocsp_resp.revocation_reason.value if ocsp_resp.revocation_reason else None
        ),
        produced_at=ocsp_resp.produced_at,
        this_update=ocsp_resp.this_update,
        next_update=ocsp_resp.next_update,
    )


async def get_crl_status(
    crl_retriever: AppCrlRetriever,
    cert: MaybeInvalidCertificate,
    issuer: x509.Certificate,
) -> CrlRevocationInfo | CrlFailure | None:
    cdp = get_cdp_from_cert(cert)
    if cdp is None:
        return None

    try:
        crl = await crl_retriever.retrieve(cdp, issuer)
    except CouldNotGetValidCRLError:
        return CrlFailure()

    if crl is None:
        return CrlFailure()

    revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.cert.serial_number)
    assert crl.next_update_utc

    crl_reason = None
    if revoked_cert is None:
        return CrlRevocationInfo(
            revoked_at=None,
            reason=None,
            this_update=crl.last_update_utc,
            next_update=crl.next_update_utc,
        )

    with contextlib.suppress(x509.ExtensionNotFound):
        crl_reason = revoked_cert.extensions.get_extension_for_class(
            x509.CRLReason
        ).value.reason.value

    return CrlRevocationInfo(
        revoked_at=revoked_cert.revocation_date,
        reason=crl_reason,
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
    )


async def get_revocation_info(
    raw_cert: str,
    cert_retriever: CertRetriever,
    crl_retriever: AppCrlRetriever,
    database: Database,
) -> RevocationInfoResponse:
    try:
        cert = MaybeInvalidCertificate.create(b64decode(raw_cert))
    except ValueError as e:
        raise ClientError("Invalid cert") from e

    # TODO: validate against database?
    issuer = cert_retriever.retrieve(cert.issuer)
    if issuer is None:
        raise ClientError("Non-trusted cert")

    try:
        ocsp_status = await get_ocsp_status(cert, issuer)
    except BaseOcspError as e:
        logger.exception("Failure during OCSP checking")
        ocsp_status = OcspFailure(error=e)

    try:
        crl_status = await get_crl_status(crl_retriever, cert, issuer)
    except BaseCrlError:
        logger.exception("Failure during CRL checking")
        crl_status = CrlFailure()

    return RevocationInfoResponse(ocsp_result=ocsp_status, crl_result=crl_status)
