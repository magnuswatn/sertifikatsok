import contextlib
import logging
import os
import urllib.parse
from datetime import datetime
from enum import Enum, auto
from functools import partial
from hashlib import sha256
from secrets import choice

import httpx
from attrs import frozen
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
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
from sertifikatsok.crypto import AppCrlRetriever, CertRetriever, CrlError
from sertifikatsok.db import Database
from sertifikatsok.enums import Environment
from sertifikatsok.errors import ClientError
from sertifikatsok.logging import performance_log
from sertifikatsok.utils import datetime_now_utc

logger = logging.getLogger(__name__)


class OcspErrorReason(Enum):
    SIGNATURE_INVALID = auto()
    MALFORMED = auto()

    INVALID_CONTENT_TYPE = auto()
    NETWORK_ERROR = auto()

    DELEGATED_SIGNER_CERT_NOT_INCLUDED = auto()
    DELEGED_RESPONDER_NOT_ISSUED_BY_ISSUER = auto()
    DELEGED_RESPONDER_CERT_INVALID_SIGNATURE = auto()
    DELEGED_RESPONDER_CERT_MISSING_EKU = auto()
    DELEGED_RESPONDER_CERT_MISSING_OCSP_EKU = auto()
    DELEGED_RESPONDER_UNSUPPORTED_KEY_TYPE = auto()
    RESP_MISMATCH_HASH_ALG = auto()
    RESP_MISMATCH_ISSUER_NAME = auto()
    RESP_MISMATCH_ISSUER_KEY_HASH = auto()
    RESP_MISMATCH_SERIAL_NUMBER = auto()
    RESP_MISMATCH_NONCE_MISSING = auto()
    RESP_MISMATCH_NONCE_MISMATCH = auto()


@frozen
class OcspHttpStatusError:
    http_status_code: int


@frozen
class OcspStatusError:
    ocsp_status: str


@frozen
class OcspNextUpdateInThePastError:
    next_update: datetime


@frozen
class OcspError(Exception):
    # Would it be nice with a Rust style Enum? Yes. Yes, it would.
    error_reason: (
        OcspErrorReason
        | OcspStatusError
        | OcspHttpStatusError
        | OcspNextUpdateInThePastError
    )
    message: str


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
    crl_number: int | None
    this_update: datetime
    next_update: datetime


@frozen
class RevocationInfoResponse:
    ocsp_result: OcspRevocationInfo | OcspError | None
    crl_result: CrlRevocationInfo | CrlError | None


def _get_key_hash(cert: x509.Certificate) -> bytes:
    hash = Hash(SHA1())  # noqa: S303
    hash.update(cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1))
    return hash.finalize()


def get_cdp_from_cert(cert: MaybeInvalidCertificate) -> str | None:
    # TODO: consolidate with the one in crypto.py somehow
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
    validate_ocsp_resp_against_request(ocsp_req, ocsp_resp)

    if ocsp_resp.responder_key_hash is not None:
        if ocsp_resp.responder_key_hash == _get_key_hash(issuer):
            # Directly signed by the issuing CA
            responder = issuer
            logger.info(
                "OCSPINFO: Directly issued OCSP response with responder_key_hash for CA %s",
                issuer.subject.rfc4514_string(),
            )
        else:
            # Delegated responder
            logger.info(
                "OCSPINFO: Delegated OCSP responder with responder_key_hash for CA %s",
                issuer.subject.rfc4514_string(),
            )
            for ocsp_resp_cert in ocsp_resp.certificates:
                if ocsp_resp.responder_key_hash == _get_key_hash(ocsp_resp_cert):
                    responder = ocsp_resp_cert
                    break
            else:
                cert_in_resp = ",".join(
                    [_get_key_hash(c).hex() for c in ocsp_resp.certificates]
                )
                raise OcspError(
                    OcspErrorReason.DELEGATED_SIGNER_CERT_NOT_INCLUDED,
                    "Did not find delegated responder "
                    f"{ocsp_resp.responder_key_hash.hex()} in the OCSP response. "
                    f"The response included: {cert_in_resp}",
                )

    elif ocsp_resp.responder_name is not None:
        if ocsp_resp.responder_name == issuer.subject:
            # Directly signed by the issuing CA
            responder = issuer
            logger.info(
                "OCSPINFO: Directly issued OCSP response with responder_name for CA %s",
                issuer.subject.rfc4514_string(),
            )
        else:
            # Delegated responder
            logger.info(
                "OCSPINFO: Delegated OCSP responder with responder_name for CA %s",
                issuer.subject.rfc4514_string(),
            )
            for ocsp_resp_cert in ocsp_resp.certificates:
                if ocsp_resp_cert.subject == ocsp_resp.responder_name:
                    responder = ocsp_resp_cert
                    break
            else:
                cert_in_resp = ",".join(
                    [c.subject.rfc4514_string() for c in ocsp_resp.certificates]
                )
                raise OcspError(
                    OcspErrorReason.DELEGATED_SIGNER_CERT_NOT_INCLUDED,
                    "Did not find delegated responder "
                    f"{ocsp_resp.responder_name.rfc4514_string()} in the OCSP response. "
                    f"The response included: {cert_in_resp}",
                )
    else:
        # Either `responder_key_hash` or `ocsp_resp.responder_name` should be set
        # as it's a CHOICE in the ASN.1 representation.
        raise AssertionError

    ocsp_issuer_pubkey = responder.public_key()
    match ocsp_issuer_pubkey:
        case RSAPublicKey():
            assert ocsp_resp.signature_hash_algorithm
            signature_verification = partial(
                ocsp_issuer_pubkey.verify,
                ocsp_resp.signature,
                ocsp_resp.tbs_response_bytes,
                PKCS1v15(),
                ocsp_resp.signature_hash_algorithm,
            )
        case EllipticCurvePublicKey():
            assert ocsp_resp.signature_hash_algorithm
            signature_verification = partial(
                ocsp_issuer_pubkey.verify,
                ocsp_resp.signature,
                ocsp_resp.tbs_response_bytes,
                ECDSA(ocsp_resp.signature_hash_algorithm),
            )
        case _:
            # As we only trust RSA keys, this must be a delegated responder,
            # but since we include that in the error message, an assert is in order.
            assert responder != issuer
            raise OcspError(
                OcspErrorReason.DELEGED_RESPONDER_UNSUPPORTED_KEY_TYPE,
                f"Responder has unsupported key type: {type(ocsp_issuer_pubkey)}",
            )

    try:
        signature_verification()
    except InvalidSignature as e:
        raise OcspError(
            OcspErrorReason.SIGNATURE_INVALID, "Signature on OCSP response was invalid"
        ) from e

    if responder != issuer:
        if responder.issuer != issuer.subject:
            raise OcspError(
                OcspErrorReason.DELEGED_RESPONDER_NOT_ISSUED_BY_ISSUER,
                f"Responder '{responder.subject.rfc4514_string()}' was issued by "
                f"'{responder.issuer.rfc4514_string()}', and not '{issuer.subject.rfc4514_string()}'",
            )

        try:
            responder.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature) as e:
            raise OcspError(
                OcspErrorReason.DELEGED_RESPONDER_CERT_INVALID_SIGNATURE,
                "Signature on delegated responder cert was invalid",
            ) from e

        try:
            ext_key_usage = responder.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            )
        except x509.ExtensionNotFound as e:
            raise OcspError(
                OcspErrorReason.DELEGED_RESPONDER_CERT_MISSING_EKU,
                "Delegated responder certificate does not have EKU",
            ) from e

        if not any(e == ExtendedKeyUsageOID.OCSP_SIGNING for e in ext_key_usage.value):
            raise OcspError(
                OcspErrorReason.DELEGED_RESPONDER_CERT_MISSING_OCSP_EKU,
                "Delegated responder certificate is missing the OCSP signing EKU",
            )

    if (
        ocsp_resp.next_update_utc is not None
        and ocsp_resp.next_update_utc < datetime_now_utc()
    ):
        raise OcspError(
            OcspNextUpdateInThePastError(ocsp_resp.next_update_utc),
            f"Next update in OCSP response is in the past: {ocsp_resp.next_update_utc}",
        )


def validate_ocsp_resp_against_request(
    ocsp_req: OCSPRequest, ocsp_resp: OCSPResponse
) -> None:
    if not isinstance(ocsp_resp.hash_algorithm, type(ocsp_req.hash_algorithm)):
        raise OcspError(
            OcspErrorReason.RESP_MISMATCH_HASH_ALG,
            "Hash algorithm mismatch between request and response",
        )

    if ocsp_resp.issuer_name_hash != ocsp_req.issuer_name_hash:
        raise OcspError(
            OcspErrorReason.RESP_MISMATCH_ISSUER_NAME,
            "Issuer name mismatch between request and response",
        )

    if ocsp_resp.issuer_key_hash != ocsp_req.issuer_key_hash:
        raise OcspError(
            OcspErrorReason.RESP_MISMATCH_ISSUER_KEY_HASH,
            "Issuer key hash mismatch between request and response",
        )

    if ocsp_resp.serial_number != ocsp_req.serial_number:
        raise OcspError(
            OcspErrorReason.RESP_MISMATCH_SERIAL_NUMBER,
            "Serial number mismatch between request and response",
        )

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
        except x509.ExtensionNotFound as e:
            raise OcspError(
                OcspErrorReason.RESP_MISMATCH_NONCE_MISSING,
                "OCSP response is missing nonce",
            ) from e

        if req_nonce_extension.value.nonce != resp_nonce_ext.value.nonce:
            raise OcspError(
                OcspErrorReason.RESP_MISMATCH_NONCE_MISMATCH,
                "Nonce in OCSP response doesn't match nonce in request",
            )


@performance_log(id_param=0)
async def do_ocsp_call(url: str, req: bytes) -> httpx.Response:
    try:
        async with httpx.AsyncClient() as httpx_client:
            # We do a POST here, instead of a GET, because
            # we want a fresh response, not something
            # old fetched from cache. (The nonce should
            # make sure of this, but still).
            resp = await httpx_client.post(
                url,
                content=req,
                headers={"Content-Type": "application/ocsp-request"},
            )
    except httpx.HTTPError as e:
        raise OcspError(OcspErrorReason.NETWORK_ERROR, "Network error") from e

    return resp


async def get_ocsp_status(
    cert: MaybeInvalidCertificate, issuer: x509.Certificate
) -> OcspRevocationInfo | None:
    assert cert.extensions is not None

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
        # Commfides G3 OCSP responder doesn't like nonces over 30 bytes,
        # so we have to limit ourselves to that, even though it goes against
        # RFC 8954.
        .add_extension(x509.OCSPNonce(os.urandom(30)), critical=False)
        .build()
    )

    chosen_ocsp_endpoint = choice(ocsp_endpoints)

    resp = await do_ocsp_call(chosen_ocsp_endpoint, ocsp_req.public_bytes(Encoding.DER))

    if (ct := resp.headers.get("Content-Type")) != "application/ocsp-response":
        if resp.is_error:
            # Invalid Content-Type, but since the HTTP status code didn't indicate
            # success, let's just throw that error instead, since it's most likely
            # the more interesting one.
            raise OcspError(
                OcspHttpStatusError(http_status_code=resp.status_code),
                "Unexpected HTTP status code from OCSP responder",
            )

        raise OcspError(
            OcspErrorReason.INVALID_CONTENT_TYPE,
            f"Got unexpected content type from OCSP responder: {ct}",
        )

    try:
        ocsp_resp = load_der_ocsp_response(resp.content)
    except ValueError as e:
        raise OcspError(OcspErrorReason.MALFORMED, "Malformed OCSP response") from e

    if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise OcspError(
            OcspStatusError(ocsp_resp.response_status.name),
            "Invalid status in OCSP response",
        )

    if resp.is_error:
        # We got served an OCSP response with SUCCESS status with an non-successfull
        # HTTP status code? That's no good
        raise OcspError(
            OcspHttpStatusError(resp.status_code),
            "Successfull OCSP response served with non-OK status code",
        )

    # TODO: handle with several responses
    validate_successfull_ocsp_response(ocsp_req, ocsp_resp, issuer)

    return OcspRevocationInfo(
        status=ocsp_resp.certificate_status.name,
        revoked_at=ocsp_resp.revocation_time_utc,
        reason=(
            ocsp_resp.revocation_reason.value if ocsp_resp.revocation_reason else None
        ),
        produced_at=ocsp_resp.produced_at_utc,
        this_update=ocsp_resp.this_update_utc,
        next_update=ocsp_resp.next_update_utc,
    )


async def get_crl_status(
    crl_retriever: AppCrlRetriever,
    cert: MaybeInvalidCertificate,
    issuer: x509.Certificate,
) -> CrlRevocationInfo | None:
    cdp = get_cdp_from_cert(cert)
    if cdp is None:
        return None

    crl = await crl_retriever.retrieve(cdp, issuer)

    # Checked as part of the validation, so safe to assume
    assert crl.next_update_utc

    crl_number = None
    with contextlib.suppress(x509.ExtensionNotFound):
        crl_number = crl.extensions.get_extension_for_class(
            x509.CRLNumber
        ).value.crl_number

    revoked_cert: x509.RevokedCertificate | None
    revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.cert.serial_number)  # type:ignore

    if revoked_cert is None:
        return CrlRevocationInfo(
            revoked_at=None,
            reason=None,
            crl_number=crl_number,
            this_update=crl.last_update_utc,
            next_update=crl.next_update_utc,
        )

    crl_reason = None
    with contextlib.suppress(x509.ExtensionNotFound):
        crl_reason = revoked_cert.extensions.get_extension_for_class(
            x509.CRLReason
        ).value.reason.value

    return CrlRevocationInfo(
        revoked_at=revoked_cert.revocation_date_utc,
        reason=crl_reason,
        crl_number=crl_number,
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
    )


async def get_revocation_info(
    raw_cert: bytes,
    env: Environment,
    cert_retriever: CertRetriever,
    crl_retriever: AppCrlRetriever,
    database: Database,
) -> tuple[RevocationInfoResponse, str]:
    # If this is a legit request, we should have the cert in our local db
    thumbprint = sha256(raw_cert).hexdigest()
    if not database.find_cert_from_sha2(thumbprint, env):
        raise ClientError("Cert not found")

    try:
        cert = MaybeInvalidCertificate.create(raw_cert)
    except ValueError as e:
        raise ClientError("Invalid cert") from e

    if cert.extensions is None:
        # Should not have made it here "the normal" way, as the
        # button should be disabled for such certs in the GUI.
        raise ClientError("Invalid extensions in cert")

    issuer = cert_retriever.retrieve(cert.issuer)
    if issuer is None:
        # Should not have made it here "the normal" way, as the
        # button should be disabled for such certs in the GUI.
        raise ClientError("Non-trusted cert")

    ocsp_status: OcspRevocationInfo | OcspError | None
    try:
        ocsp_status = await get_ocsp_status(cert, issuer)
    except OcspError as e:
        logger.exception(
            "Failure during OCSP checking of cert %s from %s",
            cert.subject.rfc4514_string() if cert.subject is not None else "UNKNOWN",
            issuer.subject.rfc4514_string(),
        )
        ocsp_status = e

    crl_status: CrlRevocationInfo | CrlError | None
    try:
        crl_status = await get_crl_status(crl_retriever, cert, issuer)
    except CrlError as e:
        logger.exception(
            "Failure during CRL checking of cert %s from %s",
            cert.subject.rfc4514_string() if cert.subject is not None else "UNKNOWN",
            issuer.subject.rfc4514_string(),
        )
        crl_status = e

    return RevocationInfoResponse(
        ocsp_result=ocsp_status, crl_result=crl_status
    ), thumbprint
