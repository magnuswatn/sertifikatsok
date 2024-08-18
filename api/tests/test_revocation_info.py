from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
)

from sertifikatsok.cert import MaybeInvalidCertificate
from sertifikatsok.revocation_info import validate_successfull_ocsp_response
from sertifikatsok.utils import datetime_now_utc
from tests.test_crypto import CertificateAuthority


def test_validate_successfull_ocsp_response_mismatch_between_signature_alg_and_hash_alg(
    ca: CertificateAuthority, ee_cert: MaybeInvalidCertificate
) -> None:
    """
    We should use the `.signature_hash_algorithm` property to get the hash alg for the signature,
    and not mix in the one used to generate the key hash for the cert.
    """
    ocsp_req = (
        OCSPRequestBuilder().add_certificate(ee_cert.cert, ca.cert, SHA1()).build()  # noqa: S303
    )
    ocsp_resp = (
        OCSPResponseBuilder()
        .add_response(
            cert=ee_cert.cert,
            issuer=ca.cert,
            algorithm=SHA1(),  # noqa: S303
            cert_status=OCSPCertStatus.GOOD,
            this_update=datetime_now_utc(),
            next_update=None,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            OCSPResponderEncoding.NAME,
            ca.cert,
        )
    ).sign(ca.key, SHA256())
    validate_successfull_ocsp_response(ocsp_req, ocsp_resp, ca.cert)
