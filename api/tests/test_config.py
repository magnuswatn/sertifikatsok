from sertifikatsok.constants import KNOWN_CERT_TYPES, SUBJECT_FIELDS
from sertifikatsok.crypto import CertRetriever
from sertifikatsok.enums import Environment


def test_known_cert_types_subject_matches_trusted_cert() -> None:
    cert_retrievers = [
        CertRetriever.create(Environment.TEST),
        CertRetriever.create(Environment.PROD),
    ]
    all_trusted_subjects = [
        subject.rfc4514_string(SUBJECT_FIELDS)
        for cert_retriever in cert_retrievers
        for subject in cert_retriever.certs
    ]
    for name, _ in KNOWN_CERT_TYPES:
        assert name in all_trusted_subjects
