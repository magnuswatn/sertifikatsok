import pytest

from sertifikatsok.cert import MaybeInvalidCertificate

from .testlib import read_pem_file


def test_cert_with_invalid_subject() -> None:
    raw_cert = read_pem_file("tests/resources/cert_with_invalid_subject.pem")
    cert = MaybeInvalidCertificate.create(raw_cert)
    assert cert.invalid
    assert cert.subject is None
    assert cert.extensions is not None


def test_cert_with_invalid_extensions() -> None:
    raw_cert = read_pem_file("tests/resources/cert_with_invalid_extensions.pem")
    cert = MaybeInvalidCertificate.create(raw_cert)
    assert cert.invalid
    assert cert.subject is not None
    assert cert.extensions is None


def test_cert_with_invalid_subject_and_extensions() -> None:
    raw_cert = read_pem_file(
        "tests/resources/cert_with_invalid_subject_and_extensions.pem"
    )
    cert = MaybeInvalidCertificate.create(raw_cert)
    assert cert.invalid
    assert cert.subject is None
    assert cert.extensions is None


def test_cert_with_invalid_issuer() -> None:
    raw_cert = read_pem_file("tests/resources/cert_with_invalid_issuer.pem")
    # We do not expect this, so it should fail
    with pytest.raises(ValueError):  # noqa
        MaybeInvalidCertificate.create(raw_cert)
