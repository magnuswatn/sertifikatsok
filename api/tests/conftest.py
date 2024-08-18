import pytest

from sertifikatsok.cert import MaybeInvalidCertificate
from tests.testlib import CertificateAuthority


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.create("sertifikatsok.no CA")


@pytest.fixture(scope="module")
def ee_cert(ca: CertificateAuthority) -> MaybeInvalidCertificate:
    return ca.generate_ee_cert("sertifikatsok.no")
