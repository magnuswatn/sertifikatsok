import environ
import pytest

from sertifikatsok.cert import MaybeInvalidCertificate
from sertifikatsok.config import AppConfig
from tests.testlib import CertificateAuthority


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.create("sertifikatsok.no CA")


@pytest.fixture(scope="module")
def ee_cert(ca: CertificateAuthority) -> MaybeInvalidCertificate:
    return ca.generate_ee_cert("sertifikatsok.no")


@pytest.fixture(scope="module")
def config_dict() -> dict:
    return {}  # use all default for now


@pytest.fixture(scope="module")
def config(config_dict: dict) -> AppConfig:
    return environ.to_config(AppConfig, config_dict)
