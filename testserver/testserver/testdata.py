from datetime import UTC, datetime

from testserver import ClonedCa, Enterprise, Person
from testserver.ca import (
    CertificateAuthority,
)

BUSINESS_CA_S = [
    ClonedCa.BUYPASS_CLASS_3_CA_G2_STBS,
    ClonedCa.BUYPASS_CLASS_3_CA_1,
    ClonedCa.BUYPASS_CLASS_3_CA_3,
    ClonedCa.COMMFIDES_ENTERPRISE,
    ClonedCa.COMMFIDES_LEGAL_PERSON_CA_G3,
]

PERSON_CA_S = [
    ClonedCa.BUYPASS_CLASS_3_CA_1,
    ClonedCa.BUYPASS_CLASS_3_CA_3,
    ClonedCa.BUYPASS_CLASS_3_CA_G2_HTPS,
    ClonedCa.COMMFIDES_PERSON_HIGH,
    ClonedCa.COMMFIDES_NATURAL_PERSON_CA_G3,
]


def generate_testdata(loaded_ca_s: dict[ClonedCa, CertificateAuthority]) -> None:
    silje = Person("Silje Fos", "Port", "9578-4050-100105758", "silje@example.com")

    for ca in PERSON_CA_S:
        iss_impl = loaded_ca_s[ca].impl
        iss_impl.issue_person_certs(silje, datetime.now(UTC))

    min_virksomhet = Enterprise("123456789", "Min virksomhet")

    for ca in BUSINESS_CA_S:
        iss_impl = loaded_ca_s[ca].impl

        iss_impl.issue_enterprise_certs(
            min_virksomhet,
            datetime.now(UTC),
            ou="Min tjeneste",
        )
