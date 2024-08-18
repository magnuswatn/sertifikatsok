from __future__ import annotations

from datetime import timedelta
from enum import Enum, auto
from typing import Literal

from attrs import field, frozen
from yarl import URL

Env = Literal["test", "prod"]


class LdapOU(str, Enum):
    AUTH = "Encryption"
    SIGN = "Signature"
    CRYPT = "Authentication"


@frozen
class Person:
    given_name: str
    family_name: str
    buypass_id: str
    email: str

    @property
    def full_name(self) -> str:
        return f"{self.given_name} {self.family_name}"


class OcspType(Enum):
    DELEGATED_RESPONDER_KEY_HASH = auto()
    DELEGATED_RESPONDER_NAME = auto()
    DIRECT_RESPONDER_NAME = auto()

    @property
    def is_delegated_responder(self) -> bool:
        return self in (
            OcspType.DELEGATED_RESPONDER_KEY_HASH,
            OcspType.DELEGATED_RESPONDER_NAME,
        )

    @property
    def is_key_hash(self) -> bool:
        return self is OcspType.DELEGATED_RESPONDER_KEY_HASH


@frozen
class Enterprise:
    org_nr: str
    name: str
    parent: Enterprise | None = field(default=None)


@frozen
class ClonedCaEnvConfig:
    org_ca_cert: str
    cdp: list[URL]
    ocsp_url: URL


@frozen
class ClonedCaConfig:
    prod_config: ClonedCaEnvConfig
    test_config: ClonedCaEnvConfig
    seid_v: Literal[1, 2]
    ocsp_type: OcspType
    ocsp_lifetime: timedelta | None = None
    ldap_name: str | None = field(default=None)


class ClonedCa(Enum):
    BUYPASS_CLASS_3_CA_1 = ClonedCaConfig(
        ClonedCaEnvConfig(
            "BPClass3CA1.pem",
            [
                URL("http://crl.buypass.no/crl/BPClass3CA1.crl"),
                URL(
                    "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%201?certificateRevocationList"
                ),
            ],
            URL("http://ocsp.buypass.no/ocsp/BPClass3CA1"),
        ),
        ClonedCaEnvConfig(
            "BPClass3T4CA1.pem",
            [
                URL("http://crl.test4.buypass.no/crl/BPClass3T4CA1.crl"),
                URL(
                    "ldap://ldap.test4.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20Test4%20CA%201?certificateRevocationList"
                ),
            ],
            URL("http://ocsp.test4.buypass.no/ocsp/BPClass3T4CA1"),
        ),
        seid_v=1,
        ocsp_type=OcspType.DIRECT_RESPONDER_NAME,
    )
    BUYPASS_CLASS_3_CA_3 = ClonedCaConfig(
        ClonedCaEnvConfig(
            "BPClass3CA3.pem",
            [
                URL("http://crl.buypass.no/crl/BPClass3CA3.crl"),
                URL(
                    "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%203?certificateRevocationList"
                ),
            ],
            URL("http://ocsp.buypass.no/ocsp/BPClass3CA3"),
        ),
        ClonedCaEnvConfig(
            "BPClass3T4CA3.pem",
            [
                URL("http://crl.test4.buypass.no/crl/BPClass3T4CA3.crl"),
                URL(
                    "ldap://ldap.test4.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20Test4%20CA%203?certificateRevocationList"
                ),
            ],
            URL("http://ocsp.test4.buypass.no/ocsp/BPClass3T4CA3"),
        ),
        seid_v=1,
        ocsp_type=OcspType.DIRECT_RESPONDER_NAME,
    )
    BUYPASS_CLASS_3_CA_G2_HTBS = ClonedCaConfig(
        ClonedCaEnvConfig(
            "BPCl3CaG2HTBS.pem",
            [URL("http://crl.buypassca.com/BPCl3CaG2HTBS.crl")],
            URL("http://ocspbs.buypassca.com"),
        ),
        ClonedCaEnvConfig(
            "BPCl3CaG2HTBS.pem",
            [URL("http://crl.test4.buypassca.com/BPCl3CaG2HTBS.crl")],
            URL("http://ocspbs.test4.buypassca.com"),
        ),
        seid_v=2,
        ocsp_type=OcspType.DELEGATED_RESPONDER_NAME,
        ocsp_lifetime=timedelta(hours=8),
    )
    BUYPASS_CLASS_3_CA_G2_STBS = ClonedCaConfig(
        ClonedCaEnvConfig(
            "BPCl3CaG2STBS.pem",
            [URL("http://crl.buypassca.com/BPCl3CaG2STBS.crl")],
            URL("http://ocspbs.buypassca.com"),
        ),
        ClonedCaEnvConfig(
            "BPCl3CaG2STBS.pem",
            [URL("http://crl.test4.buypassca.com/BPCl3CaG2STBS.crl")],
            URL("http://ocspbs.test4.buypassca.com"),
        ),
        seid_v=2,
        ocsp_type=OcspType.DELEGATED_RESPONDER_NAME,
        ocsp_lifetime=timedelta(hours=8),
    )
    BUYPASS_CLASS_3_CA_G2_HTPS = ClonedCaConfig(
        ClonedCaEnvConfig(
            "BPCl3CaG2HTPS.pem",
            [URL("http://crl.buypassca.com/BPCl3CaG2HTPS.crl")],
            URL("http://ocspps.buypassca.com"),
        ),
        ClonedCaEnvConfig(
            "BPCl3CaG2HTPS.pem",
            [URL("http://crl.test4.buypassca.com/BPCl3CaG2HTPS.crl")],
            URL("http://ocspps.test4.buypassca.com"),
        ),
        seid_v=2,
        ocsp_type=OcspType.DELEGATED_RESPONDER_NAME,
        ocsp_lifetime=timedelta(hours=8),
    )
    COMMFIDES_LEGAL_PERSON_CA_G3 = ClonedCaConfig(
        ClonedCaEnvConfig(
            "CommfidesLegalPersonCA-G3.crt",
            [URL("http://crl.commfides.com/G3/CommfidesLegalPersonCA-G3.crl")],
            URL("http://ocsp.commfides.com"),
        ),
        ClonedCaEnvConfig(
            "CommfidesLegalPersonCA-G3-TEST.crt",
            [
                URL(
                    "http://crl.test.commfides.com/G3/CommfidesLegalPersonCA-G3-TEST.crl"
                )
            ],
            URL("http://ocsp.test.commfides.com"),
        ),
        seid_v=2,
        ldap_name="Legal-Person-G3",
        ocsp_type=OcspType.DELEGATED_RESPONDER_KEY_HASH,
    )
    COMMFIDES_NATURAL_PERSON_CA_G3 = ClonedCaConfig(
        ClonedCaEnvConfig(
            "CommfidesNaturalPersonCA-G3.crt",
            [URL("http://crl.commfides.com/G3/CommfidesNaturalPersonCA-G3.crl")],
            URL("http://ocsp.commfides.com"),
        ),
        ClonedCaEnvConfig(
            "CommfidesNaturalPersonCA-G3-TEST.crt",
            [
                URL(
                    "http://crl.test.commfides.com/G3/CommfidesNaturalPersonCA-G3-TEST.crl"
                )
            ],
            URL("http://ocsp.test.commfides.com"),
        ),
        seid_v=2,
        ldap_name="Natural-Person-G3",
        ocsp_type=OcspType.DELEGATED_RESPONDER_KEY_HASH,
    )
    COMMFIDES_PERSON_HIGH = ClonedCaConfig(
        ClonedCaEnvConfig(
            "CommfidesPerson-High-SHA256.pem",
            [
                URL("http://crl1.commfides.com/CommfidesPerson-High-SHA256.crl"),
                URL("http://crl2.commfides.com/CommfidesPerson-High-SHA256.crl"),
            ],
            URL("http://ocsp1.commfides.com"),
        ),
        ClonedCaEnvConfig(
            "CommfidesPerson-High-SHA256.pem",
            [
                URL("http://crl1.test.commfides.com/CommfidesPerson-High-SHA256.crl"),
                URL("http://crl2.test.commfides.com/CommfidesPerson-High-SHA256.crl"),
            ],
            URL("http://ocsp1.test.commfides.com"),
        ),
        seid_v=1,
        ldap_name="Person-High",
        ocsp_type=OcspType.DELEGATED_RESPONDER_KEY_HASH,
    )
    COMMFIDES_ENTERPRISE = ClonedCaConfig(
        ClonedCaEnvConfig(
            "CommfidesEnterprise-SHA256.pem",
            [
                URL("http://crl1.commfides.com/CommfidesEnterprise-SHA256.crl"),
                URL("http://crl2.commfides.com/CommfidesEnterprise-SHA256.crl"),
            ],
            URL("http://ocsp1.commfides.com"),
        ),
        ClonedCaEnvConfig(
            "CommfidesEnterprise-SHA256.pem",
            [
                URL("http://crl1.test.commfides.com/CommfidesEnterprise-SHA256.crl"),
                URL("http://crl2.test.commfides.com/CommfidesEnterprise-SHA256.crl"),
            ],
            URL("http://ocsp1.test.commfides.com"),
        ),
        seid_v=1,
        ldap_name="Enterprise",
        ocsp_type=OcspType.DELEGATED_RESPONDER_KEY_HASH,
    )

    @property
    def is_commfides(self) -> bool:
        return self.name.startswith("COMMFIDES")

    @property
    def is_buypass(self) -> bool:
        return self.name.startswith("BUYPASS")
