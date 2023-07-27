from __future__ import annotations

from enum import Enum
from typing import Literal

from attr import field, frozen

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


@frozen
class Enterprise:
    org_nr: str
    name: str
    parent: Enterprise | None = field(default=None)


@frozen
class ClonedCaConfig:
    org_ca_cert_prod: str
    org_ca_cert_test: str
    cdp_prod: list[str]
    cdp_test: list[str]
    seid_v: Literal[1, 2]
    ldap_name: str | None = field(default=None)


class ClonedCa(Enum):
    BUYPASS_CLASS_3_CA_1 = ClonedCaConfig(
        "BPClass3CA1.pem",
        "BPClass3T4CA1.pem",
        [
            "http://crl.buypass.no/crl/BPClass3CA1.crl",
            "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%201?certificateRevocationList",
        ],
        [
            "http://crl.test4.buypass.no/crl/BPClass3T4CA1.crl",
            "ldap://ldap.test4.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20Test4%20CA%201?certificateRevocationList",
        ],
        seid_v=1,
    )
    BUYPASS_CLASS_3_CA_3 = ClonedCaConfig(
        "BPClass3CA3.pem",
        "BPClass3T4CA3.pem",
        [
            "http://crl.buypass.no/crl/BPClass3CA3.crl",
            "ldap://ldap.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20CA%203?certificateRevocationList",
        ],
        [
            "http://crl.test4.buypass.no/crl/BPClass3T4CA3.crl",
            "ldap://ldap.test4.buypass.no/dc=Buypass,dc=NO,CN=Buypass%20Class%203%20Test4%20CA%203?certificateRevocationList",
        ],
        seid_v=1,
    )
    BUYPASS_CLASS_3_CA_G2_HTBS = ClonedCaConfig(
        "BPCl3CaG2HTBS.pem",
        "BPCl3CaG2HTBS.pem",
        ["http://crl.buypassca.com/BPCl3CaG2HTBS.crl"],
        ["http://crl.test4.buypassca.com/BPCl3CaG2HTBS.crl"],
        seid_v=2,
    )
    BUYPASS_CLASS_3_CA_G2_STBS = ClonedCaConfig(
        "BPCl3CaG2STBS.pem",
        "BPCl3CaG2STBS.pem",
        ["http://crl.buypassca.com/BPCl3CaG2STBS.crl"],
        ["http://crl.test4.buypassca.com/BPCl3CaG2STBS.crl"],
        seid_v=2,
    )
    BUYPASS_CLASS_3_CA_G2_HTPS = ClonedCaConfig(
        "BPCl3CaG2HTPS.pem",
        "BPCl3CaG2HTPS.pem",
        ["http://crl.buypassca.com/BPCl3CaG2HTPS.crl"],
        ["http://crl.test4.buypassca.com/BPCl3CaG2HTPS.crl"],
        seid_v=2,
    )
    COMMFIDES_LEGAL_PERSON_CA_G3 = ClonedCaConfig(
        "CommfidesLegalPersonCA-G3.crt",
        "CommfidesLegalPersonCA-G3-TEST.crt",
        ["http://crl.commfides.com/G3/CommfidesLegalPersonCA-G3.crl"],
        ["http://crl.test.commfides.com/G3/CommfidesLegalPersonCA-G3-TEST.crl"],
        seid_v=2,
        ldap_name="Legal-Person-G3",
    )
    COMMFIDES_NATURAL_PERSON_CA_G3 = ClonedCaConfig(
        "CommfidesNaturalPersonCA-G3.crt",
        "CommfidesNaturalPersonCA-G3-TEST.crt",
        ["http://crl.commfides.com/G3/CommfidesNaturalPersonCA-G3.crl"],
        ["http://crl.test.commfides.com/G3/CommfidesNaturalPersonCA-G3-TEST.crl"],
        seid_v=2,
        ldap_name="Natural-Person-G3",
    )
    COMMFIDES_PERSON_HIGH = ClonedCaConfig(
        "CommfidesPerson-High-SHA256.pem",
        "CommfidesPerson-High-SHA256.pem",
        [
            "http://crl1.commfides.com/CommfidesPerson-High-SHA256.crl",
            "http://crl2.commfides.com/CommfidesPerson-High-SHA256.crl",
        ],
        [
            "http://crl1.test.commfides.com/CommfidesPerson-High-SHA256.crl",
            "http://crl2.test.commfides.com/CommfidesPerson-High-SHA256.crl",
        ],
        seid_v=1,
        ldap_name="Person-High",
    )
    COMMFIDES_ENTERPRISE = ClonedCaConfig(
        "CommfidesEnterprise-SHA256.pem",
        "CommfidesEnterprise-SHA256.pem",
        [
            "http://crl1.commfides.com/CommfidesEnterprise-SHA256.crl",
            "http://crl2.commfides.com/CommfidesEnterprise-SHA256.crl",
        ],
        [
            "http://crl1.test.commfides.com/CommfidesEnterprise-SHA256.crl",
            "http://crl2.test.commfides.com/CommfidesEnterprise-SHA256.crl",
        ],
        seid_v=1,
        ldap_name="Enterprise",
    )

    @property
    def is_commfides(self) -> bool:
        return self.name.startswith("COMMFIDES")

    @property
    def is_buypass(self) -> bool:
        return self.name.startswith("BUYPASS")
