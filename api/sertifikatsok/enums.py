from enum import Enum


class CertType(Enum):
    PERSONAL = 1
    ENTERPRISE = 2
    UNKNOWN = 3


class Environment(Enum):
    TEST = "test"
    PROD = "prod"


class CertificateStatus(Enum):
    OK = 1
    EXPIRED = 2
    REVOKED = 3
    INVALID = 4
    UNKNOWN = 5


class CertificateRoles(Enum):
    AUTH = 1
    SIGN = 2
    CRYPT = 3


class SearchAttribute(Enum):
    CN = "cn"
    MAIL = "mail"
    OU = "ou"
    O = "o"  # noqa:E741
    SN = "serialNumber"
    CSN = "certificateSerialNumber"
    ORGID = "organizationIdentifier"


class CertificateAuthority(Enum):
    BUYPASS = "buypass"
    COMMFIDES = "commfides"


class SEID(Enum):
    UNKNOWN = 0
    SEID1 = 1
    SEID2 = 2


class SearchType(Enum):
    ORG_NR = "org_nr"
    PERSONAL_SERIAL = "personal_serial"
    CERT_SERIAL = "cert_serial"
    THUMBPRINT = "thumbprint"
    EMAIL = "email"
    CUSTOM = "custom"
    LDAP_URL = "ldap_url"
    FALLBACK = "fallback"
