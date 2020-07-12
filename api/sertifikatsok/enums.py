from enum import Enum


class CertType(Enum):
    PERSONAL = 1
    ENTERPRISE = 2
    UNKNOWN = 3


class Environment(Enum):
    TEST = 1
    PROD = 2


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
    SN = "serialNumber"
