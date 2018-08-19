from enum import Enum


class CertType(Enum):
    PERSONAL = 1
    ENTERPRISE = 2
    UNKNOWN = 3


class Environemnt(Enum):
    TEST = 1
    PROD = 2


class CertificateStatus(Enum):
    OK = 1
    EXPIRED = 2
    REVOKED = 3
    INVALID = 4
    UNKNOWN = 5
