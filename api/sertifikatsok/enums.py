from enum import Enum


class CertType(Enum):
    PERSONAL = 1
    ENTERPRISE = 2
    UNKNOWN = 3


class Environemnt(Enum):
    TEST = 1
    PROD = 2
