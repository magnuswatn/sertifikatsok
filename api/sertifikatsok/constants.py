import re
from enum import Enum

# turn off black, so that we can have loooong lines
# fmt: off


LDAP_TIMEOUT = 20
LDAP_RETRIES = 5

ORG_NUMBER_REGEX = re.compile(r"(\d\s?){9}")
UNDERENHET_REGEX = re.compile(r"(?<!\d)\d{9}(?!\d)")
PERSONAL_SERIAL_REGEX = re.compile(r"9578-(4505|4050|4510)-[A-z0-9]+")


class CertType(Enum):
    PERSONAL = 1
    ENTERPRISE = 2
    UNKNOWN = 3

SUBJECT_FIELDS = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "email",
}

KEY_USAGES = [
    ("digital_signature", "Digital signature"),
    # Using Non-repudiation as it's the established name
    ("content_commitment", "Non-repudiation"),
    ("key_encipherment", "Key encipherment"),
    ("data_encipherment", "Data encipherment"),
    ("key_agreement", "Key agreement"),
    ("key_cert_sign", "Certificate signing"),
    ("crl_sign", "CRL signing"),
]

# Contains an dict with known Norwegian Qualified certificates
#
# The key is a tuple with the issuer, as a string, and the Policy OID
#
# The value is a tuple with the type of certificate,
# and a string with an human friendly description
KNOWN_CERT_TYPES = {
    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0.3.2"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (softsertifikat)"),

    # Have no source for this, just a guess based on the prod oid
    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0.3.5"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)"),

    ("C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0.3.2"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (softsertifikat)"),

    # Have no source for this, just a guess based on the prod oid
    ("C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0.3.5"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)"),

    ("C=NO, O=Buypass,  CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0",):
    (CertType.PERSONAL, "Buypass TEST person-sertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.1"):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0"):
    (CertType.PERSONAL, "Buypass TEST person-sertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.1",):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)"),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.6"):
    (CertType.PERSONAL, "Buypass person-sertifikat (HSM)"),

    ("CN=CPN Enterprise SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.13.1.1.0"):
    (CertType.ENTERPRISE, "Commfides virksomhetssertifikat"),

    ("CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.913.1.1.0"):
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat"),

    ("CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST2, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST2, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.913.1.1.0"):
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat"),

    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.1.1.0"):
    (CertType.PERSONAL, "Commfides person-sertifikat"),

    # Commfides uses 2.16.578.1.29.12.1.1.1 as PolicyOID on new Person-High certificates,
    # but it is not documented in their CP/CPS ¯\_(ツ)_/¯
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.1.1.1"):
    (CertType.PERSONAL, "Commfides person-sertifikat"),

    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.1.1.0"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat"),

    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.1.1.1"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat"),
}

# fmt: on
