import re
from typing import Dict, Tuple

from cryptography.x509.oid import ObjectIdentifier

from .enums import SEID, CertType

# turn off black, so that we can have loooong lines
# fmt: off


LDAP_TIMEOUT = 7
LDAP_RETRIES = 5

ORG_NUMBER_REGEX = re.compile(r"(\d\s?){9}")
UNDERENHET_REGEX = re.compile(r"(?<!\d)\d{9}(?!\d)")
PERSONAL_SERIAL_REGEX = re.compile(r"9578-(4505|4050|4510)-[A-z0-9]+")
# (This is a bad email regex, but it's good enough
# for this use case.)
EMAIL_REGEX = re.compile(r"[^\s@]+@[\w\d]+(\.[\w\d]+)+")
HEX_SERIAL_REGEX = re.compile(r"([0-9a-fA-F][\s:]?){16,}")
INT_SERIAL_REGEX = re.compile(r"([0-9]){19,}")

ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")

SUBJECT_FIELDS = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.4": "SN",
    "2.5.4.42": "GN",
    "2.5.4.11": "OU",
    "2.5.4.97": "organizationIdentifier",
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

EXTENDED_KEY_USAGES = {
    "0.4.0.2231.3.0": "TSL signing",
    "2.5.29.37.0": "ANY",
    "1.3.6.1.5.5.7.3.1": "Server authentication",
    "1.3.6.1.5.5.7.3.2": "Client authentication",
    "1.3.6.1.5.5.7.3.3": "Code signing",
    "1.3.6.1.5.5.7.3.4": "Email protection",
    "1.3.6.1.5.5.7.3.8": "Time stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP signing",
    "1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
    "1.3.6.1.4.1.311.10.3.12": "Microsoft Document Signing",
    "1.3.6.1.4.1.311.20.2.2": "Microsoft Smart Card Logon",
}

# Contains an dict with known Norwegian Qualified certificates
#
# The key is a tuple with the issuer, as a string, and the Policy OID
#
# The value is a tuple with the type of certificate,
# and a string with an human friendly description
KNOWN_CERT_TYPES: Dict[Tuple[str, str], Tuple[CertType, str, SEID]] = {
    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0.3.2"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (softsertifikat)", SEID.SEID1),

    # Have no source for this, just a guess based on the prod oid
    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0.3.5"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0.3.2"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (softsertifikat)", SEID.SEID1),

    # Have no source for this, just a guess based on the prod oid
    ("C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0.3.5"):
    (CertType.ENTERPRISE, "Buypass TEST virksomhetssertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)", SEID.SEID1),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 Test4 CA G2 HT Business", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 Test4 CA G2 ST Business", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 CA G2 HT Business", "2.16.578.1.26.1.3.5"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (smartkort)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 CA G2 ST Business", "2.16.578.1.26.1.3.2"):
    (CertType.ENTERPRISE, "Buypass virksomhetssertifikat (softsertifikat)", SEID.SEID2),

    ("C=NO, O=Buypass,  CN=Buypass Class 3 Test4 CA 1", "2.16.578.1.26.1.0",):
    (CertType.PERSONAL, "Buypass TEST person-sertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1", "2.16.578.1.26.1.3.1"):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3", "2.16.578.1.26.1.0"):
    (CertType.PERSONAL, "Buypass TEST person-sertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.1",):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)", SEID.SEID1),

    ("C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3", "2.16.578.1.26.1.3.6"):
    (CertType.PERSONAL, "Buypass person-sertifikat (HSM)", SEID.SEID1),

    # vetta faen hva de bruker i test her.
    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 Test4 CA G2 HT Person", "2.16.578.1.26.1.3.1"):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 Test4 CA G2 HT Person", "2.16.578.1.26.1.3.6"):
    (CertType.PERSONAL, "Buypass person-sertifikat (HSM)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 CA G2 HT Person", "2.16.578.1.26.1.3.1"):
    (CertType.PERSONAL, "Buypass person-sertifikat (smartkort)", SEID.SEID2),

    ("C=NO, organizationIdentifier=NTRNO-983163327, O=Buypass AS, CN=Buypass Class 3 CA G2 HT Person", "2.16.578.1.26.1.3.6"):
    (CertType.PERSONAL, "Buypass person-sertifikat (HSM)", SEID.SEID2),

    ("CN=CPN Enterprise SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.13.1.1.0"):
    (CertType.ENTERPRISE, "Commfides virksomhetssertifikat", SEID.SEID1),

    ("CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.913.1.1.0"):
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat", SEID.SEID1),

    ("CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST2, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST2, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.913.1.1.0"):
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat", SEID.SEID1),

    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.1.1.0"):
    (CertType.PERSONAL, "Commfides person-sertifikat", SEID.SEID1),

    # Commfides uses 2.16.578.1.29.12.1.1.1 as PolicyOID on new Person-High certificates,
    # but it is not documented in their CP/CPS ¯\_(ツ)_/¯
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.1.1.1"):
    (CertType.PERSONAL, "Commfides person-sertifikat", SEID.SEID1),

    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.1.1.0"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat", SEID.SEID1),

    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.1.1.1"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat", SEID.SEID1),


    # Commfides eIDAS certs
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.10.1.0"):
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.11.1.0"):
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.12.1.0"):
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.20.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.21.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.22.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.30.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.31.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert", SEID.SEID1),
    ("CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.12.32.1.0"):
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert", SEID.SEID1),

    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.10.1.0"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.11.1.0"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.12.1.0"):
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.20.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.21.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.22.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.30.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.31.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert", SEID.SEID1),
    ("CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - 988 312 495, C=NO", "2.16.578.1.29.912.32.1.0"):
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert", SEID.SEID1),

    ######################################
    ############ Commfides G3 ############
    ######################################
    # https://pds.commfides.com/G3/

    # Virksomhet
    # prod
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.200.1.0"): # sign
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.210.1.0"): # auth
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.220.1.0"): # crypt
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.300.1.0"): # sign
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.310.1.0"): # auth
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3 - TEST","2.16.578.1.29.913.320.1.0"): # crypt
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),

    # test
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.200.1.0"): # sign
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.210.1.0"): # auth
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.220.1.0"): # crypt
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.300.1.0"): # sign
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.310.1.0"): # auth
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Legal Person - G3","2.16.578.1.29.13.320.1.0"): # crypt
    (CertType.ENTERPRISE, "Commfides TEST virksomhetssertifikat LCP (SEID v2)", SEID.SEID2),

    # Person
    # prod
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.100.1.0"): # sign
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.110.1.0"): # auth
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.120.1.0"): # crypt
    (CertType.PERSONAL, "Commfides person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.200.1.0"): # sign
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.210.1.0"): # auth
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.220.1.0"): # crypt
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.300.1.0"): # sign
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.310.1.0"): # auth
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3","2.16.578.1.29.12.320.1.0"): # crypt
    (CertType.PERSONAL, "Commfides ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),

    # test
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.100.1.0"): # sign
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.110.1.0"): # auth
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.120.1.0"): # crypt
    (CertType.PERSONAL, "Commfides TEST person-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.200.1.0"): # sign
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.210.1.0"): # auth
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.220.1.0"): # crypt
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, sentralisert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.300.1.0"): # sign
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.310.1.0"): # auth
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),
    ("C=NO, O=Commfides Norge AS, organizationIdentifier=NTRNO-988312495, CN=Commfides Natural Person - G3 - TEST","2.16.578.1.29.912.320.1.0"): # crypt
    (CertType.PERSONAL, "Commfides TEST ansatt-sertifikat, distribuert (SEID v2)", SEID.SEID2),
}

# fmt: on
