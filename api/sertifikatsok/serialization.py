"""Serialization for the different sertifikatsok classes"""
import base64
import codecs
from datetime import datetime
from typing import Dict, Union, Tuple
from operator import attrgetter
from functools import singledispatch

from .qcert import QualifiedCertificate, QualifiedCertificateSet
from .enums import CertType, CertificateStatus, CertificateRoles
from .search import CertificateSearch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


@singledispatch
def sertifikatsok_serialization(val):
    """default"""
    return str(val)


@sertifikatsok_serialization.register(QualifiedCertificate)
def qualified_certificate(val):

    dumped: Dict[str, Union[str, Dict[str, str]]] = {}
    name, usage = _get_norwegian_display_name(val)
    dumped["name"] = name
    info = {}
    info["Bruksområde(r)"] = usage
    info["Serienummer (hex)"] = format(val.cert.serial_number, "x")
    info["Serienummer (int)"] = str(val.cert.serial_number)

    # We use SHA1 here since thats what Windows uses
    info["Avtrykk (SHA-1)"] = codecs.encode(
        val.cert.fingerprint(hashes.SHA1()), "hex"
    ).decode("ascii")
    info["Emne"] = val.print_subject(full=True)
    info["Utsteder"] = val.issuer
    info["Gyldig fra"] = val.cert.not_valid_before.isoformat()
    info["Gyldig til"] = val.cert.not_valid_after.isoformat()
    info["Nøkkelbruk"] = val.get_key_usages()
    info["Type"] = val.description

    info["Status"] = _get_norwegian_cert_status(val.status, val.revocation_date)

    dumped["info"] = info
    dumped["certificate"] = base64.b64encode(
        val.cert.public_bytes(Encoding.DER)
    ).decode("ascii")

    return dumped


@sertifikatsok_serialization.register(QualifiedCertificateSet)
def qualified_certificate_set(val):
    dumped = {}

    dumped["notices"] = []
    if val.underenhet:
        dumped["notices"].append("underenhet")
    if val.typ == CertType.UNKNOWN:
        dumped["notices"].append("ukjent")

    dumped["issuer"] = val.issuer

    if "Buypass" in val.issuer:
        dumped["issuer"] = "Buypass"
    elif "Commfides" in val.issuer:
        dumped["issuer"] = "Commfides"

    dumped["status"] = _get_norwegian_cert_status(val.status, None)

    dumped["org_number"] = val.org_number
    dumped["subject"] = val.subject
    dumped["valid_from"] = val.valid_from
    dumped["valid_to"] = val.valid_to

    dumped["ldap"] = val.ldap
    dumped["certificates"] = []

    dumped["certificates"] = val.certs

    return dumped


@sertifikatsok_serialization.register(CertificateSearch)
def certificate_search(val):
    result = {}
    result["subject"] = val.search_filter

    errors = set()
    for error in val.errors:
        errors.add(_get_norwegian_error_message(error))

    result["errors"] = list(errors)

    result["certificate_sets"] = []
    for cert_set in val.cert_sets:
        result["certificate_sets"].append(cert_set)

    result["certificate_sets"].sort(key=attrgetter("valid_from"), reverse=True)

    return result


def _get_norwegian_cert_status(
    cert_status: CertificateStatus, revocation_date: datetime
):
    if cert_status == CertificateStatus.OK:
        return "OK"
    elif cert_status == CertificateStatus.EXPIRED:
        return "Utgått"
    elif cert_status == CertificateStatus.REVOKED:
        if revocation_date:
            return f"Revokert ({revocation_date})"
        return "Revokert"
    elif cert_status == CertificateStatus.INVALID:
        return "Ugyldig"
    return "Ukjent"


def _get_norwegian_display_name(cert: QualifiedCertificate) -> Tuple[str, str]:
    """
    Returns the appropriate Norwegian name and application for it
    """
    if CertificateRoles.SIGN in cert.roles:
        return "Signeringssertifikat", "Signering"
    elif CertificateRoles.CRYPT in cert.roles and CertificateRoles.AUTH in cert.roles:
        return "Krypteringssertifikat", "Kryptering og autentisering"
    elif CertificateRoles.CRYPT in cert.roles:
        return "Krypteringssertifikat", "Kryptering"
    elif CertificateRoles.AUTH in cert.roles:
        return "Autentiseringssertifikat", "Autentisering"
    return "Ukjent", "Ukjent"


def _get_norwegian_error_message(error_code: str) -> str:
    if error_code == "ERR-001":
        return "Kunne ikke hente sertfikater fra Buypass"
    if error_code == "ERR-002":
        return "Kunne ikke hente sertfikater fra Commfides"
    if error_code == "ERR-003":
        return (
            "Kunne ikke hente ned alle CRL-er, "
            "revokeringsstatus er derfor ukjent for noen sertifikater"
        )
    if error_code == "ERR-004":
        return (
            "Det er mulig noen gamle sertifikater ikke vises, "
            "da søket returnerte for mange resultater"
        )
    return "Det har skjedd en ukjent feil"
