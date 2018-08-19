"""Serialization for the different sertifikatsok classes"""
import base64
import codecs
from datetime import datetime
from typing import Dict, Union
from operator import attrgetter
from functools import singledispatch

from .qcert import QualifiedCertificate, QualifiedCertificateSet
from .enums import CertType, CertificateStatus
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
    name, usage = val.get_display_name()
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
    result["errors"] = val.errors
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
