"""Serialization for the different sertifikatsok classes"""

from __future__ import annotations

import base64
import codecs
from datetime import datetime
from functools import singledispatch
from operator import attrgetter
from typing import Any

from cattrs.preconf.json import make_converter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from sertifikatsok.crypto import (
    CrlDateValidationError,
    CrlError,
    CrlErrorReason,
    CrlHttpStatusError,
    UnsupportedCriticalExtensionInCrlError,
)
from sertifikatsok.revocation_info import (
    OcspError,
    OcspErrorReason,
    OcspHttpStatusError,
    OcspNextUpdateInThePastError,
    OcspStatusError,
)
from sertifikatsok.utils import get_datetime_as_norway_timezone_str

from .enums import (
    CertificateRoles,
    CertificateStatus,
    CertType,
    Environment,
    RevocationCheckUnavailableReason,
    SearchType,
)
from .logging import correlation_id_var
from .qcert import QualifiedCertificate, QualifiedCertificateSet
from .search import CertificateSearchResponse

converter = make_converter()

converter.register_unstructure_hook(
    datetime, lambda dt: get_datetime_as_norway_timezone_str(dt)
)


@singledispatch
def sertifikatsok_serialization(val: Any) -> dict[Any, Any]:
    """default"""
    raise NotImplementedError()


@sertifikatsok_serialization.register(QualifiedCertificate)
def qualified_certificate(
    val: QualifiedCertificate,
) -> dict[str, str | dict[str, str] | None]:
    dumped: dict[str, str | dict[str, str] | None] = {}
    name, usage = _get_norwegian_display_name(val)
    dumped["name"] = name
    info = {}
    info["Bruksområde(r)"] = usage
    info["Serienummer (hex)"] = format(val.cert.cert.serial_number, "x")
    info["Serienummer (int)"] = str(val.cert.cert.serial_number)

    # We use SHA1 here since thats what Windows uses
    info["Avtrykk (SHA-1)"] = codecs.encode(
        val.cert.cert.fingerprint(hashes.SHA1()),  # noqa: S303
        "hex",
    ).decode("ascii")
    info["Emne"] = val.print_subject(full=True)
    info["Utsteder"] = val.issuer
    info["Gyldig fra"] = get_datetime_as_norway_timezone_str(val.cert.not_valid_before)
    info["Gyldig til"] = get_datetime_as_norway_timezone_str(val.cert.not_valid_after)
    info["Nøkkelbruk"] = val.get_key_usages()
    eku = val.get_extended_key_usages()
    info["Utvidet nøkkelbruk"] = eku if eku is not None else "(ingen)"
    key_info = val.get_key_info()
    info["Nøkkeltype"] = key_info if key_info is not None else "Ukjent"

    # If the type is unknown only the OID is present in the description
    # (if it's present. otherwise it's an invalid cert)
    if val.type == CertType.UNKNOWN:
        info["Type"] = "Ukjent"
        if val.description is not None:
            info["Type"] += f" (oid: {val.description})"
    else:
        assert val.description is not None
        info["Type"] = val.description

    info["Status"] = _get_norwegian_cert_status(val.status, val.revocation_date)

    dumped["info"] = info
    dumped["certificate"] = base64.b64encode(
        val.cert.cert.public_bytes(Encoding.DER)
    ).decode("ascii")

    dumped["revocation_check_unavailable_reason"] = (
        _get_norwegian_revocation_check_unavailable_reason(rcur)
        if (rcur := val.get_revocation_check_unavailable_reason())
        else None
    )

    return dumped


@sertifikatsok_serialization.register(QualifiedCertificateSet)
def qualified_certificate_set(val: QualifiedCertificateSet) -> dict[str, Any]:
    dumped: dict[str, Any] = {}

    dumped["notices"] = []
    if val.main_cert.cert.invalid:
        dumped["notices"].append("feilformatert")
    else:
        if val.underenhet:
            dumped["notices"].append("underenhet")
        if val.typ == CertType.UNKNOWN:
            dumped["notices"].append("ukjent")
        if val.seid2:
            dumped["notices"].append("seid2")
        if (
            # TODO: do this in a better way when this mess is cleaned up
            val.main_cert.description is not None
            and "Buypass person-sertifikat (HSM)" in val.main_cert.description
        ):
            dumped["notices"].append("not_a_smartcard")

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


@sertifikatsok_serialization.register(CertificateSearchResponse)
def certificate_search(val: CertificateSearchResponse) -> dict[str, Any]:
    result: dict[str, Any] = {}

    errors = set()
    for error in val.errors.union(val.warnings):
        errors.add(_get_norwegian_error_message(error))

    result["errors"] = list(errors)

    result["certificate_sets"] = []
    for cert_set in val.cert_sets:
        result["certificate_sets"].append(cert_set)

    result["certificate_sets"].sort(key=attrgetter("valid_from"), reverse=True)

    if val.search.ldap_params.organization is not None:
        result["subject"] = (
            f"{val.search.ldap_params.organization.name} "
            f"({val.search.ldap_params.organization.orgnr})"
        )
    else:
        result["subject"] = val.search.search_params.query

    if val.search.search_params.env == Environment.TEST:
        search_env = "Test"
    elif val.search.search_params.env == Environment.PROD:
        search_env = "Produksjon"
    else:
        search_env = "Ukjent"

    if val.search.search_params.typ == CertType.PERSONAL:
        search_type = "Personsertifikater"
    elif val.search.search_params.typ == CertType.ENTERPRISE:
        search_type = "Virksomhetssertifikater"
    else:
        search_type = "Ukjent"

    result["searchDetails"] = {
        "Type": search_type,  # TODO: remove
        "Sertifikattype": search_type,
        "Søketype": _get_norwegian_search_type(val.search.ldap_params.search_type),
        "Søkefilter": str(val.search.ldap_params.ldap_query),
        "Miljø": search_env,
        "LDAP-servere forespurt": ", ".join(
            {
                ldap_server.hostname
                for ldap_server in val.search.ldap_params.ldap_servers
            }
        ),
        "Korrelasjonsid": correlation_id_var.get(),
        "hovedOrgNr": val.search.ldap_params.organization.parent_orgnr
        if val.search.ldap_params.organization is not None
        and val.search.ldap_params.organization.is_child
        else None,
    }

    return result


def ocsp_error_hook(val: OcspError) -> dict:
    match val.error_reason:
        case OcspErrorReason.SIGNATURE_INVALID:
            msg = "Signaturen på OCSP-responsen var ugyldig"
        case OcspErrorReason.MALFORMED:
            msg = "Klarte ikke tolke OCSP-responsen"
        case OcspErrorReason.INVALID_CONTENT_TYPE:
            msg = "OCSP-responderen svarte med en ugyldig HTTP Content Type"
        case OcspErrorReason.NETWORK_ERROR:
            msg = "Nettverksfeil under tilkobling til OCSP-responderen"
        case OcspErrorReason.RESP_MISMATCH_HASH_ALG:
            msg = (
                "OCSP-responsen brukte ikke samme hash-algoritme som OCSP-forespørselen"
            )
        case OcspErrorReason.RESP_MISMATCH_ISSUER_NAME:
            msg = "Utstedernavnet i OCSP-responsen matchet ikke det i forespørselen"
        case OcspErrorReason.RESP_MISMATCH_ISSUER_KEY_HASH:
            msg = (
                "Utsteder-nøkkelhashen i OCSP-responsen matchet ikke det i "
                "forespørselen"
            )
        case OcspErrorReason.RESP_MISMATCH_SERIAL_NUMBER:
            msg = "Serienummeret i OCSP-responsen matchet ikke det i forespørselen"
        case OcspErrorReason.RESP_MISMATCH_NONCE_MISSING:
            msg = "OCSP-responsen manglet nonce"
        case OcspErrorReason.RESP_MISMATCH_NONCE_MISMATCH:
            msg = "OCSP-responsen hadde et nonce som ikke matchet det i forespørselen"
        case OcspErrorReason.DELEGATED_SIGNER_CERT_NOT_INCLUDED:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, men sertifikatet "
                "manglet fra responsen"
            )
        case OcspErrorReason.DELEGED_RESPONDER_NOT_ISSUED_BY_ISSUER:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, men sertifikatet "
                "til den delegerte utstederen var ikke signert av CA-en som signerte "
                "sertifikatet som revokeringssjekkes"
            )
        case OcspErrorReason.DELEGED_RESPONDER_CERT_INVALID_SIGNATURE:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, men signaturen "
                "på sertifikatet til den delegerte utstederen var ugyldig"
            )
        case OcspErrorReason.DELEGED_RESPONDER_CERT_MISSING_EKU:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, men sertifikatet "
                "til den delegerte utstederen manglet tillegg for utvidet nøkkelbruk "
                "('Extended Key Usage')"
            )
        case OcspErrorReason.DELEGED_RESPONDER_CERT_MISSING_OCSP_EKU:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, men sertifikatet "
                "til den delegerte utstederen manglet utvidet nøkkelbruk (EKU) for OCSP "
                "('OCSP Signing')"
            )
        case OcspErrorReason.DELEGED_RESPONDER_UNSUPPORTED_KEY_TYPE:
            msg = (
                "OCSP-responsen var signert av en delegert utsteder, og den delegerte "
                "utstederen brukte en ustøttet nøkkeltype"
            )
        case OcspHttpStatusError():
            msg = (
                f"OCSP-responderen svarte med en ugyldig HTTP-statuskode: "
                f"{val.error_reason.http_status_code}"
            )
        case OcspStatusError():
            msg = (
                f"OCSP-responsen hadde en ugyldig status: "
                f"{val.error_reason.ocsp_status}"
            )
        case OcspNextUpdateInThePastError():
            msg = (
                f"OCSP-responsen hadde 'Next Update' satt i fortiden: "
                f"{get_datetime_as_norway_timezone_str(val.error_reason.next_update)}"
            )
    return {"error": msg}


converter.register_unstructure_hook(OcspError, ocsp_error_hook)


def crl_error_hook(val: CrlError) -> dict:
    match val.error_reason:
        case CrlErrorReason.SIGNATURE_INVALID:
            msg = "Signaturen på den nedlastede CRL-en var ugyldig"
        case CrlErrorReason.MALFORMED:
            msg = "Klarte ikke å tolke den nedlastede CRL-en"
        case CrlErrorReason.NETWORK_ERROR:
            msg = "Nettverksfeil under henting av CRL"
        case CrlErrorReason.INVALID_CONTENT_TYPE:
            msg = "Fikk ugyldig Content-Type ved nedlasting av CRL"
        case CrlErrorReason.WRONG_ISSUER:
            msg = (
                "Utstederen til CRL-en matchet ikke utstederen til sertifikatet "
                "som ble sjekket"
            )
        case CrlErrorReason.MISSING_NEXT_UPDATE:
            msg = "CRL-en manglet det påkrevde feltet (ihht. rfc5280) 'nextUpdate'"
        case CrlHttpStatusError():
            msg = f"Fikk uventet HTTP-kode ved nedlasting av CRL: HTTP {val.error_reason.http_status_code}"
        case CrlDateValidationError():
            msg = (
                f"CRL-en var ikke gyldig mtp. dato. "
                f"Next update: {get_datetime_as_norway_timezone_str(val.error_reason.next_update)} "
                f"Last update: {get_datetime_as_norway_timezone_str(val.error_reason.last_update)}"
            )
        case UnsupportedCriticalExtensionInCrlError():
            msg = f"CRL-en inneholdt uventede kritiske utvidelser: {val.error_reason.extensions}"

    return {"error": msg}


converter.register_unstructure_hook(CrlError, crl_error_hook)


def _get_norwegian_cert_status(
    cert_status: CertificateStatus, revocation_date: datetime | None
) -> str:
    match cert_status:
        case CertificateStatus.OK:
            return "OK"
        case CertificateStatus.EXPIRED:
            return "Utgått"
        case CertificateStatus.REVOKED:
            return (
                f"Revokert ({get_datetime_as_norway_timezone_str(revocation_date)})"
                if revocation_date is not None
                else "Revokert"
            )
        # TODO: Should UNTRUSTED be with UNKNOWN? We don't
        # trust the issuer, but others might...
        case CertificateStatus.INVALID | CertificateStatus.UNTRUSTED:
            return "Ugyldig"
        case CertificateStatus.UNKNOWN:
            return "Ukjent"


def _get_norwegian_display_name(cert: QualifiedCertificate) -> tuple[str, str]:
    """
    Returns the appropriate Norwegian name and application for it
    """
    if len(cert.roles) == 3:
        return "Altmuligsertifikat", "Signering, kryptering og autentisering"
    elif CertificateRoles.SIGN in cert.roles:
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
        return "Kunne ikke hente alle sertfikater fra Buypass"
    if error_code == "ERR-001a":
        return "Kunne ikke hente sertfikater fra Buypass"
    if error_code == "ERR-002":
        return "Kunne ikke hente alle sertfikater fra Commfides"
    if error_code == "ERR-002a":
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
    if error_code == "ERR-005":
        return (
            "Ikke alle sertifikatene vises, da søket returnerte "
            "noen feilformaterte sertifikater"
        )
    if error_code == "ERR-006":
        return (
            "Merk at Buypass ikke lenger inkluderer e-postadresse i "
            "sine sertifikater, så nyere Buypass-sertifikater "
            "vil ikke bli funnet av søk etter e-post"
        )
    if error_code == "ERR-008":
        return (
            "Ldap-url-en matcher ikke miljøet du søkte i, "
            "sertifikatene vil derfor ikke være tiltrodde"
        )
    if error_code == "ERR-009":
        return (
            "Søket returnerte sertifikater, men de ble filtrert bort pga. de var"
            " av feil type. Pass på at du søker på riktig type (person/virksomhet)"
        )
    if error_code == "ERR-010":
        return (
            "Søk på avtrykk/thumbprint er ikke helt pålitelig, så det er"
            " mulig at sertifikatet eksisterer, selv om det ikke ble funnet"
        )
    return "Det har skjedd en ukjent feil"


def _get_norwegian_search_type(search_type: SearchType) -> str:
    match search_type:
        case SearchType.ORG_NR:
            return "Organisasjonsnummer"
        case SearchType.PERSONAL_SERIAL:
            return "Personlig serienummer"
        case SearchType.THUMBPRINT:
            return "Avtrykk"
        case SearchType.THUMBPRINT_OR_CERT_SERIAL:
            return "Avtrykk eller sertifikatserienummer"
        case SearchType.EMAIL:
            return "E-post-adresse"
        case SearchType.CERT_SERIAL:
            return "Sertifikatserienummer"
        case SearchType.CUSTOM:
            return "Egendefinert attributt"
        case SearchType.DISTINGUISHED_NAME:
            return "Emnefelt (distinguished name)"
        case SearchType.LDAP_URL:
            return "Ldap-url"
        case SearchType.FALLBACK:
            return "Fritekst (common name)"
        case _:
            return "Ukjent"


def _get_norwegian_revocation_check_unavailable_reason(
    r: RevocationCheckUnavailableReason,
) -> str:
    match r:
        case RevocationCheckUnavailableReason.UNTRUSTED:
            return "sertifikatet er ikke utstedt av en tiltrodd CA"
        case RevocationCheckUnavailableReason.DISCONTINUED_CA:
            return "sertifikatet er utstedt fra en avviklet CA"
        case RevocationCheckUnavailableReason.INVALID_EXTENSIONS:
            return "sertifikatet er feilformatert"
