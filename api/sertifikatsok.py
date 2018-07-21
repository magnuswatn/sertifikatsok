"""The API behind sertifikatsok.no"""
import re
import os
import base64
import codecs
import asyncio
import logging
import urllib.parse
from datetime import datetime
from operator import itemgetter
from typing import Optional, List, Dict, Tuple

import bonsai
import aiohttp

from quart import g
from quart import Quart
from quart import jsonify
from quart import request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

# black and pylint doesn't agree on everything
# pylint: disable=C0330

api = Quart(__name__)

try:
    api.logger.level = getattr(logging, os.environ["SERTIFIKATSOK_LOGLEVEL"])
except KeyError:
    api.logger.level = logging.INFO

api.logger.handlers.extend(logging.getLogger("gunicorn.error").handlers)

ORG_NUMBER_REGEX = re.compile(r"(\d\s?){9}")
UNDERENHET_REGEX = re.compile(r"(?<!\d)\d{9}(?!\d)")
PERSONAL_SERIAL_REGEX = re.compile(r"9578-(4505|4050|4510)-[A-z0-9]+")

# Known issuer/PolicyOID combinations
KNOWN_CERT_TYPES = {
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3",
        "2.16.578.1.26.1.0.3.2",
    ): "Buypass TEST virksomhetssertifikat (softsertifikat)",
    # Have no source for this, just a guess based on the prod oid
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3",
        "2.16.578.1.26.1.0.3.5",
    ): "Buypass TEST virksomhetssertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3",
        "2.16.578.1.26.1.3.2",
    ): "Buypass virksomhetssertifikat (softsertifikat)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3",
        "2.16.578.1.26.1.3.5",
    ): "Buypass virksomhetssertifikat (smartkort)",
    (
        "C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1",
        "2.16.578.1.26.1.0.3.2",
    ): "Buypass TEST virksomhetssertifikat (softsertifikat)",
    # Have no source for this, just a guess based on the prod oid
    (
        "C=NO, O=Buypass, CN=Buypass Class 3 Test4 CA 1",
        "2.16.578.1.26.1.0.3.5",
    ): "Buypass TEST virksomhetssertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1",
        "2.16.578.1.26.1.3.2",
    ): "Buypass virksomhetssertifikat (softsertifikat)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1",
        "2.16.578.1.26.1.3.5",
    ): "Buypass virksomhetssertifikat (smartkort)",
    (
        "C=NO, O=Buypass,  CN=Buypass Class 3 Test4 CA 1",
        "2.16.578.1.26.1.0",
    ): "Buypass TEST person-sertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 1",
        "2.16.578.1.26.1.3.1",
    ): "Buypass person-sertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3",
        "2.16.578.1.26.1.0",
    ): "Buypass TEST person-sertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3",
        "2.16.578.1.26.1.3.1",
    ): "Buypass person-sertifikat (smartkort)",
    (
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3",
        "2.16.578.1.26.1.3.6",
    ): "Buypass person-sertifikat (HSM)",
    (
        "CN=CPN Enterprise SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 "
        "Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO",
        "2.16.578.1.29.13.1.1.0",
    ): "Commfides virksomhetssertifikat",
    (
        "CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST, OU=Commfides Trust Environment(C) "
        "2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST, O=Commfides "
        "Norge AS - 988 312 495, C=NO",
        "2.16.578.1.29.913.1.1.0",
    ): "Commfides TEST virksomhetssertifikat",
    (
        "CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST2, OU=Commfides Trust Environment(C) "
        "2014 Commfides Norge AS - TEST, OU=CPN Enterprise-Norwegian SHA256 CA- TEST2, O=Commfides "
        "Norge AS - 988 312 495, C=NO",
        "2.16.578.1.29.913.1.1.0",
    ): "Commfides TEST virksomhetssertifikat",
    (
        "CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 "
        "Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO",
        "2.16.578.1.29.12.1.1.0",
    ): "Commfides person-sertifikat",
    # Commfides uses 2.16.578.1.29.12.1.1.1 as PolicyOID on new Person-High certificates,
    # but it is not documented in their CP/CPS ¯\_(ツ)_/¯
    (
        "CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 "
        "Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - "
        "988 312 495, C=NO",
        "2.16.578.1.29.12.1.1.1",
    ): "Commfides person-sertifikat",
    (
        "CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 "
        "Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - "
        "988 312 495, C=NO",
        "2.16.578.1.29.912.1.1.0",
    ): "Commfides TEST person-sertifikat",
    (
        "CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 "
        "Commfides Norge AS - TEST, OU=CPN Person High SHA256 CA - TEST, O=Commfides Norge AS - "
        "988 312 495, C=NO",
        "2.16.578.1.29.912.1.1.1",
    ): "Commfides TEST person-sertifikat",
}

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


class SertifikatSokError(Exception):
    """Superclass for all exceptions"""

    pass


class ClientError(SertifikatSokError):
    """Signifies that the request was malformed"""

    pass


class ServerError(SertifikatSokError):
    """Signifies that the server failed to respond to the request"""

    pass


class CouldNotGetValidCRLError(SertifikatSokError):
    """Signifies that we could not download a valid crl"""

    pass


class QualifiedCertificate(object):
    """Represents a Norwegian Qualified Certificate"""

    def __init__(self, cert, dn, ldap_params):
        self.cert = x509.load_der_x509_certificate(cert, default_backend())

        self.issuer = self._print_issuer()
        self.type = self._get_type()
        self.dn = dn
        self.ldap_params = ldap_params

        # Only add CDP if the cert is still valid
        # (no reason to check CRL if the cert is expired)
        if self._check_date():
            self.cdp = self._get_http_cdp()
            self.status = "OK"
        else:
            self.cdp = None
            self.status = "Utgått"

    def _check_date(self):
        """Returns whether the certificate is valid wrt. the dates"""
        return (
            self.cert.not_valid_after > datetime.utcnow()
            and self.cert.not_valid_before < datetime.utcnow()
        )

    def _get_type(self):
        """Returns the type of certificate, based on issuer and Policy OID"""
        cert_policies = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("2.5.29.32")
        ).value

        for policy in cert_policies:
            try:
                oid = policy.policy_identifier.dotted_string
                return KNOWN_CERT_TYPES[(self.issuer, oid)]
            except KeyError:
                pass

        # This will only display the last OID, out of potentially several, but good enough
        return "Ukjent (oid: {})".format(oid)

    def _get_http_cdp(self):
        """Returns the first CRL Distribution Point from the cert with http scheme, if any"""
        cdps = self.cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("2.5.29.31")).value
        for cdp in cdps:
            url = urllib.parse.urlparse(cdp.full_name[0].value)
            if url.scheme == "http":
                return cdp.full_name[0].value
        return None

    def get_roles(self):
        """
        A set of Norwegian qualified certificates should have certificates intended for
        *) Encryption
        *) Signature
        *) Authentication

        Several roles can be placed on one certificate (Buypass does this).

        This function returns which role(s) this certificate has.
        """
        cert_roles = []
        key_usage = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.digital_signature:
            cert_roles.append("auth")
        if key_usage.content_commitment:
            cert_roles.append("sign")
        if key_usage.data_encipherment:
            cert_roles.append("crypt")
        return cert_roles

    def print_subject(self, full=False):
        """
        Returns the subject of the cert as a string.
        If it's an non-Enterprise Commfides certificate (indicated by an organization number in the
        serialNumber field) the serialNumber field is skipped, unless 'full' is True.

        This is becuase Commfides generates random serialNumbers for all Person certificates,
        so they are not very useful and also different within a set
        """
        subject = []
        for field in self.cert.subject:
            if field.oid.dotted_string == "2.5.4.5" and not full:
                # Skip serialNumber if non-Enterprise cert from Commfides
                if "Commfides" in self.issuer and not ORG_NUMBER_REGEX.fullmatch(field.value):
                    continue
            try:
                subject.append("{}={}".format(SUBJECT_FIELDS[field.oid.dotted_string], field.value))
            except KeyError:
                # If we don't recognize the field, we just print the dotted string
                subject.append("{}={}".format(field.oid.dotted_string, field.value))

        # If not full (e.g. used for pretty printing), we order the fields in an uniform order
        if not full:
            subject.sort(key=subject_order)
        return ", ".join(list(subject))

    def _print_issuer(self):
        """
        Returns the issuer of the cert as a string.
        """
        subject = []
        for field in self.cert.issuer:
            try:
                subject.append("{}={}".format(SUBJECT_FIELDS[field.oid.dotted_string], field.value))
            except KeyError:
                # If we don't recognize the field, we just print the dotted string
                subject.append("{}={}".format(field.oid.dotted_string, field.value))
        return ", ".join(list(subject))

    def get_orgnumber(self) -> Tuple[Optional[str], bool]:
        """
        Gets the organization number from the cert,
        and returns the organization number + if it's and "underenhet"
        """
        serial_number = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value

        if not ORG_NUMBER_REGEX.fullmatch(serial_number):
            # personal cert
            return None, False

        try:
            ou_field = self.cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[
                0
            ].value
        except IndexError:
            return serial_number, False

        ou_number = UNDERENHET_REGEX.search(ou_field)

        if ou_number and serial_number != ou_number[0]:
            return ou_number[0], True

        return serial_number, False

    def get_display_name(self):
        """
        Examines the key usage bits in the certificate
        and returns the appropriate Norwegian name and application for it
        """
        key_usage = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.content_commitment:
            return "Signeringssertifikat", "Signering"
        elif key_usage.data_encipherment and key_usage.digital_signature:
            return "Krypteringssertifikat", "Kryptering og autentisering"
        elif key_usage.data_encipherment:
            return "Krypteringssertifikat", "Kryptering"
        elif key_usage.digital_signature:
            return "Autentiseringssertifikat", "Autentisering"
        return "Ukjent", "Ukjent"

    def get_key_usages(self):
        """Returns a string with the key usages from the cert"""
        key_usages = []
        for key_usage in KEY_USAGES:
            if getattr(
                self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
                key_usage[0],
            ):
                key_usages.append(key_usage[1])
        return ", ".join(key_usages)


class QualifiedCertificateSet(object):
    """Represents a set of Norwegian qualified certificates"""

    def __init__(self, certs):
        self.certs = certs

    def get_non_encryption_cert(self):
        """
        This tries to find an non-encryption certificate in the certificate set and return that

        If none is found, the first cert in the set is returned
        """
        for cert in self.certs:
            key_usage = cert.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if not key_usage.data_encipherment:
                return cert
        return self.certs[0]

    def create_ldap_url(self):
        """Creates an LDAP url (RFC 1959) for the certificate set"""
        filter_parts = []
        for cert in self.certs:
            filter_parts.append(cert.dn.split(",")[0])
        ldap_filter = ")(".join(filter_parts)
        ldap_url = "{}/{}?usercertificate;binary?sub?(|({}))".format(
            self.certs[0].ldap_params[0],
            urllib.parse.quote(self.certs[0].ldap_params[1], safe="=,"),
            ldap_filter,
        )
        return ldap_url


class CRL:
    """Represents a Certificate Revocation List"""

    def __init__(self, url: str) -> None:
        self.url = url
        self.crl: Optional[x509.CertificateRevocationList] = None

    @classmethod
    async def create(cls, url: str, valid_issuers: dict) -> "CRL":
        """
        Creates, and returns, a CRL object.

        Needed to be able to do the async stuff
        """
        crl = cls(url)
        try:
            crl.crl = crl.get_from_file(valid_issuers)
        except CouldNotGetValidCRLError:
            crl.crl = await crl.download(valid_issuers)

        return crl

    def get_revoked_date(self, cert: x509.Certificate) -> Optional[str]:
        """Get the revocation date for a cert"""
        revoked_cert = self.crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked_cert:
            return str(revoked_cert.revocation_date)
        return None

    def get_from_file(self, valid_issuers: dict) -> x509.CertificateRevocationList:
        """Retrieves the CRl from disk"""
        filename = "./crls/{}".format(urllib.parse.quote_plus(self.url))
        try:
            with open(filename, "rb") as open_file:
                crl_bytes = open_file.read()
        except FileNotFoundError:
            raise CouldNotGetValidCRLError

        crl = x509.load_der_x509_crl(crl_bytes, default_backend())

        if not self._validate(crl, valid_issuers):
            raise CouldNotGetValidCRLError
        return crl

    async def download(self, valid_issuers: dict) -> x509.CertificateRevocationList:
        """Downloads the crl from the specified url"""
        headers = {"user-agent": "sertifikatsok.no"}
        crl_timeout = aiohttp.ClientTimeout(total=5)

        api.logger.info("Downloading CRL %s", self.url)
        async with aiohttp.ClientSession(timeout=crl_timeout) as session:
            try:
                resp = await session.get(self.url, headers=headers)
                crl_bytes = await resp.read()
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                raise CouldNotGetValidCRLError(f"Could not retrieve CRL: {error}")

        api.logger.debug("Finishined downloading CRL %s", self.url)

        if resp.status != 200:
            raise CouldNotGetValidCRLError(f"Got status code {resp.status_code} for url {self.url}")

        if resp.headers["Content-Type"] not in ("application/pkix-crl", "application/x-pkcs7-crl"):
            raise CouldNotGetValidCRLError(
                f"Got content type: {resp.headers['Content-Type']} for url {self.url}"
            )

        crl = x509.load_der_x509_crl(crl_bytes, default_backend())

        if not self._validate(crl, valid_issuers):
            raise CouldNotGetValidCRLError

        filename = f"./crls/{urllib.parse.quote_plus(self.url)}"
        with open(filename, "wb") as open_file:
            open_file.write(crl_bytes)

        return crl

    @staticmethod
    def _validate(crl: x509.CertificateRevocationList, valid_issuers: dict) -> bool:
        """Validates a crl against a issuer certificate"""
        try:
            issuer = valid_issuers[crl.issuer]
        except KeyError:
            # We don't trust the issuer for this crl
            return False

        if not (crl.next_update > datetime.utcnow() and crl.last_update < datetime.utcnow()):
            return False
        if not crl.issuer == issuer.subject:
            return False
        try:
            issuer.public_key().verify(
                crl.signature, crl.tbs_certlist_bytes, PKCS1v15(), crl.signature_hash_algorithm
            )
        except InvalidSignature:
            return False
        return True


def subject_order(field: str) -> int:
    """Returns the order of the subject element, for pretty printing"""
    order = {"serialNumber": 0, "email": 1, "CN": 2, "OU": 3, "O": 4, "L": 5, "ST": 6, "C": 7}
    field_name = field.split("=")[0]
    try:
        return order[field_name]
    except KeyError:
        return 8


def get_issuer_cert(issuer: str, env: str) -> x509.Certificate:
    """Retrieves the issuer certificate from file, if we have it"""
    filename = "./certs/{}/{}.pem".format(env, urllib.parse.quote_plus(issuer))
    try:
        with open(filename, "rb") as open_file:
            issuer_bytes = open_file.read()
    except FileNotFoundError:
        api.logger.warning("Could not find cert %s on disk", issuer)
        return None
    return x509.load_pem_x509_certificate(issuer_bytes, default_backend())


async def get_cert_status(certs: List[QualifiedCertificate], env: str) -> None:
    """
    Checks the trust status of the certificates against the trusted issuers
    """
    # Make a list over all the issuers and crl locations that we need
    urls = set([cert.cdp for cert in certs if cert.cdp])
    issuers = set([cert.issuer for cert in certs])

    # load all the issuers that we need
    loaded_issuers = {}
    for issuer in issuers:
        loaded_issuer = get_issuer_cert(issuer, env)
        if loaded_issuer:
            loaded_issuers[loaded_issuer.subject] = loaded_issuer

    # load all the crls that we need
    crls = {}
    for url in urls:
        try:
            crls[url] = await CRL.create(url, loaded_issuers)
        except CouldNotGetValidCRLError:
            api.logger.exception("Could not get retrieve CRL")
            g.errors.append(
                f"Kunne ikke hente ned gyldig CRL fra {url}. "
                f"Revokeringsstatus er derfor ukjent for noen sertifikater."
            )

    # validate all the certs against the issuers and the crls
    for cert in certs:
        try:
            issuer = loaded_issuers[cert.cert.issuer]
        except KeyError:
            # We don't have the cert in our truststore...
            cert.status = "Ugyldig"
            continue

        if not validate_cert_against_issuer(cert, issuer):
            # Invalid signature on the cert
            cert.status = "Ugyldig"
            continue

        try:
            if not cert.status == "Utgått":
                revoked_date = crls[cert.cdp].get_revoked_date(cert.cert)
                if revoked_date:
                    cert.status = f"Revokert ({revoked_date})"
                if cert.cert.issuer != crls[cert.cdp].crl.issuer:
                    # If the issuer from the crl is not the issuer of the cert, we have a problem
                    cert.status = "Ukjent"
        except KeyError:
            # If the crl is not in the dict, it's must be because be couldn't retrieve it
            cert.status = "Ukjent"


def validate_cert_against_issuer(cert, issuer):
    """Validates a certificate against it's (alleged) issuer"""
    if not cert.cert.issuer == issuer.subject:
        return False
    try:
        issuer.public_key().verify(
            cert.cert.signature,
            cert.cert.tbs_certificate_bytes,
            PKCS1v15(),
            cert.cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False
    else:
        return True


async def query_buypass(search_filter, env):
    """Query Buypass' LDAP server for certificates"""
    api.logger.debug("Starting: Buypass query")
    if env == "test":
        server = "ldap://ldap.test4.buypass.no"
        base = "dc=Buypass,dc=no,CN=Buypass Class 3 Test4"
    else:
        server = "ldap://ldap.buypass.no"
        base = "dc=Buypass,dc=no,CN=Buypass Class 3"

    try:
        result = await do_ldap_search(server, base, search_filter, max_count=5)
    except bonsai.LDAPError:
        api.logger.exception("Could not retrieve certificates from Buypass")
        g.errors.append("Kunne ikke hente sertfikater fra Buypass")
        return []
    else:
        api.logger.debug("Ending: Buypass query")
        return await create_certificate_sets(result, (server, base), env, "Buypass")


async def query_commfides(search_filter, env, cert_type):
    """Query Commfides' LDAP server for certificates"""
    api.logger.debug("Starting: Commfides query")
    if env == "test":
        server = "ldap://ldap.test.commfides.com"
    else:
        server = "ldap://ldap.commfides.com"

    if cert_type == "person":
        # We only search for Person-High because Person-Normal certs just doesn't exist
        base = "ou=Person-High,dc=commfides,dc=com"
    else:
        base = "ou=Enterprise,dc=commfides,dc=com"

    try:
        result = await do_ldap_search(server, base, search_filter)
    except bonsai.LDAPError:
        api.logger.exception("Could not retrieve certificates from Commfides")
        g.errors.append("Kunne ikke hente sertfikater fra Commfides")
        return []
    else:
        api.logger.debug("Ending: Commfides query")
        return await create_certificate_sets(result, (server, base), env, "Commfides")


async def create_certificate_sets(search_results, ldap_params, env, issuer):
    """Takes a ldap response and creates a list of QualifiedCertificateSet"""
    qualified_certs = []
    for result in search_results:
        try:
            qualified_cert = QualifiedCertificate(
                result["userCertificate;binary"][0], str(result.dn), ldap_params
            )
        except KeyError:
            # Commfides have entries in their LDAP without a cert...
            continue
        qualified_certs.append(qualified_cert)

    await get_cert_status(qualified_certs, env)

    cert_sets = separate_certificate_sets(qualified_certs)
    return create_cert_response(cert_sets, issuer)


def create_cert_response(cert_sets, issuer):
    """Creates a response from a list of certificate sets"""
    new_cert_sets = []
    for certs in cert_sets:
        # Commfides issues encryption certs with longer validity than the rest of the
        # certificates in the set, so we shouldn't use that to check the validity of the set.
        # Therefore we try to find a non-encryption cert to use as the "main cert" of the set
        main_cert = certs.get_non_encryption_cert()
        notices = []

        org_number, underenhet = main_cert.get_orgnumber()
        if underenhet:
            notices.append("underenhet")
        if "Ukjent" in main_cert.type:
            notices.append("ukjent")

        cert_set = {}
        cert_set["issuer"] = issuer
        cert_set["valid_from"] = main_cert.cert.not_valid_before.isoformat()
        cert_set["valid_to"] = main_cert.cert.not_valid_after.isoformat()

        # This will be overridden later, if some of the certs are revoked or expired
        cert_set["status"] = main_cert.status

        cert_set["org_number"] = org_number
        cert_set["subject"] = main_cert.print_subject()
        cert_set["notices"] = notices
        cert_set["ldap"] = certs.create_ldap_url()
        cert_set["certificates"] = []

        for cert in certs.certs:
            cert_element = {}
            name, usage = cert.get_display_name()
            cert_element["name"] = name
            cert_info = {}
            cert_info["Bruksområde(r)"] = usage
            cert_info["Serienummer (hex)"] = format(cert.cert.serial_number, "x")
            cert_info["Serienummer (int)"] = str(cert.cert.serial_number)
            # We use SHA1 here since thats what Windows uses
            cert_info["Avtrykk (SHA-1)"] = codecs.encode(
                cert.cert.fingerprint(hashes.SHA1()), "hex"
            ).decode("ascii")
            cert_info["Emne"] = cert.print_subject(full=True)
            cert_info["Utsteder"] = cert.issuer
            cert_info["Gyldig fra"] = cert.cert.not_valid_before.isoformat()
            cert_info["Gyldig til"] = cert.cert.not_valid_after.isoformat()
            cert_info["Nøkkelbruk"] = cert.get_key_usages()
            cert_info["Type"] = cert.type
            cert_info["Status"] = cert.status
            cert_element["info"] = cert_info
            cert_element["certificate"] = base64.b64encode(
                cert.cert.public_bytes(Encoding.DER)
            ).decode("ascii")
            cert_set["certificates"].append(cert_element)

            if "Revokert" in cert.status:
                cert_set["status"] = "Revokert"

        new_cert_sets.append(cert_set)
    return new_cert_sets


def separate_certificate_sets(certs):
    """
    This tries to separate a list with certs into cert lists.

    This is quite hard as there isn't anything that ties the certs together.
    But they (usually?) come right after each other from the LDAP server,
    and the subjects should be the same (except the serialNumber on non-Enterprise
    certs from Commfides) and they should be issued at the same time
    (except encryption certificates from Commfides)... *sigh*
    """
    if not certs:
        return []

    cert_sets, cert_set, cert_set_roles = [], [], []
    counter = 0
    while counter < len(certs):
        cert_roles = certs[counter].get_roles()

        if not cert_set:
            cert_set_roles = cert_roles
        elif (
            # Certificates in a set should have the same subject,
            # so if they differ they are not from the same set
            (cert_set[0].print_subject() != certs[counter].print_subject())
            or
            # Commfides seems to issue the Encryption certificates at a different time than
            # the rest of the certificates in the set, but they should be issued within
            # three days of each other
            (
                (certs[counter].cert.not_valid_before - cert_set[0].cert.not_valid_before).days
                not in range(-3, 4)
            )
            or
            # A set can't contain several certs of the same type
            [i for i in cert_roles if i in cert_set_roles]
        ):
            cert_sets.append(QualifiedCertificateSet(cert_set))
            cert_set = []
            cert_set_roles = cert_roles
        else:
            cert_set_roles += cert_roles

        cert_set.append(certs[counter])
        counter += 1

    cert_sets.append(QualifiedCertificateSet(cert_set))
    return cert_sets


def escape_ldap_query(query):
    """Escapes an ldap query as described in RFC 4515"""
    return (
        query.replace("\\", r"\5c")
        .replace(r"*", r"\2a")
        .replace(r"(", r"\28")
        .replace(r")", r"\29")
        .replace("\x00", r"\00")
    )


async def do_ldap_search(server, base, search_filter, max_count=1):
    """Searches the specified LDAP server after certificates"""
    client = bonsai.LDAPClient(server)
    client.set_credentials("SIMPLE", ("", ""))

    # Buypass caps the result at 20, and doesn't support "normal" paging
    # so to get all the certs we need to do several searches and exclude the
    # certs we have already gotten. The queries get uglier and uglier,
    # so this shouldn't be repeatet too many times
    count = 0
    all_results = []
    org_search_filter = search_filter
    with (await client.connect(is_async=True, timeout=20)) as conn:
        while count < max_count:
            api.logger.debug('Doing search with filter "%s" against "%s"', search_filter, server)
            results = await conn.search(
                base,
                bonsai.LDAPSearchScope.SUBTREE,
                search_filter,
                attrlist=["userCertificate;binary"],
            )
            all_results += results

            if len(results) == 20:
                certs_to_exclude = ""
                for result in results:
                    certs_to_exclude += f"(!({str(result.dn).split(',')[0]}))"
                search_filter = "(&{}{})".format(search_filter, certs_to_exclude)
                count += 1
            else:
                count = max_count + 1

        # If we got 20 on our last (of sevaral) search, there may be more certs out there...
        if len(results) == 20 and max_count > 1:
            api.logger.warning(
                "Exceeded max count for search with filter %s against %s", org_search_filter, server
            )
            g.errors.append(
                "Det er mulig noen gamle sertifikater ikke vises, "
                "da søket returnerte for mange resultater"
            )

    return all_results


def validate_query(env, cert_type, query):
    """Validates the query from the client"""
    if env not in ["prod", "test"]:
        raise ClientError({"error": "Unknown environment"})
    if cert_type not in ["enterprise", "person"]:
        raise ClientError({"error": "Unknown certificate type"})
    if not query:
        raise ClientError({"error": "Missing query parameter"})


@api.errorhandler(ClientError)
def handle_client_error(error):
    """Handles requests from client that does not validate."""
    response = jsonify(error.args[0])
    response.status_code = 400
    return response


@api.errorhandler(Exception)
def handle_unexpected_error(_):
    """Handles errors that's not caught. Logs the exception and returns a generic error message"""
    api.logger.exception("An exception occured:")
    response = jsonify({"error": "En ukjent feil oppstod. Vennligst prøv igjen."})
    response.status_code = 500
    return response


@api.route("/api", methods=["GET"])
async def api_endpoint():
    """Handles requests to /api"""
    g.errors = []
    env, cert_type, query = [request.args.get(key) for key in ["env", "type", "query"]]
    validate_query(env, cert_type, query)

    # If the query is an organization number, or an norwegian personal serial number,
    # we search in the serialNumber field, otherwise the commonName field
    if cert_type == "enterprise" and ORG_NUMBER_REGEX.fullmatch(query):
        search_filter = r"(serialNumber=%s)" % query.replace(" ", "")
        org_number_search = True
    elif cert_type == "person" and PERSONAL_SERIAL_REGEX.fullmatch(query):
        search_filter = f"(serialNumber={query})"
        org_number_search = False
    else:
        search_filter = r"(cn=%s)" % escape_ldap_query(query)
        org_number_search = False

    certificate_sets = []
    ldap_responses = await asyncio.gather(
        query_buypass(search_filter, env), query_commfides(search_filter, env, cert_type)
    )

    for finsihed_task in ldap_responses:
        certificate_sets.extend(finsihed_task)

    certificate_sets.sort(key=itemgetter("valid_from"), reverse=True)

    response_content = {}
    # If we search for an org number, we take the org name from the
    # certs as subject, so we don't have to bother brreg unnecessary
    # if not, we just return the query
    if org_number_search and certificate_sets:
        subject = certificate_sets[0]["subject"].split(",")
        try:
            org_name = [part.split("=")[1] for part in subject if part.startswith(" O=")][0]
        except IndexError:
            response_content["subject"] = query
        else:
            response_content["subject"] = "{} ({})".format(org_name, query)
    else:
        response_content["subject"] = query

    response_content["errors"] = g.errors
    response_content["certificate_sets"] = certificate_sets
    response = jsonify(response_content)

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, s-maxage=0"
    return response


if __name__ == "__main__":
    # For development
    api.run(host="127.0.0.1", port=7000)
