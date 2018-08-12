import base64
import codecs
import urllib.parse
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature


from .utils import get_subject_order, stringify_x509_name
from .constants import (
    KNOWN_CERT_TYPES,
    ORG_NUMBER_REGEX,
    UNDERENHET_REGEX,
    SUBJECT_FIELDS,
    KEY_USAGES,
)


class QualifiedCertificate:
    """Represents a Norwegian Qualified Certificate"""

    def __init__(self, cert, dn, ldap_params):
        self.cert = x509.load_der_x509_certificate(cert, default_backend())

        self.issuer = stringify_x509_name(self.cert.issuer)
        self.type = self._get_type()
        self.dn = dn
        self.ldap_params = ldap_params
        self.status = "Ukjent"

    @classmethod
    async def create(cls, raw_cert, dn, ldap_params, crl_retriever, cert_retriever):

        cert = cls(raw_cert, dn, ldap_params)

        issuer = cert_retriever.retrieve(cert.issuer)
        if not issuer:
            cert.status = "Ukjent"
        elif not cert._validate_against_issuer(issuer):
            cert.status = "Ugyldig"
        elif not cert._check_date():
            cert.status = "Utgått"
        else:
            crl = await crl_retriever.retrieve(cert._get_http_cdp(), issuer)
            if not crl:
                cert.status = "Ukjent"
            else:
                revoked_cert = crl.get_revoked_certificate_by_serial_number(
                    cert.cert.serial_number
                )
                if revoked_cert:
                    cert.status = f"Revokert ({revoked_cert.revocation_date})"
                else:
                    cert.status = "OK"
        return cert

    def _check_date(self):
        """Returns whether the certificate is valid wrt. the dates"""
        return (
            self.cert.not_valid_after > datetime.utcnow()
            and self.cert.not_valid_before < datetime.utcnow()
        )

    def _validate_against_issuer(self, issuer: x509.Certificate) -> bool:
        """Validates a certificate against it's (alleged) issuer"""

        if not self.cert.issuer == issuer.subject:
            return False
        try:
            issuer.public_key().verify(
                self.cert.signature,
                self.cert.tbs_certificate_bytes,
                PKCS1v15(),
                self.cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False
        else:
            return True

    def _get_type(self) -> str:
        """Returns the type of certificate, based on issuer and Policy OID"""
        cert_policies = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("2.5.29.32")
        ).value

        for policy in cert_policies:
            try:
                oid = policy.policy_identifier.dotted_string
                return KNOWN_CERT_TYPES[(self.issuer, oid)][1]
            except KeyError:
                pass

        # This will only display the last OID, out of potentially several, but good enough
        return "Ukjent (oid: {})".format(oid)

    def _get_http_cdp(self) -> Optional[str]:
        """Returns the first CRL Distribution Point from the cert with http scheme, if any"""
        cdps = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("2.5.29.31")
        ).value
        for cdp in cdps:
            url = urllib.parse.urlparse(cdp.full_name[0].value)
            if url.scheme == "http":
                return cdp.full_name[0].value
        return None

    def get_roles(self) -> List[str]:
        """
        A set of Norwegian qualified certificates should have certificates intended for
        *) Encryption
        *) Signature
        *) Authentication

        Several roles can be placed on one certificate (Buypass does this).

        This function returns which role(s) this certificate has.
        """
        cert_roles = []
        key_usage = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        if key_usage.digital_signature:
            cert_roles.append("auth")
        if key_usage.content_commitment:
            cert_roles.append("sign")
        if key_usage.data_encipherment:
            cert_roles.append("crypt")
        return cert_roles

    def print_subject(self, full: bool = False) -> str:
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
                if "Commfides" in self.issuer and not ORG_NUMBER_REGEX.fullmatch(
                    field.value
                ):
                    continue
            try:
                subject.append(
                    "{}={}".format(SUBJECT_FIELDS[field.oid.dotted_string], field.value)
                )
            except KeyError:
                # If we don't recognize the field, we just print the dotted string
                subject.append("{}={}".format(field.oid.dotted_string, field.value))

        # If not full (e.g. used for pretty printing), we order the fields in an uniform order
        if not full:
            subject.sort(key=get_subject_order)
        return ", ".join(list(subject))

    def get_orgnumber(self) -> Tuple[Optional[str], bool]:
        """
        Gets the organization number from the cert,
        and returns the organization number + if it's an "underenhet"
        """
        serial_number = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[
            0
        ].value

        if not ORG_NUMBER_REGEX.fullmatch(serial_number):
            # personal cert
            return None, False

        try:
            ou_field = self.cert.subject.get_attributes_for_oid(
                NameOID.ORGANIZATIONAL_UNIT_NAME
            )[0].value
        except IndexError:
            return serial_number, False

        ou_number = UNDERENHET_REGEX.search(ou_field)

        if ou_number and serial_number != ou_number[0]:
            return ou_number[0], True

        return serial_number, False

    def get_display_name(self) -> Tuple[str, str]:
        """
        Examines the key usage bits in the certificate
        and returns the appropriate Norwegian name and application for it
        """
        key_usage = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        if key_usage.content_commitment:
            return "Signeringssertifikat", "Signering"
        elif key_usage.data_encipherment and key_usage.digital_signature:
            return "Krypteringssertifikat", "Kryptering og autentisering"
        elif key_usage.data_encipherment:
            return "Krypteringssertifikat", "Kryptering"
        elif key_usage.digital_signature:
            return "Autentiseringssertifikat", "Autentisering"
        return "Ukjent", "Ukjent"

    def get_key_usages(self) -> str:
        """Returns a string with the key usages from the cert"""
        key_usages = []
        for key_usage in KEY_USAGES:
            if getattr(
                self.cert.extensions.get_extension_for_oid(
                    ExtensionOID.KEY_USAGE
                ).value,
                key_usage[0],
            ):
                key_usages.append(key_usage[1])
        return ", ".join(key_usages)

    def dump(self) -> Dict:
        """Creates a dict from the object, for json serialization"""
        dumped: Dict[str, Union[str, Dict[str, str]]] = {}
        name, usage = self.get_display_name()
        dumped["name"] = name
        info = {}
        info["Bruksområde(r)"] = usage
        info["Serienummer (hex)"] = format(self.cert.serial_number, "x")
        info["Serienummer (int)"] = str(self.cert.serial_number)

        # We use SHA1 here since thats what Windows uses
        info["Avtrykk (SHA-1)"] = codecs.encode(
            self.cert.fingerprint(hashes.SHA1()), "hex"
        ).decode("ascii")
        info["Emne"] = self.print_subject(full=True)
        info["Utsteder"] = self.issuer
        info["Gyldig fra"] = self.cert.not_valid_before.isoformat()
        info["Gyldig til"] = self.cert.not_valid_after.isoformat()
        info["Nøkkelbruk"] = self.get_key_usages()
        info["Type"] = self.type
        info["Status"] = self.status
        dumped["info"] = info
        dumped["certificate"] = base64.b64encode(
            self.cert.public_bytes(Encoding.DER)
        ).decode("ascii")

        return dumped


class QualifiedCertificateSet(object):
    """Represents a set of Norwegian qualified certificates"""

    def __init__(self, certs):
        self.certs = certs

    @classmethod
    def create_sets_from_certs(
        cls, certs: List[QualifiedCertificate]
    ) -> List["QualifiedCertificateSet"]:
        """
        This creates a list of QualifiedCertificateSet
        from a list of QualifiedCertificate.

        This is quite hard as there isn't anything that ties the certs together.
        But they (usually?) come right after each other from the LDAP server,
        and the subjects should be the same (except the serialNumber on non-Enterprise
        certs from Commfides) and they should be issued at the same time
        (except encryption certificates from Commfides)... *sigh*
        """
        if not certs:
            return []

        cert_sets: List[QualifiedCertificateSet] = []
        cert_set: List[QualifiedCertificate] = []
        cert_set_roles: List[str] = []

        counter = 0
        while counter < len(certs):

            cert = certs[counter]
            cert_roles = cert.get_roles()

            if not cert_set:
                cert_set_roles = cert_roles
            elif (
                # Certificates in a set should have the same subject,
                # so if they differ they are not from the same set
                (cert_set[0].print_subject() != cert.print_subject())
                or
                # Commfides seems to issue the Encryption certificates at a different time than
                # the rest of the certificates in the set, but they should be issued within
                # three days of each other
                (
                    (
                        cert.cert.not_valid_before - cert_set[0].cert.not_valid_before
                    ).days
                    not in range(-3, 4)
                )
                or
                # A set can't contain several certs of the same type
                [i for i in cert_roles if i in cert_set_roles]
            ):
                cert_sets.append(cls(cert_set))
                cert_set = []
                cert_set_roles = cert_roles
            else:
                cert_set_roles += cert_roles

            cert_set.append(cert)
            counter += 1

        cert_sets.append(cls(cert_set))
        return cert_sets

    def _get_non_encryption_cert(self) -> QualifiedCertificate:
        """
        This tries to find an non-encryption certificate in the certificate set and return that

        If none is found, the first cert in the set is returned
        """
        for cert in self.certs:
            key_usage = cert.cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            if not key_usage.data_encipherment:
                return cert
        return self.certs[0]

    def _create_ldap_url(self) -> str:
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

    def dump(self):
        """Creates a dict from the object, for json serialization"""
        dumped = {}
        # Commfides issues encryption certs with longer validity than the rest of the
        # certificates in the set, so we shouldn't use that to check the validity of the set.
        # Therefore we try to find a non-encryption cert to use as the "main cert" of the set
        main_cert = self._get_non_encryption_cert()
        org_number, underenhet = main_cert.get_orgnumber()

        dumped["notices"] = []
        if underenhet:
            dumped["notices"].append("underenhet")
        if "Ukjent" in main_cert.type:
            dumped["notices"].append("ukjent")

        if "Buypass" in main_cert.issuer:
            dumped["issuer"] = "Buypass"
        elif "Commfides" in main_cert.issuer:
            dumped["issuer"] = "Commfides"
        else:
            dumped["issuer"] = main_cert.isseru

        dumped["valid_from"] = main_cert.cert.not_valid_before.isoformat()
        dumped["valid_to"] = main_cert.cert.not_valid_after.isoformat()

        # This will be overridden later, if some of the certs are revoked or expired
        dumped["status"] = main_cert.status

        dumped["org_number"] = org_number
        dumped["subject"] = main_cert.print_subject()
        dumped["ldap"] = self._create_ldap_url()
        dumped["certificates"] = []
        for cert in self.certs:
            if "Revokert" in cert.status:
                dumped["status"] = "Revokert"

            dumped["certificates"].append(cert.dump())

        return dumped
