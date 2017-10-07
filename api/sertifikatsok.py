"""The API behind sertifikatsok.no"""
import re
import base64
import codecs
import logging
import urllib.parse
from datetime import datetime
from operator import itemgetter

import ldap
import ldap.filter
import requests

from flask import g
from flask import Flask
from flask import jsonify
from flask import request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature


api = Flask(__name__)

ORG_NUMBER_REGEX = re.compile(r'\d{9}')
UNDERENHET_REGEX = re.compile(r'.*-\d{9}$')

# Known issuer/PolicyOID combinations
KNOWN_CERT_TYPES = {
    ('CN=Buypass Class 3 Test4 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.0.3.2'): 'Buypass TEST virksomhetssertifikat',

    # Have no source for this, just a guess based on the prod oid
    ('CN=Buypass Class 3 Test4 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.0.3.5'): 'Buypass TEST virksomhetssertifikat (fysisk token)',

    ('CN=Buypass Class 3 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.2'): 'Buypass virksomhetssertifikat',

    ('CN=Buypass Class 3 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.5'): 'Buypass virksomhetssertifikat (fysisk token)',

    ('CN=Buypass Class 3 Test4 CA 1, O=Buypass, C=NO',
     '2.16.578.1.26.1.0.3.2'): 'Buypass TEST virksomhetssertifikat',

    # Have no source for this, just a guess based on the prod oid
    ('CN=Buypass Class 3 Test4 CA 1, O=Buypass, C=NO',
     '2.16.578.1.26.1.0.3.5'): 'Buypass TEST virksomhetssertifikat (fysisk token)',

    ('CN=Buypass Class 3 CA 1, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.2'): 'Buypass virksomhetssertifikat',

    ('CN=Buypass Class 3 CA 1, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.5'): 'Buypass virksomhetssertifikat (fysisk token)',

    ('CN=Buypass Class 3 Test4 CA 1, O=Buypass, C=NO',
     '2.16.578.1.26.1.0'): 'Buypass TEST person-sertifikat',

    ('CN=Buypass Class 3 CA 1, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.1'): 'Buypass person-sertifikat',

    ('CN=Buypass Class 3 Test4 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.0'): 'Buypass TEST person-sertifikat',

    ('CN=Buypass Class 3 CA 3, O=Buypass AS-983163327, C=NO',
     '2.16.578.1.26.1.3.1'): 'Buypass person-sertifikat',

    ('CN=CPN Enterprise SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 '
     'Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.13.1.1.0'): 'Commfides virksomhetssertifikat',

    ('CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST, OU=Commfides Trust Environment(C) '
     '2014 Commfides Norge AS - TEST, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.913.1.1.0'): 'Commfides TEST virksomhetssertifikat',

    ('CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST2, OU=Commfides Trust Environment(C) '
     '2014 Commfides Norge AS - TEST, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.913.1.1.0'): 'Commfides TEST virksomhetssertifikat',

    ('CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 '
     'Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.12.1.1.0'): 'Commfides person-sertifikat',

    # Commfides uses 2.16.578.1.29.12.1.1.1 as PolicyOID on new Person-High certificates,
    # but it is not documented in their CP/CPS ¯\_(ツ)_/¯
    ('CN=CPN Person High SHA256 CLASS 3, OU=Commfides Trust Environment (c) 2011 '
     'Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.12.1.1.1'): 'Commfides person-sertifikat',

    ('CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 '
     'Commfides Norge AS - TEST, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.912.1.1.0'): 'Commfides TEST person-sertifikat',

    ('CN=Commfides CPN Person-High SHA256 CA - TEST, OU=Commfides Trust Environment(C) 2014 '
     'Commfides Norge AS - TEST, O=Commfides Norge AS - 988 312 495, C=NO',
     '2.16.578.1.29.912.1.1.1'): 'Commfides TEST person-sertifikat'
}

SUBJECT_FIELDS = [('COUNTRY_NAME', 'C'), ('STATE_OR_PROVINCE_NAME', 'ST'),
                  ('LOCALITY_NAME', 'L'), ('ORGANIZATION_NAME', 'O'),
                  ('ORGANIZATIONAL_UNIT_NAME', 'OU'), ('COMMON_NAME', 'CN'),
                  ('EMAIL_ADDRESS', 'email'), ('SERIAL_NUMBER', 'serialNumber')]

KEY_USAGES = [('digital_signature', 'Digital signature'),
              # Using Non-repudiation as it's the established name
              ('content_commitment', 'Non-repudiation'),
              ('key_encipherment', 'Key encipherment'),
              ('data_encipherment', 'Data encipherment'),
              ('key_agreement', 'Key agreement'),
              ('key_cert_sign', 'Certificate signing'),
              ('crl_sign', 'CRL signing')]

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
            self.status = 'OK'
        else:
            self.cdp = None
            self.status = 'Utgått'

    def _check_date(self):
        """Returns whether the certificate is valid wrt. the dates"""
        return (self.cert.not_valid_after > datetime.utcnow() and
                self.cert.not_valid_before < datetime.utcnow())

    def _get_type(self):
        """Returns the type of certificate, based on issuer and Policy OID"""
        cert_policies = self.cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier('2.5.29.32')).value

        for policy in cert_policies:
            try:
                oid = policy.policy_identifier.dotted_string
                return KNOWN_CERT_TYPES[(self.issuer, oid)]
            except KeyError:
                pass

        # This will only display the last OID, out of potentially several, but good enough
        return 'Ukjent (oid: {})'.format(oid)

    def _get_http_cdp(self):
        """Returns the first CRL Distribution Point from the cert with http scheme, if any"""
        cdps = self.cert.extensions.get_extension_for_oid(x509.ObjectIdentifier('2.5.29.31')).value
        for cdp in cdps:
            url = urllib.parse.urlparse(cdp.full_name[0].value)
            if url.scheme == 'http':
                return cdp.full_name[0].value
        return None

    def count_keyusage(self):
        """
        A set of Norwegian qualified certificates should have certificates intended for
        *) Encryption
        *) Signature
        *) Authentication

        Several roles can be placed on one certificate (Buypass does this).

        This function returns how many roles this certificate has.
        """
        count = 0
        key_usage = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.digital_signature:
            count += 1
        if key_usage.content_commitment:
            count += 1
        if key_usage.data_encipherment:
            count += 1
        return count

    def print_subject(self, full=False):
        """
        Returns the subject of the cert as a string.
        If it's an non-Enterprise Commfides certificate (indicated by an organization number in the
        serialNumber field) the serialNumber field is skipped, unless 'full' is True.

        This is becuase Commfides generates random serialNumbers for all Person certificates,
        so they are not very useful and also different within a set
        """
        subject = []
        for field_combo in SUBJECT_FIELDS:
            name_oid = getattr(NameOID, field_combo[0])
            field_value = self.cert.subject.get_attributes_for_oid(name_oid)
            if field_combo[0] == 'SERIAL_NUMBER':
                if ('Commfides' in self.issuer and not full
                        and not ORG_NUMBER_REGEX.fullmatch(field_value[0].value)):
                    continue
            if field_value:
                subject.append('%s=%s' % (field_combo[1], field_value[0].value))
        return ', '.join(list(reversed(subject)))

    def _print_issuer(self):
        """
        Returns the issuer of the cert as a string.
        """
        subject = []
        for field_combo in SUBJECT_FIELDS:
            name_oid = getattr(NameOID, field_combo[0])
            field_value = self.cert.issuer.get_attributes_for_oid(name_oid)
            if field_value:
                subject.append('%s=%s' % (field_combo[1], field_value[0].value))
        return ', '.join(list(reversed(subject)))

    def is_issued_to_underenhet(self):
        """
        Checks if the certificate is issued to an 'underenhet'

        This is indicated by the presence of an nine-digit number in the OU field
        (this is not in the Norwegian Qualified certificate standard,
        but has become a common practice for Buypass)
        """
        try:
            ou_field = self.cert.subject.get_attributes_for_oid(
                NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        except IndexError:
            return False
        return bool(UNDERENHET_REGEX.search(ou_field))

    def get_display_name(self):
        """
        Examines the key usage bits in the certificate
        and returns the appropriate Norwegian name and application for it
        """
        key_usage = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.content_commitment:
            return 'Signeringssertifikat', 'Signering'
        elif key_usage.data_encipherment and key_usage.digital_signature:
            return 'Krypteringssertifikat', 'Kryptering og autentisering'
        elif key_usage.data_encipherment:
            return 'Krypteringssertifikat', 'Kryptering'
        elif key_usage.digital_signature:
            return 'Autentiseringssertifikat', 'Autentisering'
        return 'Ukjent', 'Ukjent'

    def get_key_usages(self):
        """Returns a string with the key usages from the cert"""
        key_usages = []
        for key_usage in KEY_USAGES:
            if getattr(self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
                       key_usage[0]):
                key_usages.append(key_usage[1])
        return ', '.join(key_usages)

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
            filter_parts.append(cert.dn.split(',')[0])
        ldap_filter = ')('.join(filter_parts)
        ldap_url = '{}/{}?usercertificate;binary?sub?(|({}))'.format(
            self.certs[0].ldap_params[0],
            urllib.parse.quote(self.certs[0].ldap_params[1], safe='=,'),
            ldap_filter)
        return ldap_url

def get_issuer_cert(issuer, env):
    """Retrieves the issuer certificate from file, if we have it"""
    filename = './certs/{}/{}.pem'.format(env, urllib.parse.quote_plus(issuer))
    try:
        with open(filename, 'rb') as open_file:
            issuer_bytes = open_file.read()
    except FileNotFoundError:
        api.logger.warning('Could not find cert %s on disk', issuer)
        return None
    return x509.load_pem_x509_certificate(issuer_bytes, default_backend())

def get_crl(url, valid_issuers):
    """Retrieves the CRl from disk, or optionally, downloads it"""
    filename = './crls/{}'.format(urllib.parse.quote_plus(url))
    try:
        with open(filename, 'rb') as open_file:
            crl_bytes = open_file.read()
        fresh = False
    except FileNotFoundError:
        crl_bytes = download_crl(url)
        fresh = True

    crl = x509.load_der_x509_crl(crl_bytes, default_backend())

    if not validate_crl(crl, valid_issuers):
        if fresh:
            raise CouldNotGetValidCRLError
        else:
            # Our copy on disk was not valid. Try to download it again
            crl_bytes = download_crl(url)
            crl = x509.load_der_x509_crl(crl_bytes, default_backend())
            if not validate_crl(crl, valid_issuers):
                raise CouldNotGetValidCRLError
    return crl

def validate_crl(crl, valid_issuers):
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
            crl.signature,
            crl.tbs_certlist_bytes,
            PKCS1v15(),
            crl.signature_hash_algorithm
        )
    except InvalidSignature:
        return False
    return True

def download_crl(url):
    """Downloads a crl from the specified url"""
    headers = {'user-agent': 'sertifikatsok.no'}
    filename = './crls/{}'.format(urllib.parse.quote_plus(url))
    api.logger.info('Downloading CRL %s', url)
    try:
        r = requests.get(url, headers=headers, timeout=5)
    except requests.exceptions.ConnectionError as error:
        raise CouldNotGetValidCRLError('Could not retrieve CRL: {}'.format(error))

    if r.status_code != 200:
        raise CouldNotGetValidCRLError('Got status code {} for url {}'.format(r.status_code, url))

    if r.headers['Content-Type'] not in ('application/pkix-crl', 'application/x-pkcs7-crl'):
        raise CouldNotGetValidCRLError('Got content type: {} for url {}'
                                       .format(r.headers['Content-Type'], url))

    with open(filename, 'wb') as open_file:
        open_file.write(r.content)

    return r.content

def get_cert_status(certs, env):
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
            crls[url] = get_crl(url, loaded_issuers)
        except CouldNotGetValidCRLError:
            g.errors.append('Kunne ikke hente ned gyldig CRL fra {}. '
                            'Revokeringsstatus er derfor ukjent for noen sertifikater.'.format(url))

    # retrieve all the revoked certificates from the crls
    revoked_certs = {}
    for crl in crls:
        revoked_certs[crl] = [revoked_cert.serial_number for revoked_cert in crls[crl]]

    # validate all the certs against the issuers and the crls
    for cert in certs:
        try:
            issuer = loaded_issuers[cert.cert.issuer]
        except KeyError:
            # We don't have the cert in our truststore...
            cert.status = 'Ugyldig'
            continue

        if not validate_cert_against_issuer(cert, issuer):
            # Invalid signature on the cert
            cert.status = 'Ugyldig'
            continue

        try:
            if not cert.status == 'Utgått':
                if cert.cert.serial in revoked_certs[cert.cdp]:
                    cert.status = 'Revokert'
                if cert.cert.issuer != crls[cert.cdp].issuer:
                    # If the issuer from the crl is not the issuer of the cert, we have a problem
                    cert.status = 'Ukjent'
        except KeyError:
            # If the crl is not in the dict, it's must be because be couldn't retrieve it
            cert.status = 'Ukjent'

def validate_cert_against_issuer(cert, issuer):
    """Validates a certificate against it's (alleged) issuer"""
    if not cert.cert.issuer == issuer.subject:
        return False
    try:
        issuer.public_key().verify(
            cert.cert.signature,
            cert.cert.tbs_certificate_bytes,
            PKCS1v15(),
            cert.cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False
    else:
        return True

def query_buypass(search_filter, env):
    """Query Buypass' LDAP server for certificates"""
    if env == 'test':
        server = 'ldap://ldap.test4.buypass.no'
        base = "dc=Buypass,dc=no,CN=Buypass Class 3 Test4"
    else:
        server = 'ldap://ldap.buypass.no'
        base = "dc=Buypass,dc=no,CN=Buypass Class 3"

    try:
        result = do_ldap_search(server, base, search_filter)
    except ldap.SERVER_DOWN:
        g.errors.append('Kunne ikke hente sertfikater fra Buypass')
        return []
    else:
        return create_certificate_sets(result, (server, base), env, 'Buypass')

def query_commfides(search_filter, env, cert_type):
    """Query Commfides' LDAP server for certificates"""
    if env == 'test':
        server = 'ldap://ldap.test.commfides.com'
    else:
        server = 'ldap://ldap.commfides.com'

    if cert_type == 'person':
        # We only search for Person-High because Person-Normal certs just doesn't exist
        base = 'ou=Person-High,dc=commfides,dc=com'
    else:
        base = 'ou=Enterprise,dc=commfides,dc=com'

    try:
        result = do_ldap_search(server, base, search_filter)
    except ldap.SERVER_DOWN:
        g.errors.append('Kunne ikke hente sertfikater fra Commfides')
        return []
    else:
        return create_certificate_sets(result, (server, base), env, 'Commfides')

def create_certificate_sets(search_results, ldap_params, env, issuer):
    """Takes a ldap response and creates a list of QualifiedCertificateSet"""
    qualified_certs = []
    for result in search_results:
        try:
            qualified_cert = QualifiedCertificate(
                result[1]['userCertificate;binary'][0],
                result[0],
                ldap_params)
        except KeyError:
            # Commfides have entries in their LDAP without a cert...
            continue
        qualified_certs.append(qualified_cert)

    get_cert_status(qualified_certs, env)

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

        if main_cert.is_issued_to_underenhet():
            notices.append('underenhet')
        if 'Ukjent' in main_cert.type:
            notices.append('ukjent')

        cert_set = {}
        cert_set['issuer'] = issuer
        cert_set['valid_from'] = main_cert.cert.not_valid_before.isoformat()
        cert_set['valid_to'] = main_cert.cert.not_valid_after.isoformat()

        # This will be overridden later, if some of the certs are revoked or expired
        cert_set['status'] = main_cert.status

        cert_set['subject'] = main_cert.print_subject()
        cert_set['notices'] = notices
        cert_set['ldap'] = certs.create_ldap_url()
        cert_set['certificates'] = []

        for cert in certs.certs:
            cert_element = {}
            name, usage = cert.get_display_name()
            cert_element['name'] = name
            cert_info = {}
            cert_info['Bruksområde(r)'] = usage
            cert_info['Serienummer (hex)'] = format(cert.cert.serial, 'x')
            cert_info['Serienummer (int)'] = str(cert.cert.serial)
            # We use SHA1 here since thats what Windows uses
            cert_info['Avtrykk (SHA-1)'] = codecs.encode(
                cert.cert.fingerprint(hashes.SHA1()), 'hex').decode('ascii')
            cert_info['Emne'] = cert.print_subject(full=True)
            cert_info['Utsteder'] = cert.issuer
            cert_info['Gyldig fra'] = cert.cert.not_valid_before.isoformat()
            cert_info['Gyldig til'] = cert.cert.not_valid_after.isoformat()
            cert_info['Nøkkelbruk'] = cert.get_key_usages()
            cert_info['Type'] = cert.type
            cert_info['Status'] = cert.status
            cert_element['info'] = cert_info
            cert_element['certificate'] = base64.b64encode(
                cert.cert.public_bytes(Encoding.DER)).decode('ascii')
            cert_set['certificates'].append(cert_element)

            if cert.status == 'Revokert':
                cert_set['status'] = "Revokert"

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
    cert_sets, cert_set = [], []
    cert_type_count = counter = 0
    if not certs:
        return []
    while counter < len(certs):
        if not cert_set:
            cert_set.append(certs[counter])
            cert_type_count += certs[counter].count_keyusage()
        else:
            # Certificates in a set should have the same subject,
            # so if they differ they are not from the same set
            if cert_set[0].print_subject() != certs[counter].print_subject():
                cert_sets.append(QualifiedCertificateSet(cert_set))
                cert_set = []
                cert_type_count = certs[counter].count_keyusage()
            # Commfides seems to issue the Encryption certificates at a different time than the
            # rest of the certificates in the set (maybe because they need to backup that key?).
            # But they should be issued within three days of each other
            elif (certs[counter].cert.not_valid_before
                  - cert_set[0].cert.not_valid_before).days > 3:
                cert_sets.append(QualifiedCertificateSet(cert_set))
                cert_set = []
                cert_type_count = certs[counter].count_keyusage()
            else:
                # There are three types of Norwegian Qualified Certificates
                # so there can only be three roles in a set
                if cert_type_count < 3:
                    cert_type_count += certs[counter].count_keyusage()
                else:
                    cert_sets.append(QualifiedCertificateSet(cert_set))
                    cert_set = []
                    cert_type_count = certs[counter].count_keyusage()
            cert_set.append(certs[counter])
        counter += 1
    cert_sets.append(QualifiedCertificateSet(cert_set))
    return cert_sets

def do_ldap_search(server, base, search_filter):
    """Searches the specified LDAP server after certificates"""
    # TODO: paging for Buypass?
    conn = ldap.initialize(server)
    conn.protocol_version = 3
    # 5 seconds to connect to the ldap server, and 20 to return the response
    conn.set_option(ldap.OPT_TIMELIMIT, 20)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
    conn.simple_bind_s('', '')
    result = conn.search_ext_s(
        base,
        ldap.SCOPE_SUBTREE,
        search_filter,
        attrlist=['userCertificate;binary'],
        serverctrls=None
    )
    conn.unbind_s()
    return result

def validate_query(env, cert_type, query):
    """Validates the query from the client"""
    if env not in ['prod', 'test']:
        raise ClientError({'error':'Unknown environment'})
    if cert_type not in ['enterprise', 'person']:
        raise ClientError({'error':'Unknown certificate type'})
    if not query:
        raise ClientError({'error':'Missing query parameter'})

@api.errorhandler(ClientError)
def handle_client_error(error):
    """Handles requests from client that does not validate."""
    response = jsonify(error.args[0])
    response.status_code = 400
    return response

@api.errorhandler(Exception)
def handle_unexpected_error(_):
    """Handles errors that's not caught. Logs the exception and returns a generic error message"""
    api.logger.exception('An exception occured:')
    response = jsonify({'error':'En ukjent feil oppstod. Vennligst prøv igjen.'})
    response.status_code = 500
    return response

@api.route("/api", methods=['GET'])
def api_endpoint():
    """Handles requests to /api"""
    g.errors = []
    env, cert_type, query = [request.args.get(key) for key in ['env', 'type', 'query']]
    validate_query(env, cert_type, query)

    # If the query is an organization number we search in the serialNumber field,
    # otherwise the commonName field
    if cert_type == 'enterprise' and ORG_NUMBER_REGEX.fullmatch(query):
        search_filter = r'(serialNumber=%s)' % query
        org_number_search = True
    else:
        search_filter = r'(cn=%s)' % ldap.filter.escape_filter_chars(query)
        org_number_search = False

    # TODO: do the searches in paralell?
    certificate_sets = []
    certificate_sets.extend(query_buypass(search_filter, env))
    certificate_sets.extend(query_commfides(search_filter, env, cert_type))
    certificate_sets.sort(key=itemgetter('valid_from'), reverse=True)

    response_content = {}
    # If we search for an org number, we take the org name from the
    # certs as subject, so we don't have to bother brreg unnecessary
    # if not, we just return the query
    if org_number_search and certificate_sets:
        subject = certificate_sets[0]['subject'].split(',')
        try:
            org_name = [part.split('=')[1] for part in subject if part.startswith(' O=')][0]
        except IndexError:
            response_content['subject'] = query
        else:
            response_content['subject'] = '{} ({})'.format(org_name, query)
    else:
        response_content['subject'] = query

    response_content['errors'] = g.errors
    response_content['certificate_sets'] = certificate_sets
    response = jsonify(response_content)

    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, s-maxage=0'
    return response

if __name__ == "__main__":
    # For development
    api.run(host='127.0.0.1', port=7000)
