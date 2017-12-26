"""Tests for the sertifikatsok api"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import sertifikatsok

def _generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

def _gen_cert(**kwargs):
    """Generates a self signed dummy certificate for testing"""
    not_before = kwargs.pop('not_before', datetime.datetime.now())
    common_name = kwargs.pop('cn', 'cn')
    ou = kwargs.pop('ou', 'ou')
    sign = kwargs.pop('sign', False)
    crypt = kwargs.pop('crypt', False)
    auth = kwargs.pop('auth', False)
    sn = kwargs.pop('sn', '1234')

    key = _generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NO"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Watn IT System"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, sn),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_before + datetime.timedelta(days=10)
    ).add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                x509.ObjectIdentifier('2.16.578.1.26.1.0.3.2'), None)]),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            digital_signature=auth,
            content_commitment=sign,
            key_encipherment=crypt,
            data_encipherment=crypt,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.DER)

def _gen_qcert(**kwargs):
    """Generates a QualifiedCertificate"""
    ldap_params = kwargs.pop('ldap_params', '')
    dn = kwargs.pop('dn', '')

    cert = _gen_cert(**kwargs)
    return sertifikatsok.QualifiedCertificate(cert, dn, ldap_params)


def test_subject_order():
    assert sertifikatsok.subject_order('serialNumber=123') == 0
    assert sertifikatsok.subject_order('C=NO') == 7
    assert sertifikatsok.subject_order('oggabogga=123') == 8

def test_get_prod_issuer_cert_ok():
    """Tests that we can retrieve a known prod issuer OK"""
    issuer = sertifikatsok.get_issuer_cert(
        'C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 CA 3', 'prod')
    assert (issuer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == 'Buypass Class 3 CA 3')

def test_get_test_issuer_cert_ok():
    """Tests that we can retrieve a known test issuer OK"""
    issuer = sertifikatsok.get_issuer_cert(
        'C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3', 'test')
    assert (issuer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == 'Buypass Class 3 Test4 CA 3')

def test_get_test_issuer_from_prod():
    """Tests that retrival of a test issuer from prod will fail"""
    issuer = sertifikatsok.get_issuer_cert(
        'C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 CA 3', 'prod')
    assert issuer is None

def test_get_issuer_cert_fail():
    """Tests that we can't retrieve an unknown issuer"""
    issuer = sertifikatsok.get_issuer_cert('CN=Magnus TEST CA', 'prod')
    assert issuer is None

def test_is_issued_to_underenhet():
    """
    Certs with a continuous nine digit number in the OU field
    should be marked as issued to an underenhet
    """
    cert1 = _gen_qcert(ou='124738043')
    cert2 = _gen_qcert(ou='Underenhet 124738043')
    cert3 = _gen_qcert(ou='Underenhet-124738043')
    cert4 = _gen_qcert(ou='Underenhet-1247380433')
    cert5 = _gen_qcert(ou='Underenhet-12473804')
    cert6 = _gen_qcert()

    assert cert1.is_issued_to_underenhet() is True
    assert cert2.is_issued_to_underenhet() is True
    assert cert3.is_issued_to_underenhet() is True
    assert cert4.is_issued_to_underenhet() is False
    assert cert5.is_issued_to_underenhet() is False
    assert cert6.is_issued_to_underenhet() is False

def test_auth_cert():
    """Test that an authentication cert is identified as such"""
    cert = _gen_qcert(auth=True)
    assert cert.get_display_name() == ('Autentiseringssertifikat', 'Autentisering')
    assert cert.get_key_usages() == 'Digital signature'
    assert cert.get_roles() == ['auth']

def test_sign_cert():
    """Test that an signature cert is identified as such"""
    cert = _gen_qcert(sign=True)
    assert cert.get_display_name() == ('Signeringssertifikat', 'Signering')
    assert cert.get_key_usages() == 'Non-repudiation'
    assert cert.get_roles() == ['sign']

def test_crypt_cert():
    """Test that an crypt cert is identified as such"""
    cert = _gen_qcert(crypt=True)
    assert cert.get_display_name() == ('Krypteringssertifikat', 'Kryptering')
    assert cert.get_key_usages() == 'Key encipherment, Data encipherment'
    assert cert.get_roles() == ['crypt']

def test_crypt_and_auth_cert():
    """Test that an authentication AND crypt cert is identified as such"""
    cert = _gen_qcert(crypt=True, auth=True)
    assert cert.get_display_name() == ('Krypteringssertifikat', 'Kryptering og autentisering')
    assert cert.get_key_usages() == 'Digital signature, Key encipherment, Data encipherment'
    assert cert.get_roles() == ['auth', 'crypt']

#### BEGIN CERT SET TESTS ####

def test_separate_certsets_normal_buypass():
    """Tests that a normal Buypass case is separated correctly"""

    auth1 = _gen_qcert(crypt=True, auth=True)
    sign1 = _gen_qcert(sign=True)
    auth2 = _gen_qcert(crypt=True, auth=True)
    sign2 = _gen_qcert(sign=True)

    qualified_certs = [auth1, sign1, auth2, sign2]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [auth1, sign1]
    assert cert_sets[1].certs == [auth2, sign2]

def test_separate_certsets_normal_commfides():
    """Tests that a normal Commfides case is separated correctly"""

    auth1 = _gen_qcert(auth=True)
    sign1 = _gen_qcert(sign=True)
    crypt1 = _gen_qcert(crypt=True)
    auth2 = _gen_qcert(auth=True)
    sign2 = _gen_qcert(sign=True)
    crypt2 = _gen_qcert(crypt=True)


    qualified_certs = [auth1, sign1, crypt1, auth2, sign2, crypt2]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [auth1, sign1, crypt1]
    assert cert_sets[1].certs == [auth2, sign2, crypt2]

def test_separate_certsets_subject():
    """Tests that certs differentiated by subject is separated correctly"""

    auth = _gen_qcert(crypt=True, auth=True, cn='cert1')
    sign = _gen_qcert(sign=True, cn='cert2')

    qualified_certs = [auth, sign]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [auth]
    assert cert_sets[1].certs == [sign]

def test_separate_certsets_only_date():
    """Tests that certs only differentiated by date is separated correctly"""

    date1 = datetime.datetime(2015, 3, 4, 10, 12, 10, 000)
    date2 = datetime.datetime(2016, 3, 4, 10, 12, 10, 000)

    auth = _gen_qcert(crypt=True, auth=True, not_before=date1)
    sign = _gen_qcert(sign=True, not_before=date2)

    qualified_certs = [auth, sign]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [auth]
    assert cert_sets[1].certs == [sign]

def test_separate_certsets_wrong_order():
    """Tests that two certs delivered in the wrong order is not placed in the same set"""

    date1 = datetime.datetime(2015, 3, 4, 10, 12, 10, 000)
    date2 = datetime.datetime(2016, 3, 4, 10, 12, 10, 000)

    auth = _gen_qcert(crypt=True, auth=True, not_before=date2)
    sign = _gen_qcert(sign=True, not_before=date1)

    qualified_certs = [auth, sign]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [auth]
    assert cert_sets[1].certs == [sign]

def test_separate_certsets_slow_cryptocert():
    """Tests that a set with a crypt cert issued two days after the others is grouped together"""

    date1 = datetime.datetime(2015, 3, 4, 10, 12, 10, 000)
    date2 = datetime.datetime(2015, 3, 6, 10, 12, 10, 000)

    auth = _gen_qcert(auth=True, not_before=date1)
    sign = _gen_qcert(sign=True, not_before=date1)
    crypt = _gen_qcert(crypt=True, not_before=date2)

    qualified_certs = [auth, sign, crypt]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 1

def test_separate_certsets_serialnumber_commfides():
    """Tests that the serialNumber is ignored in grouping person certs from Commfides"""

    auth = _gen_qcert(auth=True, cn='Commfides', sn='31432-432-fds')
    sign = _gen_qcert(sign=True, cn='Commfides', sn='342rfddfds-fs')
    crypt = _gen_qcert(crypt=True, cn='Commfides', sn='dsadas23rwefsdz')

    qualified_certs = [auth, sign, crypt]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 1

def test_separate_certsets_same_keyusage():
    """Tests that two standalone certs with the same keyusage is not placed in the same set"""

    sign1 = _gen_qcert(sign=True)
    sign2 = _gen_qcert(sign=True)

    qualified_certs = [sign1, sign2]
    cert_sets = sertifikatsok.separate_certificate_sets(qualified_certs)

    assert len(cert_sets) == 2
    assert cert_sets[0].certs == [sign1]
    assert cert_sets[1].certs == [sign2]
