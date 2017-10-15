#!/usr/bin/env python3
"""
Quick script to print the subject of a PEM cert, the same way the api does (both encoded and not)
"""
import sys
import urllib.parse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

SUBJECT_FIELDS = {
    '2.5.4.3': 'CN',
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '1.2.840.113549.1.9.1': 'email'
}

def print_subject(cert):
    subject = []
    for field in cert.subject:
        subject.append('{}={}'.format(SUBJECT_FIELDS[field.oid.dotted_string], field.value))

    return ', '.join(list(subject))

def loadCert(filename):
    with open(filename, 'rb') as open_file:
            cert_bytes = open_file.read()
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    subject = print_subject(cert)

    print(urllib.parse.quote_plus(subject))
    print(subject)

if __name__ == '__main__':
     loadCert(sys.argv[1])
