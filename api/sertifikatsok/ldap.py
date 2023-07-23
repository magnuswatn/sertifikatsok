import hashlib
from collections.abc import Collection
from typing import Self

from attr import frozen

from ruldap3 import LdapEntry, ldap_escape

from .enums import CertificateAuthority, CertType, Environment, SearchAttribute


@frozen
class LdapServer:
    hostname: str
    base: str
    ca: CertificateAuthority
    cert_types: list[CertType]
    need_double_csn_search: bool = False

    def __str__(self) -> str:
        # Used for logging.
        return f"{self.hostname}: {self.base}"


@frozen
class LdapCertificateEntry:
    dn: str
    raw_cert: bytes
    cert_serial: str | None
    ldap_server: LdapServer

    @classmethod
    def create(cls, ldap_entry: LdapEntry, ldap_server: LdapServer) -> Self | None:
        raw_certs = ldap_entry.bin_attrs.get("userCertificate;binary")
        if raw_certs is None or len(raw_certs) < 1:
            assert "userCertificate;binary" not in ldap_entry.attrs
            return None
        [raw_cert] = raw_certs

        cert_serials = ldap_entry.attrs.get("certificateSerialNumber")
        if cert_serials is not None and len(cert_serials) > 0:
            [cert_serial] = cert_serials
        else:
            assert "certificateSerialNumber" not in ldap_entry.bin_attrs
            cert_serial = None

        return cls(str(ldap_entry.dn), bytes(raw_cert), cert_serial, ldap_server)

    def cert_sha1sum(self) -> str:
        return hashlib.sha1(self.raw_cert).hexdigest()  # noqa: S324

    def cert_sha256sum(self) -> str:
        return hashlib.sha256(self.raw_cert).hexdigest()


@frozen
class LdapFilter:
    """
    This exists because some ldap servers have certificate
    serial numbers in differing formats (dec vs hex), and some
    ldap servers will get mad if you try to query cert serial
    in hex format, so we need to generate different searches
    for cert serial numbers for the different ldap servers.
    """

    _filtr: str
    _double_csn_filtr: str | None = None

    def __str__(self) -> str:
        return self._filtr

    def get_for_ldap_server(self, ldap_server: LdapServer) -> str:
        if ldap_server.need_double_csn_search and self._double_csn_filtr is not None:
            return self._double_csn_filtr
        return self._filtr

    @classmethod
    def create_from_params(cls, params: list[tuple[SearchAttribute, str]]) -> Self:
        return cls(cls._create_ldap_filter(params))

    @classmethod
    def create_for_cert_serials(cls, serials: Collection[int]) -> Self:
        filtr = cls._create_ldap_filter(
            [(SearchAttribute.CSN, str(serial)) for serial in serials]
        )
        double_csn_filtr = cls._create_ldap_filter(
            [
                serial_variant
                for serial in serials
                for serial_variant in [
                    (SearchAttribute.CSN, str(serial)),
                    (SearchAttribute.CSN, format(serial, "x")),
                ]
            ]
        )
        return cls(filtr, double_csn_filtr)

    @staticmethod
    def _create_ldap_filter(params: list[tuple[SearchAttribute, str]]) -> str:
        search_params = "".join(
            [f"({param[0].value}={ldap_escape(param[1])})" for param in params]
        )

        if len(params) > 1:
            return f"(|{search_params})"

        return search_params


LDAP_SERVERS = {
    Environment.TEST: [
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 1",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA 3",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 ST Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 HT Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.test4.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 Test4 CA G2 HT Person",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Enterprise,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Person-High,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Legal-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.test.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
            need_double_csn_search=True,
        ),
    ],
    Environment.PROD: [
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA 1",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA 3",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL, CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 ST Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 HT Business",
            CertificateAuthority.BUYPASS,
            [CertType.ENTERPRISE],
        ),
        LdapServer(
            "ldap.buypass.no",
            "dc=Buypass,dc=no,CN=Buypass Class 3 CA G2 HT Person",
            CertificateAuthority.BUYPASS,
            [CertType.PERSONAL],
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Enterprise,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Person-High,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Legal-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.ENTERPRISE],
            need_double_csn_search=True,
        ),
        LdapServer(
            "ldap.commfides.com",
            "ou=Natural-Person-G3,dc=commfides,dc=com",
            CertificateAuthority.COMMFIDES,
            [CertType.PERSONAL],
            need_double_csn_search=True,
        ),
    ],
}
