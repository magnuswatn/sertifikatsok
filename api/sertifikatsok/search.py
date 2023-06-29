from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import unquote, urlparse

import bonsai
from attrs import field, frozen, mutable
from bonsai import escape_filter_exp
from bonsai.asyncio import AIOLDAPConnection

from ruldap3 import is_ldap_filter_valid

from .constants import (
    EMAIL_REGEX,
    HEX_SERIAL_REGEX,
    HEX_SERIALS_REGEX,
    INT_SERIALS_REGEX,
    LDAP_RETRIES,
    LDAP_TIMEOUT,
    MAX_SERIAL_NUMBER_COUNT,
    ORG_NUMBER_REGEX,
    PERSONAL_SERIAL_REGEX,
)
from .crypto import CertValidator
from .db import Database, Organization
from .enums import (
    CertificateAuthority,
    CertType,
    Environment,
    SearchAttribute,
    SearchType,
)
from .errors import ClientError
from .ldap import LDAP_SERVERS, LdapFilter, LdapServer
from .logging import performance_log
from .qcert import QualifiedCertificate, QualifiedCertificateSet

logger = logging.getLogger(__name__)


@frozen
class SearchParams:
    env: Environment
    typ: CertType
    query: str
    attr: SearchAttribute | None


@frozen
class LdapSearchParams:
    ldap_query: LdapFilter
    scope: bonsai.LDAPSearchScope
    ldap_servers: list[LdapServer]
    limitations: list[str]
    organization: Organization | None
    search_type: SearchType

    @classmethod
    def create(
        cls, search_params: SearchParams, database: Database
    ) -> LdapSearchParams:
        if search_params.attr is not None:
            scope = bonsai.LDAPSearchScope.SUBTREE
            ldap_servers = [
                ldap_server
                for ldap_server in LDAP_SERVERS[search_params.env]
                if search_params.typ in ldap_server.cert_types
            ]

            ldap_query = LdapFilter.create_from_params(
                [(search_params.attr, search_params.query)]
            )

            return cls(ldap_query, scope, ldap_servers, [], None, SearchType.CUSTOM)

        if "ldap://" in search_params.query:
            return cls._parse_ldap_url(search_params)
        else:
            return cls._guess_search_params(search_params, database)

    @classmethod
    def _guess_search_params(
        cls, search_params: SearchParams, database: Database
    ) -> LdapSearchParams:
        ldap_servers = [
            ldap_server
            for ldap_server in LDAP_SERVERS[search_params.env]
            if search_params.typ in ldap_server.cert_types
        ]
        typ, query = search_params.typ, search_params.query
        limitations: list[str] = []
        organization = None

        # If the query is an organization number, we must search
        # for it in the SERIALNUMBER field (SEID 1), and the
        # ORGANIZATION_IDENTIFIER field with a prefix (SEID 2).
        if typ == CertType.ENTERPRISE and ORG_NUMBER_REGEX.fullmatch(query):
            search_type = SearchType.ORG_NR

            # (prefix or whitespace allowed by the regex)
            query = (
                query[6:]
                if query.startswith("NTRNO-")
                else "".join(re.split(r"[\s]", query))
            )

            organization = database.get_organization(query)
            if organization is not None and organization.is_child:
                # Child org, we must query the parent, but with
                # the child orgnr in the OU field.
                logger.info("Child org - adopting query accordingly")

                assert organization.parent_orgnr is not None
                base_ldap_query = LdapFilter.create_from_params(
                    [
                        (SearchAttribute.SN, organization.parent_orgnr),
                        (SearchAttribute.ORGID, f"NTRNO-{organization.parent_orgnr}"),
                    ]
                )
                # We must create the filter "by hand" here (not by using
                # create_ldap_filter), because we need the unescaped * char.
                ldap_query = LdapFilter(
                    f"(&{base_ldap_query}"
                    f"({SearchAttribute.OU.value}="
                    f"*{escape_filter_exp(organization.orgnr)}*))"
                )
            else:
                ldap_query = LdapFilter.create_from_params(
                    [
                        (SearchAttribute.SN, query),
                        (SearchAttribute.ORGID, f"NTRNO-{query}"),
                    ]
                )

        # If the query is a norwegian personal serial number, we must search
        # for it in the serialNumber field, both without (SEID 1) and with (SEID 2)
        # the "UN:NO-" prefix.
        elif typ == CertType.PERSONAL and PERSONAL_SERIAL_REGEX.fullmatch(query):
            search_type = SearchType.PERSONAL_SERIAL

            if query.startswith("UN:NO-"):
                query = query[6:]

            ldap_query = LdapFilter.create_from_params(
                [
                    (SearchAttribute.SN, query),
                    (SearchAttribute.SN, f"UN:NO-{query}"),
                ]
            )

            # The different CAs have their own ranges of personal serial numbers,
            # so we can query only the relevant CA.
            # The ranges are specified in "Vedlegg til SEID Leveranse 1".
            ca_id = query.split("-")[1]
            if ca_id == "4050":
                ldap_servers = [
                    ldap_server
                    for ldap_server in ldap_servers
                    if ldap_server.ca == CertificateAuthority.BUYPASS
                ]
            elif ca_id.startswith("45"):
                ldap_servers = [
                    ldap_server
                    for ldap_server in ldap_servers
                    if ldap_server.ca == CertificateAuthority.COMMFIDES
                ]

        # If the query looks like an email address, we search for it in the
        # MAIL attribute.
        elif typ == CertType.PERSONAL and EMAIL_REGEX.fullmatch(query):
            search_type = SearchType.EMAIL

            ldap_query = LdapFilter.create_from_params([(SearchAttribute.MAIL, query)])

            # Buypass doesn't include email in SEID2 certificates, so we warn
            # that searches like this will only find older Buypass certs. Whether
            # it make sense for us to warn about this can be discussed, but
            # there's some historical reasons behind this.
            limitations.append("ERR-006")

        # Try the certificateSerialNumber field, if it looks like one or more
        # serial numbers, or check the database after the thumbprint if it looks
        # like a hash.
        elif INT_SERIALS_REGEX.fullmatch(query):
            search_type = SearchType.CERT_SERIAL

            serial_numbers = {
                int(serial) for serial in re.split(r"[\s;,]+", query) if serial
            }

            if len(serial_numbers) > MAX_SERIAL_NUMBER_COUNT:
                raise ClientError("Too many serial numbers in search")

            ldap_query = LdapFilter.create_for_cert_serials(serial_numbers)
        elif HEX_SERIALS_REGEX.fullmatch(query):
            search_type = SearchType.CERT_SERIAL

            serial_numbers = {
                int(serial, 16) for serial in re.split(r"[\s;,]+", query) if serial
            }

            if len(serial_numbers) > MAX_SERIAL_NUMBER_COUNT:
                raise ClientError("Too many serial numbers in search")

            ldap_query = LdapFilter.create_for_cert_serials(serial_numbers)
        elif HEX_SERIAL_REGEX.fullmatch(query):
            cleaned_query = "".join(re.split(r"[\s:]+", query)).lower()

            if len(cleaned_query) == 40:
                search_type = SearchType.THUMBPRINT
                # matches the length of a SHA1 thumbprint
                ldap_servers = database.find_cert_from_sha1(
                    cleaned_query, search_params.env
                )
                ldap_query = LdapFilter("")
                if not ldap_servers:
                    limitations.append("ERR-010")

            elif len(cleaned_query) == 64:
                search_type = SearchType.THUMBPRINT
                # matches the length of a SHA256 thumbprint
                ldap_servers = database.find_cert_from_sha2(
                    cleaned_query, search_params.env
                )
                ldap_query = LdapFilter("")
                if not ldap_servers:
                    limitations.append("ERR-010")

            else:
                search_type = SearchType.CERT_SERIAL
                serial_number = int(cleaned_query, 16)
                ldap_query = LdapFilter.create_for_cert_serials([serial_number])

        # Fallback to the Common Name field.
        else:
            search_type = SearchType.FALLBACK
            ldap_query = LdapFilter.create_from_params([(SearchAttribute.CN, query)])

        return cls(
            ldap_query,
            bonsai.LDAPSearchScope.SUBTREE,
            ldap_servers,
            limitations,
            organization,
            search_type,
        )

    @classmethod
    def _parse_ldap_url(cls, search_params: SearchParams) -> LdapSearchParams:
        limitations = []

        parsed_url = urlparse(
            # strip garbage before the url
            search_params.query[search_params.query.find("ldap://") :]
        )

        if parsed_url.scheme != "ldap":
            # Should not happen
            raise ClientError("Unsupported scheme in ldap url")

        if parsed_url.hostname is None:
            raise ClientError("Hostname missing in ldap url")

        allowed_ldap_servers_match = [
            (env, ldap_server)
            for env, ldap_servers in LDAP_SERVERS.items()
            for ldap_server in ldap_servers
            if ldap_server.hostname == parsed_url.hostname.lower()
        ]

        if not allowed_ldap_servers_match:
            raise ClientError("Unsupported hostname in ldap url")

        pre_allowed_ldap_server_env = allowed_ldap_servers_match[0][0]
        pre_allowed_ldap_server = allowed_ldap_servers_match[0][1]

        if search_params.env != pre_allowed_ldap_server_env:
            limitations.append("ERR-008")

        ldap_server = LdapServer(
            pre_allowed_ldap_server.hostname,
            # strip leading /
            unquote(parsed_url.path[1:]),
            pre_allowed_ldap_server.ca,
            [],
        )

        parsed_query = parsed_url.query.split("?")
        if len(parsed_query) != 3:
            raise ClientError("Malformed query in ldap url")

        attrlist, raw_scope, filtr = parsed_query
        if attrlist != "usercertificate;binary":
            raise ClientError(
                "Unsupported attribute(s) in url. "
                "Only 'usercertificate;binary' is supported."
            )

        if raw_scope == "one":
            scope = bonsai.LDAPSearchScope.ONE
        elif raw_scope == "sub":
            scope = bonsai.LDAPSearchScope.SUB
        # rfc1959: If <scope> is omitted, a scope of "base" is assumed.
        elif raw_scope in {"base", ""}:
            scope = bonsai.LDAPSearchScope.BASE
        else:
            raise ClientError("Unsupported scope in url")

        if not is_ldap_filter_valid(filtr):
            logger.info("Rejecting ldap filter %s", filtr)
            raise ClientError("Invalid filter in url")

        return cls(
            LdapFilter(filtr),
            scope,
            [ldap_server],
            limitations,
            None,
            SearchType.LDAP_URL,
        )


@mutable
class CertificateSearch:
    search_params: SearchParams
    ldap_params: LdapSearchParams
    cert_validator: CertValidator
    database: Database
    filtered_results: bool = field(default=False)
    errors: list[str] = field(factory=list)
    warnings: list[str] = field(factory=list)
    results: list[QualifiedCertificate] = field(factory=list)

    @classmethod
    def create(
        cls,
        search_params: SearchParams,
        cert_validator: CertValidator,
        database: Database,
    ) -> CertificateSearch:
        ldap_params = LdapSearchParams.create(search_params, database)

        return cls(search_params, ldap_params, cert_validator, database)

    @performance_log(id_param=1)
    async def query_ca(self, ldap_server: LdapServer) -> None:
        logger.debug("Start: query against %s", ldap_server)

        try:
            self.results.extend(
                await self.do_ldap_search(
                    ldap_server,
                    retry=ldap_server.ca == CertificateAuthority.BUYPASS,
                )
            )
        except (bonsai.LDAPError, asyncio.TimeoutError):
            logger.exception("Error during ldap query against '%s'", ldap_server)
            if ldap_server.ca == CertificateAuthority.BUYPASS:
                self.errors.append("ERR-001")
            elif ldap_server.ca == CertificateAuthority.COMMFIDES:
                self.errors.append("ERR-002")
            else:
                raise RuntimeError(f"Unexpeced ca: {ldap_server.ca}") from None
        else:
            logger.debug("End: query against %s", ldap_server)

    async def do_ldap_search(
        self, ldap_server: LdapServer, retry: bool = False
    ) -> list[QualifiedCertificate]:
        """
        Searches the specified LDAP server after certificates

        Buypass caps the result at 20, and doesn't support "normal" paging
        so to get all the certs we need to do several searches and exclude the
        certs we have already gotten. The queries get uglier and uglier,
        so this shouldn't be repeated too many times
        """
        client = bonsai.LDAPClient(f"ldap://{ldap_server.hostname}")
        count = 0
        results: list[bonsai.LDAPEntry] = []
        all_results: list[bonsai.LDAPEntry] = []
        search_filter = self.ldap_params.ldap_query.get_for_ldap_server(ldap_server)
        logger.debug("Starting: ldap search against: %s", ldap_server)

        conn: AIOLDAPConnection
        async with client.connect(is_async=True, timeout=LDAP_TIMEOUT) as conn:
            while count < LDAP_RETRIES:
                logger.debug(
                    'Doing search with filter "%s" against "%s"',
                    search_filter,
                    ldap_server,
                )
                results = await conn.search(
                    ldap_server.base,
                    self.ldap_params.scope,
                    search_filter,
                    attrlist=["certificateSerialNumber", "userCertificate;binary"],
                )
                all_results += results

                if len(results) == 20 and retry:
                    certs_to_exclude = ""
                    for result in results:
                        certs_to_exclude += f"(!({result.dn[0]}))"
                    search_filter = f"(&{search_filter}{certs_to_exclude})"
                    count += 1
                else:
                    count = LDAP_RETRIES + 1

            logger.debug("Ending: ldap search against: %s", ldap_server)
            # If we got 20 on our last search (of several),
            # there may be more certs out there...
            if len(results) == 20 and retry:
                logger.warning(
                    "Exceeded max count for search with filter %s against %s",
                    self.ldap_params.ldap_query,
                    ldap_server,
                )
                self.warnings.append("ERR-004")

        return await self._parse_ldap_results(all_results, ldap_server)

    @performance_log(id_param=2)
    async def _parse_ldap_results(
        self, search_results: list[bonsai.LDAPEntry], ldap_server: LdapServer
    ) -> list[QualifiedCertificate]:
        """Takes a ldap response and creates a list of QualifiedCertificateSet"""
        logger.debug("Start: parsing certificates from %s", ldap_server)

        self.database.insert_certificates(
            [
                (str(result.dn), result.get("userCertificate;binary"))
                for result in search_results
            ],
            ldap_server.hostname,
        )

        qualified_certs = []
        for result in search_results:
            raw_cert = result.get("userCertificate;binary")
            if raw_cert is None or len(raw_cert) < 1:
                # Commfides have entries in their LDAP without a cert...
                continue

            cert_serials = result.get("certificateSerialNumber")
            if cert_serials is not None and len(cert_serials) > 0:
                cert_serial = cert_serials[0]
            else:
                cert_serial = None

            try:
                qualified_cert = await QualifiedCertificate.create(
                    raw_cert[0], cert_serial, ldap_server, self.cert_validator
                )
            except ValueError:
                # https://github.com/magnuswatn/sertifikatsok/issues/22
                logging.exception("ValueError while decoding certificate")
                self.errors.append("ERR-005")
                continue

            if qualified_cert.type in {
                self.search_params.typ,
                CertType.UNKNOWN,
            }:
                qualified_certs.append(qualified_cert)
            else:
                self.filtered_results = True

        logger.debug("End: parsing certificates from %s", ldap_server)
        return qualified_certs

    async def get_response(self) -> CertificateSearchResponse:
        await asyncio.gather(
            *[
                self.query_ca(ldap_server)
                for ldap_server in self.ldap_params.ldap_servers
            ]
        )
        self.errors.extend(self.cert_validator.errors)
        self.warnings.extend(self.ldap_params.limitations)
        if len(self.results) == 0 and self.filtered_results:
            self.warnings.append("ERR-009")

        return CertificateSearchResponse.create(self)


@frozen
class CertificateSearchResponse:
    search: CertificateSearch
    cert_sets: list[QualifiedCertificateSet]
    warnings: list[str]
    errors: list[str]

    @classmethod
    def create(cls, search: CertificateSearch) -> CertificateSearchResponse:
        cert_sets = QualifiedCertificateSet.create_sets_from_certs(search.results)
        return cls(search, cert_sets, search.warnings, search.errors)

    @property
    def cacheable(self) -> bool:
        return not self.errors
