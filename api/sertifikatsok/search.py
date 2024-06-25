from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import unquote, urlparse

from attrs import field, frozen, mutable

from ruldap3 import (
    LdapConnection,
    Ruldap3Error,
    Scope,
    SearchEntry,
    is_ldap_filter_valid,
    ldap_escape,
)
from sertifikatsok.rfc4514 import try_parse_as_lax_rfc4514_string

from .constants import (
    EMAIL_REGEX,
    HEX_SERIAL_REGEX,
    HEX_SERIALS_REGEX,
    INT_SERIALS_REGEX,
    LDAP_CONN_TIMEOUT,
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
from .errors import (
    AllServersFailedError,
    ClientError,
    SertifikatSokError,
)
from .ldap import LDAP_SERVERS, LdapCertificateEntry, LdapFilter, LdapServer
from .logging import performance_log
from .qcert import QualifiedCertificate, QualifiedCertificateSet

logger = logging.getLogger(__name__)


class CouldNotContactCaError(SertifikatSokError):
    def __init__(self, ca: CertificateAuthority):
        super().__init__(f"Could not contact CA {ca}")
        self.ca = ca


@frozen
class SearchParams:
    env: Environment
    typ: CertType
    query: str
    attr: SearchAttribute | None


@frozen
class LdapSearchParams:
    ldap_query: LdapFilter
    scope: Scope
    ldap_servers: list[LdapServer]
    limitations: list[str]
    organization: Organization | None
    search_type: SearchType

    @classmethod
    def create(
        cls, search_params: SearchParams, database: Database
    ) -> LdapSearchParams:
        if search_params.attr is not None:
            scope = Scope.SUB
            ldap_servers = [
                ldap_server
                for ldap_server in LDAP_SERVERS[search_params.env]
                if search_params.typ in ldap_server.cert_types
            ]

            ldap_query = LdapFilter.create_from_params(
                [(search_params.attr, search_params.query)]
            )

            return cls(ldap_query, scope, ldap_servers, [], None, SearchType.CUSTOM)

        if "ldap://" in search_params.query.lower():
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
                    f"*{ldap_escape(organization.orgnr)}*))"
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

            ldap_query_params = [
                (SearchAttribute.SN, query),
                (SearchAttribute.SN, f"UN:NO-{query}"),
            ]

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
                # Buypass had a bug in 2024 where they issued
                # certs with only their internal ID in the serialNumber,
                # so let's search for those certs as well.
                ldap_query_params.append((SearchAttribute.SN, query.split("-")[-1]))

            elif ca_id.startswith("45"):
                ldap_servers = [
                    ldap_server
                    for ldap_server in ldap_servers
                    if ldap_server.ca == CertificateAuthority.COMMFIDES
                ]

            ldap_query = LdapFilter.create_from_params(ldap_query_params)

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
            serial_number = int(cleaned_query, 16)
            ldap_query = LdapFilter.create_for_cert_serials([serial_number])

            if (cleaned_query_len := len(cleaned_query)) in (40, 64):
                # Might be a thumbprint
                hash_ldap_servers = (
                    database.find_cert_from_sha1(cleaned_query, search_params.env)
                    if cleaned_query_len == 40
                    else database.find_cert_from_sha2(cleaned_query, search_params.env)
                )

                if hash_ldap_servers:
                    # We found a match for this as a thumbprint.
                    search_type = SearchType.THUMBPRINT
                    ldap_query = LdapFilter("(objectClass=*)")
                    ldap_servers = hash_ldap_servers
                else:
                    # Not a known thumbprint, let's continue the search
                    # for it as a serial number
                    search_type = SearchType.THUMBPRINT_OR_CERT_SERIAL
            else:
                search_type = SearchType.CERT_SERIAL

        elif search_attrs := try_parse_as_lax_rfc4514_string(query):
            search_type = SearchType.DISTINGUISHED_NAME
            ldap_query = LdapFilter.create_query_of_type_and_from_params(search_attrs)

        # Fallback to the Common Name field.
        else:
            search_type = SearchType.FALLBACK
            ldap_query = LdapFilter.create_from_params([(SearchAttribute.CN, query)])

        return cls(
            ldap_query,
            Scope.SUB,
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
            search_params.query[search_params.query.lower().find("ldap://") :]
        )

        if parsed_url.scheme.lower() != "ldap":
            # Should not happen
            raise ClientError("Unsupported scheme in ldap url")

        if parsed_url.hostname is None:
            raise ClientError("Hostname is required in ldap url")

        allowed_ldap_servers_match = [
            (env, ldap_server)
            for env, ldap_servers in LDAP_SERVERS.items()
            for ldap_server in ldap_servers
            if ldap_server.hostname == parsed_url.hostname.lower()
        ]

        if not allowed_ldap_servers_match:
            allowed_ldap_servers = ",".join(
                {
                    ldap_server.hostname
                    for ldap_servers in LDAP_SERVERS.values()
                    for ldap_server in ldap_servers
                }
            )
            raise ClientError(
                "Disallowed hostname in ldap url. "
                f"Only following are allowed: {allowed_ldap_servers}"
            )

        pre_allowed_ldap_server_env = allowed_ldap_servers_match[0][0]
        pre_allowed_ldap_server = allowed_ldap_servers_match[0][1]

        if search_params.env != pre_allowed_ldap_server_env:
            limitations.append("ERR-008")

        try:
            url_port = parsed_url.port
        except ValueError as e:
            raise ClientError("Invalid port in ldap url") from e

        if url_port is not None and url_port != 389:
            raise ClientError(
                "Unsupported port in ldap url. Only port 389 is supported."
            )

        ldap_server = LdapServer(
            pre_allowed_ldap_server.hostname,
            # strip leading /
            unquote(parsed_url.path[1:]),
            pre_allowed_ldap_server.ca,
            [],
        )

        parsed_query = parsed_url.query.split("?")
        parsed_query.extend("" for _ in range(4 - len(parsed_query)))

        if len(parsed_query) != 4:
            raise ClientError("Malformed query in ldap url")

        raw_attrlist, raw_scope, raw_filtr, raw_extensions = parsed_query

        # This is a lie, as we always request both `usercertificate;binary`
        # and `certificateSerialNumber`, but the last one is mostly a
        # implementation detail. It's the `usercertificate;binary` that is
        # "the deal".
        attrlist = [
            unquote(raw_attr)
            for raw_attr in raw_attrlist.lower().split(",")
            if raw_attr
        ]
        if attrlist and not any(x in attrlist for x in ["usercertificate;binary", "*"]):
            raise ClientError(
                "Invalid attribute(s) in ldap url: 'usercertificate;binary' is required"
            )

        match raw_scope.lower():
            case "one":
                scope = Scope.ONE
            case "sub":
                scope = Scope.SUB
            # rfc4516: If <scope> is omitted, a <scope> of "base" is assumed.
            case "base" | "":
                scope = Scope.BASE
            case _:
                raise ClientError(
                    "Invalid scope in url. Must be 'one', 'sub' or 'base'"
                )

        # rfc4516: If <filter> is omitted, a filter of "(objectClass=*)" is assumed.
        filtr = unquote(raw_filtr) or "(objectClass=*)"
        if not is_ldap_filter_valid(filtr):
            logger.info("Rejecting ldap filter %s", filtr)
            raise ClientError("Invalid filter in ldap url")

        # We don't care about the extensions, but if there's a critical one,
        # we have to reject the url. From rfc4516:
        #  If an extension is not implemented and is marked critical, the
        #  implementation MUST NOT process the URL.
        extlist = raw_extensions.split(",")
        if any(ext.startswith("!") for ext in extlist):
            raise ClientError("Unsupported critical extension in ldap url")

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
    failed_ldap_servers: list[LdapServer] = field(factory=list)

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
        except (Ruldap3Error, TimeoutError):
            logger.exception("Error during ldap query against '%s'", ldap_server)
            self.failed_ldap_servers.append(ldap_server)
            if ldap_server.ca == CertificateAuthority.BUYPASS:
                self.errors.append("ERR-001")
            elif ldap_server.ca == CertificateAuthority.COMMFIDES:
                self.errors.append("ERR-002")
            else:
                raise RuntimeError(f"Unexpeced ca: {ldap_server.ca}") from None
        else:
            logger.debug("End: query against %s", ldap_server)

    async def do_ldap_search(
        self, ldap_server: LdapServer, *, retry: bool = False
    ) -> list[QualifiedCertificate]:
        """
        Searches the specified LDAP server after certificates

        Buypass caps the result at 20, and doesn't support "normal" paging
        so to get all the certs we need to do several searches and exclude the
        certs we have already gotten. The queries get uglier and uglier,
        so this shouldn't be repeated too many times
        """
        count = 0
        results: list[SearchEntry] = []
        all_results: list[SearchEntry] = []
        search_filter = self.ldap_params.ldap_query.get_for_ldap_server(ldap_server)
        logger.debug("Starting: ldap search against: %s", ldap_server)

        async with await LdapConnection.connect(
            f"ldap://{ldap_server.hostname}", timeout_sec=LDAP_CONN_TIMEOUT
        ) as conn:
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
                    timeout_sec=LDAP_TIMEOUT,
                )
                all_results += results

                if len(results) == 20 and retry:
                    certs_to_exclude = ""
                    for result in results:
                        # TODO: This is not robust, as the dn can
                        # contain escaped commas. Also, it can contain
                        # chars that must be escaped in the filter.
                        # Also, is it even guaranteed that the dn attr
                        # exists as an attribute? But this is only used
                        # with Buypass and their pssUniqueIdentifier, so
                        # it works in practice.
                        dn = result.dn.split(",")[0]
                        certs_to_exclude += f"(!({dn}))"
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
        self, search_results: list[SearchEntry], ldap_server: LdapServer
    ) -> list[QualifiedCertificate]:
        """Takes a ldap response and creates a list of QualifiedCertificateSet"""
        logger.debug("Start: parsing certificates from %s", ldap_server)

        ldap_cert_entries = [
            entry
            for result in search_results
            if (entry := LdapCertificateEntry.create(result, ldap_server))
        ]

        self.database.insert_certificates(
            ldap_cert_entries,
            ldap_server.hostname,
        )

        qualified_certs = []
        for ldap_cert_entry in ldap_cert_entries:
            try:
                qualified_cert = await QualifiedCertificate.create(
                    ldap_cert_entry, self.cert_validator
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
        if len(self.failed_ldap_servers) == len(self.ldap_params.ldap_servers):
            if all(
                server.hostname == self.failed_ldap_servers[0].hostname
                for server in self.failed_ldap_servers
            ):
                raise CouldNotContactCaError(self.failed_ldap_servers[0].ca)

            raise AllServersFailedError()

        self.errors.extend(self.cert_validator.errors)
        self.warnings.extend(self.ldap_params.limitations)
        if len(self.results) == 0:
            if self.filtered_results:
                self.warnings.append("ERR-009")
            if self.ldap_params.search_type == SearchType.THUMBPRINT_OR_CERT_SERIAL:
                self.warnings.append("ERR-010")

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
