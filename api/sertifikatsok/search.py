from __future__ import annotations

import asyncio
import logging
from typing import List, Optional
from urllib.parse import urlparse

import attr
import bonsai
from aiohttp.web import Request

from .constants import (
    EMAIL_REGEX,
    HEX_SERIAL_REGEX,
    INT_SERIAL_REGEX,
    LDAP_RETRIES,
    LDAP_TIMEOUT,
    ORG_NUMBER_REGEX,
    PERSONAL_SERIAL_REGEX,
)
from .crypto import CertValidator
from .enums import CertificateAuthority, CertType, Environment, SearchAttribute
from .errors import ClientError
from .logging import audit_log, performance_log
from .qcert import QualifiedCertificate, QualifiedCertificateSet
from .utils import convert_hex_serial_to_int, create_ldap_filter

logger = logging.getLogger(__name__)


@attr.frozen
class SearchParams:
    env: Environment
    typ: CertType
    query: str
    attr: Optional[SearchAttribute]

    @classmethod
    def create_from_request(cls, request: Request):

        try:
            env = Environment(request.query.get("env"))
        except ValueError:
            raise ClientError("Unknown environment")

        raw_type = request.query.get("type")
        if raw_type == "enterprise":
            typ = CertType.ENTERPRISE
        # Accept both for backward compatibility
        elif raw_type in {"personal", "person"}:
            typ = CertType.PERSONAL
        else:
            raise ClientError("Unknown certificate type")

        if not (query := request.query.get("query")):
            raise ClientError("Missing query parameter")

        if (raw_attr := request.query.get("attr")) is not None:
            try:
                attr = SearchAttribute(raw_attr)
            except ValueError:
                raise ClientError("Unknown search attribute")
        else:
            attr = None

        return cls(env, typ, query, attr)


@attr.frozen
class LdapSearchParams:
    ldap_query: str
    scope: bonsai.LDAPSearchScope
    ca_s: List[CertificateAuthority]
    limitations: List[str]

    @classmethod
    def create(cls, search_params: SearchParams) -> LdapSearchParams:

        if search_params.attr is not None:
            scope = bonsai.LDAPSearchScope.SUBTREE
            ca_s = [CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES]

            ldap_query = create_ldap_filter([(search_params.attr, search_params.query)])

            return cls(ldap_query, scope, ca_s, [])

        if search_params.query.startswith("ldap://"):
            return cls._parse_ldap_url(search_params)
        else:
            return cls._guess_search_params(search_params)

    @classmethod
    def _guess_search_params(cls, search_params: SearchParams) -> LdapSearchParams:

        ca_s = [CertificateAuthority.BUYPASS, CertificateAuthority.COMMFIDES]
        typ, query = search_params.typ, search_params.query
        limitations: List[str] = []

        # If the query is an organization number, we must search
        # for it in the SERIALNUMBER field (SEID 1), and the
        # ORGANIZATION_IDENTIFIER field with a prefix (SEID 2).
        if typ == CertType.ENTERPRISE and ORG_NUMBER_REGEX.fullmatch(query):
            query = query.replace(" ", "")
            ldap_query = create_ldap_filter(
                [
                    (SearchAttribute.SN, query),
                    # Commented out for the time being, as this does not work
                    # in production atm. And the Buypass LDAP server gets real mad
                    # if you try to search for it.
                    # (SearchAttribute.ORGID, f"NTRNO-{query}"),
                ]
            )

        # If the query is a norwegian personal serial number, we must search
        # for it in the serialNumber field, both without (SEID 1) and with (SEID 2)
        # the "UN:NO-" prefix.
        elif typ == CertType.PERSONAL and PERSONAL_SERIAL_REGEX.fullmatch(query):
            ldap_query = create_ldap_filter(
                [
                    (SearchAttribute.SN, query),
                    (SearchAttribute.SN, f"UN:NO-{query}"),
                ]
            )

            # If we are searching for personal certificates by serial number,
            # we can limit our search to only the relevant CA.
            ca_id = query.split("-")[1]
            if ca_id in {"4050"}:
                ca_s = [CertificateAuthority.BUYPASS]
            elif ca_id in {"4505", "4510"}:
                ca_s = [CertificateAuthority.COMMFIDES]

        # If the query looks like an email address, we search for it in the
        # MAIL attribute.
        elif typ == CertType.PERSONAL and EMAIL_REGEX.fullmatch(query):
            ldap_query = create_ldap_filter([(SearchAttribute.MAIL, query)])

            # Only Buypass have the mail attribute in their LDAP catalog.
            ca_s = [CertificateAuthority.BUYPASS]
            limitations.append("ERR-006")

        # Try the certificateSerialNumber field, if it looks like a serial number.
        elif INT_SERIAL_REGEX.fullmatch(query):
            ldap_query = create_ldap_filter([(SearchAttribute.CSN, query)])
        elif HEX_SERIAL_REGEX.fullmatch(query):
            serial_number = convert_hex_serial_to_int(query)
            ldap_query = create_ldap_filter([(SearchAttribute.CSN, serial_number)])

        # Fallback to the Common Name field.
        else:
            ldap_query = create_ldap_filter([(SearchAttribute.CN, query)])

        return cls(ldap_query, bonsai.LDAPSearchScope.SUBTREE, ca_s, limitations)

    @classmethod
    def _parse_ldap_url(cls, search_params: SearchParams) -> LdapSearchParams:
        # This parsing should be improved, so that
        # we actually use the base, and the ldap server
        # (if it is pre-approved).
        parsed_url = urlparse(search_params.query)

        if parsed_url.scheme != "ldap":
            # Should not happen
            raise ClientError("Unsupported scheme in ldap url")

        if parsed_url.hostname is None:
            raise ClientError("Hostname missing in ldap url")

        # TODO: fix this somehow. Dunno what env we should prefer
        # if the server and the environment differ ¯\_(ツ)_/¯
        if CertificateAuthority.BUYPASS.value in parsed_url.hostname:
            ca_s = [CertificateAuthority.BUYPASS]
        elif CertificateAuthority.COMMFIDES.value in parsed_url.hostname:
            ca_s = [CertificateAuthority.COMMFIDES]
        else:
            raise ClientError("Unsupported hostname in ldap url")

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

        if len(filtr) > 150 or filtr.count("(") != filtr.count(")"):
            raise ClientError("Invalid filter in url")

        return cls(filtr, scope, ca_s, ["ERR-007"])


@attr.mutable
class CertificateSearch:
    search_params: SearchParams
    ldap_params: LdapSearchParams
    cert_validator: CertValidator
    errors: List[str] = attr.ib(factory=list)
    warnings: List[str] = attr.ib(factory=list)
    _ldap_servers: List[str] = attr.ib(factory=list)
    results: List[QualifiedCertificate] = attr.ib(factory=list)

    @classmethod
    def create_from_request(cls, request) -> CertificateSearch:

        search_params = SearchParams.create_from_request(request)
        ldap_params = LdapSearchParams.create(search_params)

        cert_validator = CertValidator(
            request.app["CertRetrievers"][search_params.env],
            request.app["CrlRetriever"].get_retriever_for_request(),
        )

        audit_log(request)

        return cls(search_params, ldap_params, cert_validator)

    @performance_log()
    async def query_buypass(self):
        logger.debug("Starting: Buypass query")
        if self.search_params.env == Environment.TEST:
            server = "ldap.test4.buypass.no"
            base = "dc=Buypass,dc=no,CN=Buypass Class 3 Test4"
        else:
            server = "ldap.buypass.no"
            base = "dc=Buypass,dc=no,CN=Buypass Class 3"

        self._ldap_servers.append(server)

        try:
            self.results.extend(await self.do_ldap_search(server, base, retry=True))
        except (bonsai.LDAPError, asyncio.TimeoutError):
            logger.exception("Could not retrieve certificates from Buypass")
            self.errors.append("ERR-001")
        else:
            logger.debug("Ending: Buypass query")

    @performance_log()
    async def query_commfides(self):
        logger.debug("Starting: Commfides query")
        if self.search_params.env == Environment.TEST:
            server = "ldap.test.commfides.com"
        else:
            server = "ldap.commfides.com"

        base = "dc=commfides,dc=com"

        self._ldap_servers.append(server)

        try:
            self.results.extend(await self.do_ldap_search(server, base))
        except (bonsai.LDAPError, asyncio.TimeoutError):
            logger.exception("Could not retrieve certificates from Commfides")
            self.errors.append("ERR-002")
        else:
            logger.debug("Ending: Commfides query")

    async def do_ldap_search(self, server, base, retry=False):
        """
        Searches the specified LDAP server after certificates

        Buypass caps the result at 20, and doesn't support "normal" paging
        so to get all the certs we need to do several searches and exclude the
        certs we have already gotten. The queries get uglier and uglier,
        so this shouldn't be repeatet too many times
        """
        client = bonsai.LDAPClient(f"ldap://{server}")
        count = 0
        results = []
        all_results = []
        search_filter = self.ldap_params.ldap_query
        logger.debug("Starting: ldap search against: %s", server)
        with (await client.connect(is_async=True, timeout=LDAP_TIMEOUT)) as conn:  # type: ignore
            while count < LDAP_RETRIES:
                logger.debug(
                    'Doing search with filter "%s" against "%s"', search_filter, server
                )
                results = await conn.search(
                    base,
                    self.ldap_params.scope,
                    search_filter,
                    attrlist=["userCertificate;binary"],
                )
                all_results += results

                if len(results) == 20 and retry:
                    certs_to_exclude = ""
                    for result in results:
                        certs_to_exclude += f"(!({str(result.dn).split(',')[0]}))"
                    search_filter = "(&{}{})".format(search_filter, certs_to_exclude)
                    count += 1
                else:
                    count = LDAP_RETRIES + 1

            logger.debug("Ending: ldap search against: %s", server)
            # If we got 20 on our last search (of several),
            # there may be more certs out there...
            if len(results) == 20 and retry:
                logger.warning(
                    "Exceeded max count for search with filter %s against %s",
                    self.ldap_params.ldap_query,
                    server,
                )
                self.warnings.append("ERR-004")

        return await self._parse_ldap_results(all_results, server, base)

    @performance_log(id_param=2)
    async def _parse_ldap_results(self, search_results, server, base):
        """Takes a ldap response and creates a list of QualifiedCertificateSet"""
        logger.debug("Start: parsing certificates from %s", server)

        qualified_certs = []
        for result in search_results:
            raw_cert = result.get("userCertificate;binary")
            if raw_cert is None or len(raw_cert) < 1:
                # Commfides have entries in their LDAP without a cert...
                continue

            try:
                qualified_cert = await QualifiedCertificate.create(
                    raw_cert[0], (server, base), self.cert_validator
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

        logger.debug("End: parsing certificates from %s", server)
        return qualified_certs

    async def get_response(self):
        tasks = []
        if CertificateAuthority.BUYPASS in self.ldap_params.ca_s:
            tasks.append(self.query_buypass)
        if CertificateAuthority.COMMFIDES in self.ldap_params.ca_s:
            tasks.append(self.query_commfides)

        await asyncio.gather(*[task() for task in tasks])
        self.errors.extend(self.cert_validator.errors)
        self.warnings.extend(self.ldap_params.limitations)
        return CertificateSearchResponse.create(self)


@attr.frozen
class CertificateSearchResponse:
    search: CertificateSearch
    cert_sets: List[QualifiedCertificateSet]
    warnings: List[str]
    errors: List[str]

    @classmethod
    def create(cls, search: CertificateSearch) -> CertificateSearchResponse:
        cert_sets = QualifiedCertificateSet.create_sets_from_certs(search.results)
        return cls(search, cert_sets, search.warnings, search.errors)

    @property
    def cacheable(self):
        return not self.errors
