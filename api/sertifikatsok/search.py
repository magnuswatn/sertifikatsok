import logging
from operator import itemgetter

import bonsai

from .utils import escape_ldap_query
from .constants import (
    ORG_NUMBER_REGEX,
    PERSONAL_SERIAL_REGEX,
    LDAP_RETRIES,
    LDAP_TIMEOUT,
)
from .qcert import QualifiedCertificate, QualifiedCertificateSet
from .crypto import CrlRetriever, CertRetriever

# black and pylint doesn't agree on everything
# pylint: disable=C0330

logger = logging.getLogger(__name__)


class CertificateSearch:
    def __init__(self, params):
        self.env = params.get("env")
        self.cert_type = params.get("type")
        self.org_number_search = False
        self.results = []
        self.errors = []
        self.cert_retriever = CertRetriever(self.env)
        self.crl_retriever = CrlRetriever()

        query = params.get("query")

        # If the query is an organization number, or an norwegian personal serial number,
        # we search in the serialNumber field, otherwise the commonName field
        if self.cert_type == "enterprise" and ORG_NUMBER_REGEX.fullmatch(query):
            self.search_filter = f"(serialNumber={query.replace(' ', '')})"
            self.org_number_search = True
        elif self.cert_type == "person" and PERSONAL_SERIAL_REGEX.fullmatch(query):
            self.search_filter = f"(serialNumber={query})"
        else:
            self.search_filter = f"(cn={escape_ldap_query(query)})"

    async def query_buypass(self):
        logger.debug("Starting: Buypass query")
        if self.env == "test":
            server = "ldap://ldap.test4.buypass.no"
            base = "dc=Buypass,dc=no,CN=Buypass Class 3 Test4"
        else:
            server = "ldap://ldap.buypass.no"
            base = "dc=Buypass,dc=no,CN=Buypass Class 3"

        try:
            self.results.extend(await self.do_ldap_search(server, base, retry=True))
        except bonsai.LDAPError:
            logger.exception("Could not retrieve certificates from Buypass")
            self.errors.append("Kunne ikke hente sertfikater fra Buypass")
        else:
            logger.debug("Ending: Buypass query")

    async def query_commfides(self):
        logger.debug("Starting: Commfides query")
        if self.env == "test":
            server = "ldap://ldap.test.commfides.com"
        else:
            server = "ldap://ldap.commfides.com"

        if self.cert_type == "person":
            # We only search for Person-High
            # because Person-Normal certs just doesn't exist
            base = "ou=Person-High,dc=commfides,dc=com"
        else:
            base = "ou=Enterprise,dc=commfides,dc=com"

        try:
            self.results.extend(await self.do_ldap_search(server, base))
        except bonsai.LDAPError:
            logger.exception("Could not retrieve certificates from Commfides")
            self.errors.append("Kunne ikke hente sertfikater fra Commfides")
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
        client = bonsai.LDAPClient(server)
        count = 0
        all_results = []
        search_filter = self.search_filter
        logger.debug("Starting: ldap search against: %s", server)
        with (await client.connect(is_async=True, timeout=LDAP_TIMEOUT)) as conn:
            while count < LDAP_RETRIES:
                logger.debug(
                    'Doing search with filter "%s" against "%s"', search_filter, server
                )
                results = await conn.search(
                    base,
                    bonsai.LDAPSearchScope.SUBTREE,
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
            # If we got 20 on our last (of sevaral) search, there may be more certs out there...
            if len(results) == 20 and retry:
                logger.warning(
                    "Exceeded max count for search with filter %s against %s",
                    self.search_filter,
                    server,
                )
                self.errors.append(
                    "Det er mulig noen gamle sertifikater ikke vises, "
                    "da søket returnerte for mange resultater"
                )

        return await self._parse_ldap_results(all_results, server, base)

    async def _parse_ldap_results(self, search_results, server, base):
        """Takes a ldap response and creates a list of QualifiedCertificateSet"""
        logger.debug("Start: parsing certificates from %s", server)

        qualified_certs = []
        for result in search_results:
            try:
                qualified_cert = await QualifiedCertificate.create(
                    result["userCertificate;binary"][0],
                    str(result.dn),
                    (server, base),
                    self.crl_retriever,
                    self.cert_retriever,
                )
            except KeyError:
                # Commfides have entries in their LDAP without a cert...
                continue
            qualified_certs.append(qualified_cert)

        logger.debug("End: parsing certificates from %s", server)
        return qualified_certs

    def get_tasks(self):
        """Returnes the tasks that need solving for this search"""
        tasks = [self.query_buypass(), self.query_commfides()]
        return tasks

    def get_result(self):

        self.errors.extend(self.crl_retriever.errors)

        cert_sets = QualifiedCertificateSet.create_sets_from_certs(self.results)

        result = {}

        result["subject"] = self.search_filter
        result["errors"] = self.errors
        result["certificate_sets"] = []
        for cert_set in cert_sets:
            result["certificate_sets"].append(cert_set.dump())

        result["certificate_sets"].sort(key=itemgetter("valid_from"), reverse=True)

        return result