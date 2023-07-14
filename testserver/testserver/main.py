import logging
import os
import sys
from collections import defaultdict
from collections.abc import Iterable
from typing import Literal, Self, TypeGuard
from urllib.parse import urlparse

from ldaptor.interfaces import IConnectedLDAPEntry  # type: ignore
from twisted.internet import endpoints, reactor
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.web import resource, server
from twisted.web.http import Request

from testserver.testdata import generate_testdata

from .config import CertificateAuthority, init
from .ldap import LDAPServerFactory

logger = logging.getLogger(__name__)


class CrlResource(resource.Resource):
    isLeaf = True

    def __init__(self, crls: dict[str, dict[str, bytes]]) -> None:
        self.crls = crls
        super().__init__()

    @classmethod
    def create(cls, cas: Iterable[CertificateAuthority]) -> Self:
        crls: dict[str, dict[str, bytes]] = defaultdict(dict)
        for ca in cas:
            parsed_cdp = urlparse(ca.cdp)
            assert parsed_cdp.hostname
            crls[parsed_cdp.hostname][parsed_cdp.path] = ca.impl.get_crl()

        return cls(dict(crls))

    def render_GET(self, req: Request) -> bytes:
        path = req.path or b""
        if path == b"/ping":
            return b"pong"

        req.setHeader("Content-Type", "application/pkix-crl")
        return self.crls[req.getRequestHostname().decode()][path.decode()]


def is_valid_market(env: str) -> TypeGuard[Literal["test", "prod"]]:
    return env in ["test", "prod"]


def main() -> None:
    if os.getenv("RUNNING_IN_DOCKER"):
        listen_host = "0.0.0.0"  # ruff: noqa: S104
        ldap_port = 389
        http_port = 80
    else:
        listen_host = "127.0.0.1"
        ldap_port = 3389
        http_port = 8080

    log.startLogging(sys.stderr)
    logging.basicConfig(level=logging.DEBUG)

    env = os.environ.get("ENVIRONMENT", "test")
    assert is_valid_market(env)

    logger.info("Loading certs for environment %s", env)

    # Init the LDAP root tree
    ldap_server_factory = LDAPServerFactory.create()

    # Create clone of CAs from disk
    loaded_ca_s = init(env)

    # set up testdata
    logger.info("Generating test data")
    generate_testdata(loaded_ca_s)

    logger.info("Loading test data into LDAP tree")
    for cloned_ca, ca in loaded_ca_s.items():
        if cloned_ca.is_buypass:
            ldap_server_factory.add_buypass_ca(ca)
        else:
            ldap_server_factory.add_commfides_ca(ca)

    # Create CrlResource with the CRLs
    crl_resource = CrlResource.create(loaded_ca_s.values())

    # Create endpoints and mount up Twisted stuff
    endpoint = endpoints.TCP4ServerEndpoint(reactor, http_port, interface=listen_host)
    endpoint.listen(server.Site(crl_resource))

    # sprincle some more Twisted magic
    registerAdapter(lambda x: x.root, LDAPServerFactory, IConnectedLDAPEntry)

    ldap_endpoint = endpoints.TCP4ServerEndpoint(
        reactor, ldap_port, interface=listen_host
    )
    ldap_endpoint.listen(ldap_server_factory)

    reactor.run()  # type: ignore
