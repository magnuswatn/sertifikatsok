import logging
import os
import sys
from collections.abc import Iterable
from typing import Literal, Self, TypeGuard

from ldaptor.interfaces import IConnectedLDAPEntry  # type: ignore
from twisted.internet import endpoints, reactor
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.web import resource, server
from twisted.web.http import Request
from yarl import URL

from testserver.testdata import generate_testdata

from .config import CertificateAuthority, init
from .ldap import LDAPServerFactory

logger = logging.getLogger(__name__)


class CrlResource(resource.Resource):
    isLeaf = True

    def __init__(self, crls: dict[URL, bytes]) -> None:
        self.crls = crls
        super().__init__()

    @classmethod
    def create(cls, cas: Iterable[CertificateAuthority]) -> Self:
        crls: dict[URL, bytes] = {}
        for ca in cas:
            crl = ca.impl.get_crl()
            for cdp in ca.impl.cdp:
                if cdp.scheme == "http":
                    assert cdp.host
                    crls[cdp] = crl

        return cls(dict(crls))

    def render_GET(self, req: Request) -> bytes:
        path = req.path or b""
        if path == b"/ping":
            return b"pong"

        request_url = URL.build(
            scheme="http", host=req.getRequestHostname().decode(), path=path.decode()
        )

        req.setHeader("Content-Type", "application/pkix-crl")
        return self.crls[request_url]


def is_valid_env(env: str) -> TypeGuard[Literal["test", "prod"]]:
    return env in ["test", "prod"]


def main() -> None:
    if os.getenv("RUNNING_IN_DOCKER"):
        listen_host = "0.0.0.0"  # noqa: S104
        ldap_port = 389
        http_port = 80
    else:
        listen_host = "127.0.0.1"
        ldap_port = 3389
        http_port = 8080

    log.startLogging(sys.stderr)
    logging.basicConfig(level=logging.DEBUG)

    env = os.environ.get("ENVIRONMENT", "test")
    assert is_valid_env(env)

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
