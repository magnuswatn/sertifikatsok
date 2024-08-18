import logging
import os
import sys
from collections import defaultdict
from collections.abc import Iterable
from typing import Literal, Self, TypeGuard

from cryptography.x509 import ocsp
from ldaptor.interfaces import IConnectedLDAPEntry  # type: ignore
from twisted.internet import endpoints, reactor
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.web import resource, server
from twisted.web.http import Request
from yarl import URL

from testserver.ca import CertificateId, OcspResponder, OcspResponders
from testserver.testdata import generate_testdata

from .config import CertificateAuthority, init
from .ldap import LDAPServerFactory

logger = logging.getLogger(__name__)


class TestServerResource(resource.Resource):
    isLeaf = True

    def __init__(
        self, crls: dict[URL, bytes], ocsp_responders: dict[URL, OcspResponders]
    ) -> None:
        self.crls = crls
        self.ocsp_responders = ocsp_responders
        super().__init__()

    @classmethod
    def create(cls, cas: Iterable[CertificateAuthority]) -> Self:
        crls: dict[URL, bytes] = {}
        responders_mapping: dict[URL, list[OcspResponder]] = defaultdict(list)

        for ca in cas:
            crl = ca.impl.get_crl()
            for cdp in ca.impl.cdp:
                if cdp.scheme == "http":
                    assert cdp.host
                    crls[cdp] = crl
            responders_mapping[ca.ocsp_responder.url].append(ca.ocsp_responder)

        return cls(
            crls,
            {
                url: OcspResponders.create(ocsp_responders)
                for url, ocsp_responders in responders_mapping.items()
            },
        )

    def render_GET(self, req: Request) -> bytes:
        path = req.path or b""
        if path == b"/ping":
            return b"pong"

        request_url = URL.build(
            scheme="http", host=req.getRequestHostname().decode(), path=path.decode()
        )

        req.setHeader("Content-Type", "application/pkix-crl")
        return self.crls[request_url]

    def render_POST(self, req: Request) -> bytes:
        if (ct := req.getHeader("content-type")) != "application/ocsp-request":
            raise ValueError(f"Unsupported content-type: {ct}")

        incoming_url = URL().build(
            scheme="http",
            host=req.getRequestHostname().decode(),
            path=req.path.decode(),  # type: ignore
        )
        logger.info("OCSP request for %s received", incoming_url)
        ocsp_responders = self.ocsp_responders.get(incoming_url)
        if ocsp_responders is None:
            raise ValueError(f"Invalid URL called: {incoming_url}")

        assert req.content

        raw_data = req.content.read(3000)

        ocsp_request = ocsp.load_der_ocsp_request(raw_data)

        request_cert_id = CertificateId.from_ocsp_request(ocsp_request)

        ocsp_responder = ocsp_responders.responders.get(request_cert_id)

        if ocsp_responder is None:
            raise ValueError(
                f"Invalid CA in request. Request cert id: {request_cert_id}"
            )

        req.setHeader("Content-Type", "application/ocsp-response")
        return ocsp_responder.get_response(ocsp_request)


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
    crl_resource = TestServerResource.create(loaded_ca_s.values())

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
