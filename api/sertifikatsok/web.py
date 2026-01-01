import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.datastructures import MutableHeaders
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sertifikatsok import get_version, is_running_on_fly
from sertifikatsok.revocation_info import get_revocation_info
from sertifikatsok.static import StaticResourceHandler

from .audit_log import AuditLogger
from .brreg_batch import schedule_batch
from .crypto import AppCrlRetriever, CertRetriever, CertValidator, CrlDownloader
from .db import Database
from .enums import Environment, RequestCertType, SearchAttribute
from .errors import ClientError
from .logging import audit_logger, correlation_context, performance_log
from .search import CertificateSearch, CouldNotContactCaError, SearchParams
from .serialization import converter, sertifikatsok_serialization

logger = logging.getLogger(__name__)


def _parse_query(
    request: Request,
) -> tuple[Environment, RequestCertType, str, SearchAttribute | None]:
    try:
        env = Environment(request.query_params.get("env"))
    except ValueError as e:
        raise ClientError("Unknown environment") from e

    try:
        typ = RequestCertType(request.query_params.get("type"))
    except ValueError as e:
        raise ClientError("Unknown certificate type") from e

    if not (query := request.query_params.get("query")):
        raise ClientError("Missing query parameter")

    if (raw_attr := request.query_params.get("attr")) is not None:
        try:
            attr = SearchAttribute(raw_attr)
        except ValueError as e:
            raise ClientError("Unknown search attribute") from e
    else:
        attr = None

    return env, typ, query, attr


async def handle_client_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ClientError)
    logger.info("Returning client error: %s", exc)
    return Response(
        content=json.dumps({"error": exc.args[0]}, ensure_ascii=False),
        status_code=400,
        media_type="application/json",
    )


async def handle_could_not_contact_ca_error(
    request: Request, exc: Exception
) -> Response:
    logger.exception("Could not contact CA")
    assert isinstance(exc, CouldNotContactCaError)
    return Response(
        content=json.dumps(
            {
                "error": f"Klarte ikke kontakte {exc.ca.value.title()}. Vennligst prøv igjen."
            },
            ensure_ascii=False,
        ),
        status_code=503,
        media_type="application/json",
    )


async def handle_exception(request: Request, exc: Exception) -> Response:
    logger.exception("An exception occured:")
    return Response(
        content=json.dumps(
            {"error": "En ukjent feil oppstod. Vennligst prøv igjen."},
            ensure_ascii=False,
        ),
        status_code=500,
        media_type="application/json",
    )


class CorrelationMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        with correlation_context() as correlation_id:

            async def send_with_extra_headers(message: Message) -> None:
                if message["type"] == "http.response.start":
                    MutableHeaders(scope=message).append(
                        "Correlation-Id", str(correlation_id)
                    )

                await send(message)

            await self.app(scope, receive, send_with_extra_headers)


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    audit_logger.info("## Starting version %s ##", get_version())
    app.state.database = Database.connect_to_database()
    app.state.crl_retriever = AppCrlRetriever(CrlDownloader())
    app.state.cert_retrievers = {
        Environment.TEST: CertRetriever.create(Environment.TEST),
        Environment.PROD: CertRetriever.create(Environment.PROD),
    }
    if not is_running_on_fly():
        # Need a reference to this, so the garbage collector
        # doesn't clean it up.
        _batch_task = schedule_batch(app.state.database)
    yield


@performance_log()
async def api_endpoint(request: Request) -> Response:
    env, type, query, attr = _parse_query(request)
    audit_logger = AuditLogger(env, type, query, request, attr)
    with audit_logger:
        search_params = SearchParams(env, type.to_cert_type(), query, attr)

        certificate_search = CertificateSearch.create(
            search_params,
            CertValidator(
                request.app.state.cert_retrievers[search_params.env],
                request.app.state.crl_retriever.get_retriever_for_request(),
            ),
            request.app.state.database,
        )

        search_response = await certificate_search.get_response()
        audit_logger.set_results(search_response)

        response = Response(
            content=json.dumps(
                search_response, ensure_ascii=False, default=sertifikatsok_serialization
            ),
            status_code=200,
            media_type="application/json",
        )

        if search_response.cacheable and not request.app.state.dev:
            cache_control = "public, max-age=300"
        else:
            cache_control = "no-cache, no-store, must-revalidate, private, s-maxage=0"

        response.headers["Cache-Control"] = cache_control

        return response


@performance_log()
async def revocation_endpoint(request: Request) -> Response:
    env, type, query, attr = _parse_query(request)
    audit_logger = AuditLogger(env, type, query, request, attr)

    if request.headers.get("Content-Type") != "application/pkix-cert":
        raise ClientError("Unsupported content type")

    cert = b""
    async for chunk in request.stream():
        cert += chunk
        if len(cert) > 5000:
            raise ClientError("Body too big")

    with audit_logger:
        revocation_info, thumbprint = await get_revocation_info(
            cert,
            env,
            request.app.state.cert_retrievers[env],
            request.app.state.crl_retriever,
            request.app.state.database,
        )
        audit_logger.set_revocation_info_results(revocation_info, thumbprint)

    response = Response(
        content=converter.dumps(revocation_info),
        status_code=200,
        media_type="application/json",
    )

    return response


app = Starlette(
    middleware=[Middleware(CorrelationMiddleware)],
    lifespan=lifespan,
    routes=[
        Route("/api", api_endpoint),
        Route("/revocation_info", revocation_endpoint, methods=["POST"]),
        Route(
            "/{path:path}",
            StaticResourceHandler.create().handle_static_request,
        ),
    ],
    exception_handlers={
        ClientError: handle_client_error,
        CouldNotContactCaError: handle_could_not_contact_ca_error,
        Exception: handle_exception,
    },
)
