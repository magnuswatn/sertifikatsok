import argparse
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import MutableHeaders
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sertifikatsok import get_version, is_dev

from .audit_log import AuditLogger
from .brreg_batch import schedule_batch
from .crypto import AppCrlRetriever, CertRetriever, CertValidator, CrlDownloader
from .db import Database
from .enums import Environment, RequestCertType, SearchAttribute
from .errors import ClientError
from .logging import audit_logger, correlation_context, get_log_config, performance_log
from .search import CertificateSearch, SearchParams
from .serialization import sertifikatsok_serialization

logger = logging.getLogger(__name__)


async def handle_request_validation_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, RequestValidationError)
    logger.info("Request validation error %s", exc)
    error = exc.errors()[0]
    error_loc = error["loc"][-1]
    error_msg = error["msg"]
    return Response(
        content=json.dumps(
            {"error": f"Error for query field '{error_loc}': {error_msg}"},
            ensure_ascii=False,
        ),
        status_code=400,
        media_type="application/json",
    )


async def handle_client_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ClientError)
    logger.info("Returning client error: %s", exc)
    return Response(
        content=json.dumps({"error": exc.args[0]}, ensure_ascii=False),
        status_code=400,
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
        # Stuff caught by a general `Exception` handler
        # bubbles all the way up to Uvicorn, which closes
        # the connection after the response is sent. So
        # add a matching Connection header.
        headers={"Connection": "close"},
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
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    audit_logger.info("## Starting version %s ##", app.version)
    app.state.dev = is_dev()
    app.state.database = Database.connect_to_database()
    app.state.crl_retriever = AppCrlRetriever(CrlDownloader())
    app.state.cert_retrievers = {
        Environment.TEST: CertRetriever.create(Environment.TEST),
        Environment.PROD: CertRetriever.create(Environment.PROD),
    }
    # Need a reference to this, so the garbage collector
    # doesn't clean it up.
    _batch_task = schedule_batch(app.state.database)
    yield


app = FastAPI(
    middleware=[Middleware(CorrelationMiddleware)],
    lifespan=lifespan,
    title="Sertifikatsøk",
    version=get_version(),
    exception_handlers={
        ClientError: handle_client_error,
        RequestValidationError: handle_request_validation_error,
        Exception: handle_exception,
    },
)


@app.get("/api")
@performance_log()
async def api_endpoint(
    env: Environment,
    type: RequestCertType,
    query: str,
    request: Request,
    audit_logger: Annotated[AuditLogger, Depends(AuditLogger)],
    attr: SearchAttribute | None = None,
) -> Response:
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


def run() -> None:
    parser = argparse.ArgumentParser(description="Sertifikatsok API")
    parser.add_argument("--host")
    parser.add_argument("--path")
    parser.add_argument("--port")
    parser.add_argument("--log-level")
    parser.add_argument("--log-files")

    args = parser.parse_args()

    if args.log_level:
        log_level = getattr(logging, args.log_level)
    elif is_dev():
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    uvicorn.run(
        "sertifikatsok.web:app",
        port=int(args.port),
        host=args.host,
        log_level=log_level,
        reload=is_dev(),
        log_config=get_log_config(log_level, args.log_files),
    )
