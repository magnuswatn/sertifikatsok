import json
import logging
import os
import uuid
from functools import cache
from typing import Optional

from fastapi.applications import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.param_functions import Depends
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette_precompressed_static import PreCompressedStaticFiles

from .crypto import AppCrlRetriever, CertRetriever, CertValidator, CrlDownloader
from .db import Database
from .enums import CertType, Environment, SearchAttribute
from .errors import ClientError
from .logging import (
    audit_logger,
    configure_logging,
    correlation_id_var,
    performance_log,
)
from .search import CertificateSearch, CertificateSearchResponse, SearchParams
from .serialization import sertifikatsok_serialization

logger = logging.getLogger(__name__)

app = FastAPI(title="Sertifikatsøk")

DEV = bool(os.getenv("SERTIFIKATSOK_DEBUG"))


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)
    response = await call_next(request)
    response.headers["Correlation-Id"] = correlation_id
    return response


@cache
def cert_retriever(env: Environment) -> CertRetriever:
    return CertRetriever.create(env)


@cache
def crl_retriever() -> AppCrlRetriever:
    return AppCrlRetriever.create(CrlDownloader())


@cache
def database() -> Database:
    return Database.connect_to_database()


def cert_validator(
    cert_retriever: CertRetriever = Depends(cert_retriever),
    crl_retriever: AppCrlRetriever = Depends(crl_retriever),
) -> CertValidator:
    return CertValidator(cert_retriever, crl_retriever.get_retriever_for_request())


@app.on_event("startup")
async def init_app():

    configure_logging(
        logging.DEBUG if DEV else logging.INFO,
        os.getenv("SERTIFIKATSOK_LOGFILE"),
    )

    # Initialize these, so that they are
    # ready before the first request.
    database()
    crl_retriever()
    # We need to use kwargs here so the
    # @cache works as intended, as that
    # is what FastAPI does.
    cert_retriever(env=Environment.TEST)
    cert_retriever(env=Environment.PROD)


def search_params(
    env: Environment, type: CertType, query: str, attr: Optional[SearchAttribute] = None
):
    return SearchParams(env, type, query, attr)


@performance_log()
@app.get("/api")
async def api_endpoint(
    search_params: SearchParams = Depends(search_params),
    cert_validator: CertValidator = Depends(cert_validator),
    database: Database = Depends(database),
):
    certificate_search = CertificateSearch.create(
        search_params, cert_validator, database
    )

    search_response = None
    try:
        search_response = await certificate_search.get_response()
    finally:
        audit_log(search_params, search_response)

    cache_control = (
        "no-cache, no-store, must-revalidate, private, s-maxage=0"
        if DEV
        else "public, max-age=300"
    )

    return Response(
        content=json.dumps(
            search_response, ensure_ascii=False, default=sertifikatsok_serialization
        ),
        media_type="application/json",
        headers={"Cache-Control": cache_control},
    )


static_files = PreCompressedStaticFiles(directory="../www")


@app.head("/", include_in_schema=False)
@app.get("/", include_in_schema=False)
async def root(request: Request):
    # Can't use html mode with PreCompressedStaticFiles, but the only "magic"
    # we need is that index.html is served from the root, so let's just do it
    # ourselves.
    return await static_files.get_response("index.html", request.scope)


app.mount("/", static_files, name="static")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc):
    first_error = exc.errors()[0]
    field = first_error["loc"][1]
    org_msg = first_error["msg"]
    return JSONResponse(
        {"error": f"Error in field '{field}': {org_msg}"}, status_code=400
    )


@app.exception_handler(ClientError)
async def client_error_exception_handler(_, exc):
    return JSONResponse({"error": exc.args[0]}, status_code=400)


@app.exception_handler(Exception)
async def general_exception_handler(_, exc):
    return JSONResponse(
        {"error": "En ukjent feil oppstod. Vennligst prøv igjen."}, status_code=500
    )


def audit_log(
    search_params: SearchParams, response: Optional[CertificateSearchResponse]
):
    # ip = request.headers.get("X-Forwarded-For")
    # if not ip:
    # ip = request.remote

    status = "OK" if response is not None else "FAIL"

    audit_logger.info(
        "STATUS=%s IP=%s ENV=%s TYPE=%s QUERY='%s' ATTR='%s' RESULTS=%d CORRELATION_ID=%s",
        status,
        "dummy",
        search_params.env.value,
        search_params.typ.value,
        search_params.query,
        search_params.attr.value if search_params.attr else None,
        len(response.cert_sets) if response else 0,
        correlation_id_var.get(),
    )
