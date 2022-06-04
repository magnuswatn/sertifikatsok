import json
import logging
import os
import uuid
from functools import lru_cache
from typing import Optional

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .crypto import AppCrlRetriever, CertRetriever, CertValidator
from .enums import CertType, Environment, SearchAttribute
from .errors import ClientError
from .logging import configure_logging, correlation_id_var, performance_log
from .search import CertificateSearch, SearchParams
from .serialization import sertifikatsok_serialization
from .starlette_precompressed_static import PreCompressedStaticFiles

logger = logging.getLogger(__name__)

app = FastAPI()

DEV = bool(os.getenv("SERTIFIKATSOK_DEBUG"))


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)
    response = await call_next(request)
    response.headers["Correlation-Id"] = correlation_id
    return response


@lru_cache
def cert_retriever(env: Environment) -> CertRetriever:
    return CertRetriever.create(env)


@lru_cache
def crl_retriever() -> AppCrlRetriever:
    return AppCrlRetriever()


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
    crl_retriever()
    # We need to use kwargs here so the
    # lru_cache works as intended, as that
    # is what FastAPI does.
    cert_retriever(env=Environment.TEST)
    cert_retriever(env=Environment.PROD)


@performance_log()
@app.get("/api")
async def api_endpoint(
    env: Environment,
    type: CertType,
    query: str,
    attr: Optional[SearchAttribute] = None,
    cert_validator: CertValidator = Depends(cert_validator),
):
    search_params = SearchParams(env, type, query, attr)
    certificate_search = CertificateSearch.create(search_params, cert_validator)

    search_response = await certificate_search.get_response()

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


@app.get("/")
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
