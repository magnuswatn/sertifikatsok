import argparse
import asyncio
import json
import logging

import uvloop
from aiohttp import web
from aiohttp.typedefs import Handler
from aiohttp.web_response import StreamResponse

from .audit_log import AuditLogger
from .brreg_batch import schedule_batch
from .crypto import AppCrlRetriever, CertRetriever, CrlDownloader
from .db import Database
from .enums import Environment
from .errors import ClientError
from .logging import configure_logging, correlation_context, performance_log
from .search import CertificateSearch
from .serialization import sertifikatsok_serialization

logger = logging.getLogger(__name__)


@web.middleware
async def error_middleware(request: web.Request, handler: Handler) -> StreamResponse:
    try:
        return await handler(request)
    except web.HTTPException:  # pylint: disable=E0705
        raise
    except ClientError as error:
        return web.Response(
            text=json.dumps({"error": error.args[0]}, ensure_ascii=False),
            status=400,
            content_type="application/json",
        )
    except Exception:
        logger.exception("An exception occured:")
        return web.Response(
            text=json.dumps(
                {"error": "En ukjent feil oppstod. Vennligst prøv igjen."},
                ensure_ascii=False,
            ),
            status=500,
            content_type="application/json",
        )


@web.middleware
async def correlation_middleware(
    request: web.Request, handler: Handler
) -> StreamResponse:
    with correlation_context() as correlation_id:
        response = await handler(request)
        response.headers["Correlation-Id"] = str(correlation_id)
        return response


async def init_app(app: web.Application) -> None:
    app["CrlRetriever"] = AppCrlRetriever(CrlDownloader())
    app["CertRetrievers"] = {
        Environment.TEST: CertRetriever.create(Environment.TEST),
        Environment.PROD: CertRetriever.create(Environment.PROD),
    }
    app["Database"] = Database.connect_to_database()
    schedule_batch(app["Database"])


@performance_log()
async def api_endpoint(request: web.Request) -> web.Response:
    """
    ---
    description: Search after certificates.
    parameters:
        - in: query
          name: env
          type: string
          required: true
          enum: [test, prod]
          description: The environment to search in
        - in: query
          name: type
          required: true
          type: string
          enum: [personal, enterprise]
          description: The type of certificate
        - in: query
          name: attr
          type: string
          enum: [cn, mail, ou, o, serialNumber, certificateSerialNumber, organizationIdentifier]
          description: The ldap attribute to search by (optional)
        - in: query
          name: query
          required: true
          type: string
          description: The search query

    produces:
        - application/json
    responses:
        "200":
            description: Search OK.
        "400":
            description: Invalid parameters.
        "500":
            description: Technical error in the API.
    """
    with AuditLogger(request) as audit_logger:
        certificate_search = CertificateSearch.create_from_request(request)

        search_response = await certificate_search.get_response()
        audit_logger.set_results(search_response)

        # web.json_response() doesn't set ensure_ascii = False
        # so the æøås get messed up
        response = web.Response(
            text=json.dumps(
                search_response, ensure_ascii=False, default=sertifikatsok_serialization
            ),
            status=200,
            content_type="application/json",
        )

        if search_response.cacheable and not request.app["dev"]:
            cache_control = "public, max-age=300"
        else:
            cache_control = "no-cache, no-store, must-revalidate, private, s-maxage=0"

        response.headers["Cache-Control"] = cache_control

        return response


def run() -> None:
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    parser = argparse.ArgumentParser(description="Sertifikatsok API")
    parser.add_argument("--host")
    parser.add_argument("--path")
    parser.add_argument("--port")
    parser.add_argument("--log-level")
    parser.add_argument("--log-files")
    parser.add_argument("--dev", action="store_true")

    args = parser.parse_args()

    if args.log_level:
        log_level = getattr(logging, args.log_level)
    elif args.dev:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    configure_logging(log_level, args.log_files)

    app = web.Application(middlewares=[error_middleware, correlation_middleware])
    app.router.add_get("/api", api_endpoint)
    app.on_startup.append(init_app)
    app["dev"] = False

    if args.dev:
        from aiohttp_swagger import setup_swagger  # type: ignore

        setup_swagger(app)

        app["dev"] = True

    web.run_app(app, port=args.port, host=args.host, path=args.path)
