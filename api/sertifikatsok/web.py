import asyncio
import logging
import json
import argparse
import uvloop
import uuid
import aiotask_context as context
from aiohttp import web
from .search import CertificateSearch
from .logging import configure_logging, performance_log
from .errors import ClientError
from .crypto import AppCrlRetriever, CertRetriever
from .serialization import sertifikatsok_serialization

logger = logging.getLogger(__name__)


@web.middleware
async def error_middleware(request, handler):
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
    except:
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
async def correlation_middleware(request, handler):
    correlation_id = str(uuid.uuid4())
    context.set(key="correlation_id", value=correlation_id)
    request["correlation_id"] = correlation_id
    response = await handler(request)
    response.headers["Correlation-Id"] = correlation_id
    return response


async def init_app(app):
    app["CrlRetriever"] = AppCrlRetriever()
    app["CertRetrievers"] = {
        "test": CertRetriever.create("test"),
        "prod": CertRetriever.create("prod"),
    }


@performance_log()
async def api_endpoint(request):
    """
    ---
    description: Search after certificates.
    parameters:
        - in: query
          name: env
          type: string
          enum: [test, prod]
          description: The environment to search in
        - in: query
          name: type
          type: string
          enum: [personal, enterprise]
          description: The type of certificate
        - in: query
          name: query
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

    certificate_search = CertificateSearch.create_from_request(request)

    await asyncio.gather(*certificate_search.tasks)

    certificate_search.finish()

    # web.json_response() doesn't set ensure_ascii = False
    # so the æøås get messed up
    response = web.Response(
        text=json.dumps(
            certificate_search, ensure_ascii=False, default=sertifikatsok_serialization
        ),
        status=200,
        content_type="application/json",
    )

    if certificate_search.cacheable:
        cache_control = "public, max-age=300"
    else:
        cache_control = "no-cache, no-store, must-revalidate, private, s-maxage=0"

    response.headers["Cache-Control"] = cache_control

    return response


def run():
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.get_event_loop().set_task_factory(context.task_factory)

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

    if args.dev:
        from aiohttp_swagger import setup_swagger

        setup_swagger(app)

    web.run_app(app, port=args.port, host=args.host, path=args.path)
