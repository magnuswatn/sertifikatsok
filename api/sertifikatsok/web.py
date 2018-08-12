import asyncio
import logging
import json
import argparse
import uvloop
from aiohttp import web
from .search import CertificateSearch
from .errors import ClientError

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


def validate_query(query):

    if query.get("env") not in ["prod", "test"]:
        raise ClientError("Unknown environment")

    if query.get("type") not in ["enterprise", "person"]:
        raise ClientError("Unknown certificate type")

    if not query.get("query"):
        raise ClientError("Missing query parameter)")


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
          enum: [person, enterprise]
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

    validate_query(request.query)

    certificate_search = CertificateSearch(request.query)

    await asyncio.gather(*certificate_search.get_tasks())

    # web.json_response() doesn't set ensure_ascii = False
    # so the æøås get messed up
    response = web.Response(
        text=json.dumps(certificate_search.get_result(), ensure_ascii=False),
        status=200,
        content_type="application/json",
    )

    response.headers[
        "Cache-Control"
    ] = "no-cache, no-store, must-revalidate, private, s-maxage=0"

    return response


def run():
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    parser = argparse.ArgumentParser(description="Sertifikatsok API")
    parser.add_argument("--host")
    parser.add_argument("--path")
    parser.add_argument("--port")
    parser.add_argument("--log-level")
    parser.add_argument("--dev", action="store_true")

    args = parser.parse_args()

    if args.log_level:
        log_level = getattr(logging, args.log_level)
    elif args.dev:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(level=log_level)

    app = web.Application(middlewares=[error_middleware])
    app.router.add_get("/api", api_endpoint)

    if args.dev:
        from aiohttp_swagger import setup_swagger

        setup_swagger(app)

    web.run_app(app, port=args.port, host=args.host, path=args.path)