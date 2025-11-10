import os
from email.utils import parsedate
from mimetypes import guess_file_type
from pathlib import Path
from typing import Self

from attrs import frozen
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import FileResponse, Response
from starlette.staticfiles import NotModifiedResponse

NORMAL_CACHE_CONTROL = "max-age=300"
IMMUTABLE_CACHE_CONTROL = "max-age=31536000, immutable"


@frozen
class StaticFile:
    path: Path
    stat_result: os.stat_result


@frozen
class StaticResource:
    media_type: str | None
    cache_control: str
    org_file: StaticFile
    br_file: StaticFile | None


@frozen
class StaticResourceHandler:
    path_to_resource: dict[str, StaticResource]

    @classmethod
    def create(cls, dist: Path | None = None) -> Self:
        if dist is None:
            dist = dist if (dist := Path("../www/dist")).exists() else dist.parent

        path_to_resource: dict[str, StaticResource] = {}
        for path in dist.iterdir():
            if path.is_dir():
                cache_control = (
                    IMMUTABLE_CACHE_CONTROL
                    if path.name in ("assets", "resources")
                    else NORMAL_CACHE_CONTROL
                )
                cls.add_folder(path_to_resource, f"/{path.name}", path, cache_control)
            elif path.suffix != ".br":
                resource_path = "/" if path.name == "index.html" else path.name
                path_to_resource[resource_path] = cls.create_static_file_for_path(
                    path, NORMAL_CACHE_CONTROL
                )

        return cls(path_to_resource)

    @classmethod
    def add_folder(
        cls,
        path_to_resource: dict[str, StaticResource],
        prefix: str,
        in_path: Path,
        cache_control: str,
    ) -> None:
        for path in in_path.iterdir():
            if path.is_dir():
                cls.add_folder(
                    path_to_resource, f"{prefix}/{path.name}", path, cache_control
                )
                continue
            if path.suffix == ".br":
                continue

            path_to_resource[f"{prefix}/{path.name}"] = cls.create_static_file_for_path(
                path, cache_control
            )

    @staticmethod
    def create_static_file_for_path(path: Path, cache_control: str) -> StaticResource:
        uncompressed_file = StaticFile(path, path.stat())

        br_file = (
            StaticFile(br_path, br_path.stat())
            if (br_path := path.with_suffix(f"{path.suffix}.br")).exists()
            else None
        )

        file_typ, _ = guess_file_type(path)

        return StaticResource(file_typ, cache_control, uncompressed_file, br_file)

    async def handle_static_request(self, request: Request) -> Response:
        static_resource = self.path_to_resource.get(request.url.path)

        if static_resource is None:
            return Response(status_code=404)

        headers = {"cache-control": static_resource.cache_control}

        if static_resource.br_file is None or "br" not in request.headers.get(
            "accept-encoding", ""
        ):
            file_to_serve = static_resource.org_file
        else:
            file_to_serve = static_resource.br_file
            headers["content-encoding"] = "br"
            headers["vary"] = "accept-encoding"

        response = FileResponse(
            file_to_serve.path,
            headers=headers,
            media_type=static_resource.media_type,
            stat_result=file_to_serve.stat_result,
        )

        if self.is_not_modified(response.headers, request.headers):
            return NotModifiedResponse(response.headers)
        return response

    @staticmethod
    def is_not_modified(response_headers: Headers, request_headers: Headers) -> bool:
        """
        Borrowed from Starlette.
        """
        try:
            if_none_match = request_headers["if-none-match"]
            etag = response_headers["etag"]
            if etag in [tag.strip(" W/") for tag in if_none_match.split(",")]:
                return True
        except KeyError:
            pass

        try:
            if_modified_since = parsedate(request_headers["if-modified-since"])
            last_modified = parsedate(response_headers["last-modified"])
            if (
                if_modified_since is not None
                and last_modified is not None
                and if_modified_since >= last_modified
            ):
                return True
        except KeyError:
            pass

        return False
