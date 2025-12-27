from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from lxml.html import iterlinks  # type: ignore
from yarl import URL

from sertifikatsok.utils import datetime_now_utc


class Client:
    def __init__(self, httpx_client: httpx.Client) -> None:
        self.httpx_client = httpx_client

    def get(self, path: str, accept_encoding: str | None = None) -> httpx.Response:
        path = path[1:] if path.startswith("/") else path
        resp = self.httpx_client.get(
            f"http://sertifikatsok:7001/{path}",
            headers={"accept-encoding": accept_encoding or ""},
        )
        return resp

    def _get_and_verify_link(self, link: URL) -> None:
        assert not link.absolute
        no_compression_rep = self.get(str(link))
        assert no_compression_rep.status_code == 200
        assert "content-encoding" not in no_compression_rep.headers

        compression_rep = self.get(str(link), "br")
        assert compression_rep.status_code == 200
        assert compression_rep.headers["content-encoding"] == "br"
        assert compression_rep.headers["vary"] == "accept-encoding"

        # (httpx magically decodes the brotli for us)
        assert no_compression_rep.content == compression_rep.content


def test_security_txt_doesnt_expire_in_the_next_five_weeks() -> None:
    security_txt = Path("../www/public/.well-known/security.txt").read_text()

    [expire_line] = [
        line for line in security_txt.splitlines() if line.startswith("Expires: ")
    ]
    _, _, expire_timestamp = expire_line.partition(": ")
    expires = datetime.fromisoformat(expire_timestamp)
    assert expires > (datetime_now_utc() + timedelta(weeks=5))


@pytest.mark.apitest
@pytest.mark.parametrize("compression", [False, True])
def test_get_index(*, compression: bool) -> None:
    client = Client(httpx.Client())

    resp = client.get("/", accept_encoding="mordi,br,fardi" if compression else None)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")

    if compression:
        assert resp.headers["content-encoding"] == "br"
        assert resp.headers["vary"] == "accept-encoding"
    else:
        assert "content-encoding" not in resp.headers

    has_links = False
    for link in iterlinks(resp.content):
        has_links = True
        link_dest = URL(link[2])  # pyright: ignore[reportIndexIssue]
        if link_dest == URL("https://github.com/magnuswatn/sertifikatsok"):
            continue
        client._get_and_verify_link(link_dest)

    assert has_links
