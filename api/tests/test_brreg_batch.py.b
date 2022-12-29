import httpx
import pytest

from sertifikatsok.db import Database
from sertifikatsok.brreg_batch import fetch_and_store_updates


def get_mock_httpx_client(units: list[dict]) -> httpx.AsyncClient:
    resp = {
        "_embedded": {"oppdaterteEnheter": units},
        "_links": {
            "first": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/enheter?oppdateringsid=1592999&page=0&size=20"
            },
            "self": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/enheter?oppdateringsid=1592999"
            },
            "next": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/enheter?oppdateringsid=1592999&page=1&size=20"
            },
            "last": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/enheter?oppdateringsid=1592999&page=383445&size=20"
            },
        },
        "page": {
            "size": 20,
            "totalElements": 7668912,
            "totalPages": 383446,
            "number": 0,
        },
    }
    return httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json=resp,
            )
        )
    )


@pytest.fixture
def database() -> Database:
    return Database.connect_to_database(":memory:")



async def test_no_updates(database: Database) -> None:
    httpx_client = get_mock_httpx_client([])
    await fetch_and_store_updates(httpx_client, database, None)


async def update_
