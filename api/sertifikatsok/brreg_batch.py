from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Iterable

import httpx
from attrs import asdict, frozen

from sertifikatsok.enums import BatchResult
from sertifikatsok.logging import configure_logging, correlation_context

from .db import BatchRun, Database, Organization

# The first ID returned when asking for
# dato=2022-09-25T00:00:00.000Z, which is
# the initial load date.
INITIAL_UPDATE_ID = 15600739

BATCH_NAME = "batch-brreg-update"

MAIN_UPDATES_URL = httpx.URL(
    "https://data.brreg.no/enhetsregisteret/api/oppdateringer/enheter/"
)
CHILD_UPDATES_URL = httpx.URL(
    "https://data.brreg.no/enhetsregisteret/api/oppdateringer/underenheter/"
)
MAIN_SINGLE_URL = httpx.URL("https://data.brreg.no/enhetsregisteret/api/enheter/")
CHILD_SINGLE_URL = httpx.URL("https://data.brreg.no/enhetsregisteret/api/underenheter/")

MAX_UPDATE_FETCHES_PER_RUN = 500
USEFUL_UPDATES = ["Endring", "Ny"]

logger = logging.getLogger(__name__)


@frozen
class BrregBatchRun:
    main_updateid: int
    child_updateid: int

    def to_row(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_batch_run(cls, batch_run: BatchRun | None) -> BrregBatchRun | None:
        if batch_run is None:
            return None
        assert batch_run.data
        return cls(
            batch_run.data["main_updateid"],
            batch_run.data["child_updateid"],
        )


@frozen
class BrregUpdateResult:
    elements_left: int
    updated_units: set[str]
    highest_update_id: int


async def get_update_from_brreg(
    httpx_client: httpx.AsyncClient, url: httpx.URL, current_update_id: int
) -> BrregUpdateResult:
    resp = await httpx_client.get(url, params={"oppdateringsid": current_update_id + 1})
    resp.raise_for_status()
    resp_json = resp.json()

    total_elements = resp_json["page"]["totalElements"]
    if total_elements == 0:
        return BrregUpdateResult(
            elements_left=0, updated_units=set(), highest_update_id=current_update_id
        )

    embedded = resp_json["_embedded"]
    updated_units = embedded.get("oppdaterteEnheter") or embedded.get(
        "oppdaterteUnderenheter"
    )

    updates: set[str] = set()
    for unit in updated_units:
        if unit["oppdateringsid"] > current_update_id:
            current_update_id = unit["oppdateringsid"]

        if unit["endringstype"] in USEFUL_UPDATES:
            updates.add(unit["organisasjonsnummer"])

    elements_left = total_elements - len(updated_units)

    return BrregUpdateResult(elements_left, updates, current_update_id)


async def get_updates_from_brreg(
    httpx_client: httpx.AsyncClient, url: httpx.URL, current_update_id: int
) -> BrregUpdateResult:
    all_updates: set[str] = set()
    result = None
    for _ in range(MAX_UPDATE_FETCHES_PER_RUN):
        result = await get_update_from_brreg(httpx_client, url, current_update_id)
        all_updates.update(result.updated_units)
        current_update_id = result.highest_update_id

        if not result.elements_left:
            break

    assert result
    return BrregUpdateResult(result.elements_left, all_updates, current_update_id)


async def get_organizations_from_brreg(
    httpx_client: httpx.AsyncClient,
    url: httpx.URL,
    org_numbers: Iterable[str],
    is_children: bool,
) -> list[Organization]:
    all_orgs = []
    for org_number in org_numbers:
        resp = await httpx_client.get(url.join(org_number))
        if resp.status_code == 410:
            # Is to be expected if the unit has status 'Fjernet'
            continue

        resp.raise_for_status()
        raw_org = resp.json()

        if raw_org.get("slettedato") is not None:
            continue

        all_orgs.append(
            Organization(
                raw_org["organisasjonsnummer"],
                raw_org["navn"],
                is_children,
                raw_org.get("overordnetEnhet"),
            )
        )
    return all_orgs


async def update_organizations(
    httpx_client: httpx.AsyncClient,
    database: Database,
    last_updateid: int,
    children: bool,
) -> int:
    updates_url = CHILD_UPDATES_URL if children else MAIN_UPDATES_URL
    single_url = CHILD_SINGLE_URL if children else MAIN_SINGLE_URL

    update_result = await get_updates_from_brreg(
        httpx_client, updates_url, last_updateid
    )

    updated_organizations = await get_organizations_from_brreg(
        httpx_client, single_url, update_result.updated_units, is_children=children
    )

    database.upsert_organizations(updated_organizations)

    logger.info(
        "Updated %d %s organizations, %d changes left to process",
        len(updated_organizations),
        "child" if children else "main",
        update_result.elements_left,
    )
    return update_result.highest_update_id


async def fetch_and_store_updates(
    database: Database,
    httpx_client: httpx.AsyncClient,
    last_run: BrregBatchRun | None,
) -> BrregBatchRun:
    if last_run is None:
        last_run = BrregBatchRun(
            INITIAL_UPDATE_ID,
            INITIAL_UPDATE_ID,
        )

    main_updateid = await update_organizations(
        httpx_client, database, last_run.main_updateid, children=False
    )

    child_updateid = await update_organizations(
        httpx_client, database, last_run.child_updateid, children=True
    )
    return BrregBatchRun(main_updateid, child_updateid)


async def run_batch(database: Database, httpx_client: httpx.AsyncClient) -> None:
    with correlation_context() as uuid:
        logger.info("Starting %s", BATCH_NAME)
        try:
            last_run = database.get_last_successful_batch_run(BATCH_NAME)
            logger.debug("Last run: %s", last_run)
            batch_run = await fetch_and_store_updates(
                database, httpx_client, BrregBatchRun.from_batch_run(last_run)
            )
        except Exception:
            logger.exception("Exception during %s", BATCH_NAME)
            database.add_batch_run(BATCH_NAME, uuid, BatchResult.ERROR, None)
        else:
            logger.info("%s finished successfully", BATCH_NAME)
            database.add_batch_run(BATCH_NAME, uuid, BatchResult.OK, batch_run.to_row())


def get_seconds_to_next_run() -> float:
    now = datetime.utcnow()
    two_am = now.replace(hour=2, minute=0, second=0, microsecond=0)
    if now > two_am:
        two_am = two_am + timedelta(days=1)
    return (two_am - now).total_seconds()


async def run_batch_when_scheduled(database: Database) -> None:
    while True:
        sleep_seconds = get_seconds_to_next_run()
        logger.debug("Scheduling %s in %d seconds", BATCH_NAME, sleep_seconds)
        await asyncio.sleep(sleep_seconds)
        async with httpx.AsyncClient() as httpx_client:
            await run_batch(database, httpx_client)


def schedule_batch(database: Database) -> None:
    # Hackish? Yes. Works? Also yes.
    asyncio.ensure_future(run_batch_when_scheduled(database))


async def run_adhoc() -> None:
    configure_logging(logging.DEBUG, None)

    async with httpx.AsyncClient() as httpx_client:
        await run_batch(Database.connect_to_database(), httpx_client)


if __name__ == "__main__":
    asyncio.run(run_adhoc())
