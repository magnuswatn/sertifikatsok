import random
from math import ceil
from typing import Any, Literal
from uuid import uuid4

import httpx
import pytest
from attr import frozen

from sertifikatsok.brreg_batch import (
    BATCH_NAME,
    CHILD_SINGLE_URL,
    CHILD_UPDATES_URL,
    INITIAL_UPDATE_ID,
    MAIN_SINGLE_URL,
    MAIN_UPDATES_URL,
    MAX_UPDATE_FETCHES_PER_RUN,
    BrregBatchRun,
    run_batch,
)
from sertifikatsok.db import Database, Organization
from sertifikatsok.enums import BatchResult


@pytest.fixture
def database() -> Database:
    return Database.connect_to_database(":memory:")


@frozen
class ChangedOrganization(Organization):
    removed: bool  # 410 GONE
    deleted: bool  # with "slettedato"
    disappeared: bool  # 404 not found
    change_type: Literal["Ny"] | Literal["Endring"] | Literal["Sletting"]

    def __attrs_post_init__(self) -> None:
        if self.change_type == "Sletting":
            assert self.deleted

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Organization):
            return False

        return all(
            [
                self.orgnr == other.orgnr,
                self.name == other.name,
                self.is_child == other.is_child,
                self.parent_orgnr == other.parent_orgnr,
            ]
        )


def generate_update_list(
    start_update_id: int, units: list[ChangedOrganization]
) -> tuple[dict[int, dict], int]:
    # The update_ids from brreg have holes in them, so let's generate a range five time
    # as long as needed, and then take the amount we need from that.
    full_update_id_range = range(start_update_id, int(start_update_id + len(units) * 5))
    update_ids = sorted(random.sample(full_update_id_range, len(units)))

    return {
        update_id: {
            "oppdateringsid": update_id,
            "dato": "2022-10-31T05:04:09.595Z",
            "organisasjonsnummer": changed_org.orgnr,
            "endringstype": changed_org.change_type,
            "_links": {
                "underenhet"
                if changed_org.is_child
                else "enhet": {
                    "href": "https://data.brreg.no/enhetsregisteret/api/"
                    + (
                        f"underenheter/{changed_org.orgnr}"
                        if changed_org.is_child
                        else f"enheter/{changed_org.orgnr}"
                    )
                }
            },
        }
        for update_id, changed_org in zip(update_ids, units)
    }, update_ids[-1]


def generate_single_unit_resp(changed_org: ChangedOrganization) -> dict:
    single_unit_resp = {
        "organisasjonsnummer": changed_org.orgnr,
        "navn": f"Nytt navn på {changed_org.orgnr}",
    }
    if changed_org.parent_orgnr:
        single_unit_resp["overordnetEnhet"] = changed_org.parent_orgnr
    if changed_org.deleted:
        single_unit_resp["slettedato"] = "2022-10-31T05:04:09.595Z"
    return single_unit_resp


def generate_base_updates_resp(
    units: dict[int, dict],
    typ: Literal["oppdaterteEnheter"] | Literal["oppdaterteUnderenheter"],
    params: httpx.QueryParams,
) -> dict:
    oppdateringid = int(params["oppdateringsid"])

    all_units_after_this_update = [
        unit for update_id, unit in sorted(units.items()) if update_id >= oppdateringid
    ]

    total_units = len(all_units_after_this_update)
    total_pages = ceil(total_units / 20)

    units_to_return = all_units_after_this_update[:20]

    return {
        "_embedded": {typ: units_to_return},
        "_links": {
            "first": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/"
                f"enheter?oppdateringsid={oppdateringid}&page=0&size=20"
            },
            "self": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/"
                f"enheter?oppdateringsid={oppdateringid}"
            },
            "next": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/"
                f"enheter?oppdateringsid={oppdateringid}&page=0&size=20"
            },
            "last": {
                "href": "https://data.brreg.no/enhetsregisteret/api/oppdateringer/"
                f"enheter?oppdateringsid={oppdateringid}&page=21&size=20"
            },
        },
        "page": {
            "size": len(units_to_return),
            "totalElements": total_units,
            "totalPages": total_pages,
            "number": 0,
        },
    }


def get_mock_httpx_client(
    main_units: dict[int, dict],
    child_units: dict[int, dict],
    all_main_units: list[ChangedOrganization],
    all_child_units: list[ChangedOrganization],
) -> httpx.AsyncClient:
    def transport_handler(request: httpx.Request) -> httpx.Response:
        status_code = 200
        if request.url.path == MAIN_UPDATES_URL.path:
            body = generate_base_updates_resp(
                main_units, "oppdaterteEnheter", request.url.params
            )
        elif request.url.path == CHILD_UPDATES_URL.path:
            body = generate_base_updates_resp(
                child_units,
                "oppdaterteUnderenheter",
                request.url.params,
            )
        elif request.url.path.startswith(MAIN_SINGLE_URL.path):
            org_nr = request.url.path.split("/")[-1]
            [org] = [org for org in all_main_units if org.orgnr == org_nr]
            if org.removed:
                status_code = 410
                body = None
            elif org.disappeared:
                status_code = 404
                body = None
            else:
                body = generate_single_unit_resp(org)
        elif request.url.path.startswith(CHILD_SINGLE_URL.path):
            org_nr = request.url.path.split("/")[-1]
            [org] = [org for org in all_child_units if org.orgnr == org_nr]
            if org.removed:
                status_code = 410
                body = None
            elif org.disappeared:
                status_code = 404
                body = None
            else:
                body = generate_single_unit_resp(org)
        else:
            raise NotImplementedError(request.url.path)

        return httpx.Response(status_code, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))


async def test_no_updates(database: Database) -> None:
    assert database.get_last_successful_batch_run(BATCH_NAME) is None

    httpx_client = get_mock_httpx_client({}, {}, [], [])
    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == INITIAL_UPDATE_ID
    assert batch_data.child_updateid == INITIAL_UPDATE_ID


async def test_starts_from_where_it_left_of(database: Database) -> None:
    main_org = ChangedOrganization(
        "012345678",
        "Gammelt navn på 012345678",
        is_child=False,
        parent_orgnr=None,
        removed=False,
        deleted=True,
        disappeared=False,
        change_type="Sletting",
    )
    child_org = ChangedOrganization(
        "123456789",
        "Gammelt navn på 123456789",
        is_child=True,
        parent_orgnr="234567890",
        removed=False,
        deleted=True,
        disappeared=False,
        change_type="Sletting",
    )

    database.add_batch_run(
        BATCH_NAME,
        uuid4(),
        BatchResult.OK,
        # lower than INITIAL_UPDATE_ID
        {"main_updateid": 200000, "child_updateid": 300000},
    )

    main_update_list, max_main_update_id = generate_update_list(200001, [main_org])
    child_update_list, max_child_update_id = generate_update_list(300001, [child_org])

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        # Emtpy lists, as change_type="Sletting" should not
        # trigger a query for the org itself
        [],
        [],
    )
    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id


async def test_updates_exisiting_orgs(database: Database) -> None:
    existing_main_org = ChangedOrganization(
        "012345678",
        "Gammelt navn på 012345678",
        is_child=False,
        parent_orgnr=None,
        removed=False,
        deleted=False,
        disappeared=False,
        change_type="Endring",
    )
    existing_child_org = ChangedOrganization(
        "123456789",
        "Gammelt navn på 123456789",
        is_child=True,
        parent_orgnr="234567890",
        removed=False,
        deleted=False,
        disappeared=False,
        change_type="Endring",
    )

    database.upsert_organizations([existing_main_org, existing_child_org])
    assert database.get_organization(existing_main_org.orgnr) == existing_main_org
    assert database.get_organization(existing_child_org.orgnr) == existing_child_org

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 1, [existing_main_org]
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 2, [existing_child_org]
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        [existing_main_org],
        [existing_child_org],
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    for existing_org in existing_main_org, existing_child_org:
        new_org = database.get_organization(existing_org.orgnr)
        assert new_org
        assert new_org != existing_org
        assert new_org.name == f"Nytt navn på {existing_org.orgnr}"


async def test_handles_gone_orgs(database: Database) -> None:
    existing_main_org = ChangedOrganization(
        "012345678",
        "Gammelt navn på 012345678",
        is_child=False,
        parent_orgnr=None,
        removed=True,
        deleted=False,
        disappeared=False,
        change_type="Endring",
    )
    existing_child_org = ChangedOrganization(
        "123456789",
        "Gammelt navn på 123456789",
        is_child=True,
        parent_orgnr="234567890",
        removed=True,
        deleted=False,
        disappeared=False,
        change_type="Endring",
    )

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 13, [existing_main_org]
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 24, [existing_child_org]
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        [existing_main_org],
        [existing_child_org],
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None


async def test_handles_mysteriously_disappeared_orgs(database: Database) -> None:
    existing_main_org = ChangedOrganization(
        "931221671",
        "Gammelt navn på 931221671",
        is_child=False,
        parent_orgnr=None,
        removed=False,
        deleted=False,
        disappeared=True,
        change_type="Ny",
    )
    existing_child_org = ChangedOrganization(
        "931164147",
        "Gammelt navn på 931164147",
        is_child=True,
        parent_orgnr="234567890",
        removed=False,
        deleted=False,
        disappeared=True,
        change_type="Ny",
    )

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 13, [existing_main_org]
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 24, [existing_child_org]
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        [existing_main_org],
        [existing_child_org],
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None


async def test_handles_changed_org_but_later_deleted(database: Database) -> None:
    existing_main_org = ChangedOrganization(
        "012345678",
        "Gammelt navn på 012345678",
        is_child=False,
        parent_orgnr=None,
        removed=False,
        deleted=True,
        disappeared=False,
        change_type="Endring",
    )
    existing_child_org = ChangedOrganization(
        "123456789",
        "Gammelt navn på 123456789",
        is_child=True,
        parent_orgnr="234567890",
        removed=False,
        deleted=True,
        disappeared=False,
        change_type="Endring",
    )

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 1700, [existing_main_org]
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 2600, [existing_child_org]
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        [existing_main_org],
        [existing_child_org],
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    assert database.get_organization(existing_main_org.orgnr) is None
    assert database.get_organization(existing_child_org.orgnr) is None


async def test_handles_several_pages(database: Database) -> None:
    main_orgs = [
        ChangedOrganization(
            str(org_nr),
            f"Nytt navn på {org_nr}",
            is_child=False,
            parent_orgnr=None,
            removed=False,
            deleted=False,
            disappeared=False,
            change_type="Endring",
        )
        for org_nr in range(989643214, 989643284)
    ]

    child_orgs = [
        ChangedOrganization(
            str(org_nr),
            f"Nytt navn på {org_nr}",
            is_child=True,
            parent_orgnr=str(org_nr - 40000),
            removed=False,
            deleted=False,
            disappeared=False,
            change_type="Endring",
        )
        for org_nr in range(969643214, 969643284)
    ]

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 1, main_orgs
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 320, child_orgs
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        main_orgs,
        child_orgs,
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    for org in main_orgs + child_orgs:
        assert database.get_organization(org.orgnr) == org


async def test_doesnt_update_more_than_limit(database: Database) -> None:
    main_orgs = [
        ChangedOrganization(
            str(org_nr),
            f"Nytt navn på {org_nr}",
            is_child=False,
            parent_orgnr=str(org_nr - 10000),
            removed=False,
            deleted=False,
            disappeared=False,
            change_type="Endring",
        )
        for org_nr in range(989643214, 989643214 + (MAX_UPDATE_FETCHES_PER_RUN * 30))
    ]

    child_orgs = [
        ChangedOrganization(
            str(org_nr),
            f"Nytt navn på {org_nr}",
            is_child=True,
            parent_orgnr=str(org_nr - 40000),
            removed=False,
            deleted=False,
            disappeared=False,
            change_type="Endring",
        )
        for org_nr in range(969643214, 969643214 + (MAX_UPDATE_FETCHES_PER_RUN * 30))
    ]

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 1, main_orgs
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 320, child_orgs
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        main_orgs,
        child_orgs,
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    # We expect the batch to read MAX_UPDATE_FETCHES_PER_RUN pages,
    # with 20 in each pages. So we need to find the expected update ids
    first_run_max_main_update_id = sorted(main_update_list.keys())[
        : (MAX_UPDATE_FETCHES_PER_RUN * 20) :
    ][-1]
    first_run_max_child_update_id = sorted(child_update_list.keys())[
        : (MAX_UPDATE_FETCHES_PER_RUN * 20)
    ][-1]

    assert batch_data.main_updateid == first_run_max_main_update_id
    assert batch_data.child_updateid == first_run_max_child_update_id

    for org_list in [main_orgs, child_orgs]:
        # The first batch should be loaded
        for x in range(MAX_UPDATE_FETCHES_PER_RUN * 20):
            org = org_list[x]
            assert database.get_organization(org.orgnr) == org

        # the next batch should NOT be loaded
        for x in range(
            MAX_UPDATE_FETCHES_PER_RUN * 20, MAX_UPDATE_FETCHES_PER_RUN * 30
        ):
            org = org_list[x]
            assert database.get_organization(org.orgnr) is None

    # run again
    await run_batch(database, httpx_client)

    # Every org should now be loaded
    for org in main_orgs + child_orgs:
        assert database.get_organization(org.orgnr) == org

    batch_data2 = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data2 is not None

    assert batch_data2.main_updateid == max_main_update_id
    assert batch_data2.child_updateid == max_child_update_id


async def test_inserts_new_organizations(database: Database) -> None:
    main_org = ChangedOrganization(
        "012345678",
        "Nytt navn på 012345678",
        is_child=False,
        parent_orgnr="123456789",
        removed=False,
        deleted=False,
        disappeared=False,
        change_type="Ny",
    )
    child_org = ChangedOrganization(
        "123456789",
        "Nytt navn på 123456789",
        is_child=True,
        parent_orgnr="123456789",
        removed=False,
        deleted=False,
        disappeared=False,
        change_type="Ny",
    )

    assert database.get_organization(main_org.orgnr) is None
    assert database.get_organization(child_org.orgnr) is None

    main_update_list, max_main_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 100, [main_org]
    )
    child_update_list, max_child_update_id = generate_update_list(
        INITIAL_UPDATE_ID + 200, [child_org]
    )

    httpx_client = get_mock_httpx_client(
        main_update_list,
        child_update_list,
        [main_org],
        [child_org],
    )

    await run_batch(database, httpx_client)

    batch_data = BrregBatchRun.from_batch_run(
        database.get_last_successful_batch_run(BATCH_NAME)
    )
    assert batch_data is not None

    assert batch_data.main_updateid == max_main_update_id
    assert batch_data.child_updateid == max_child_update_id

    new_main_org = database.get_organization(main_org.orgnr)
    assert new_main_org == main_org

    new_child_org = database.get_organization(child_org.orgnr)
    assert new_child_org == child_org
