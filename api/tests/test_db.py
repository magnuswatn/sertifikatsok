from sqlite3 import IntegrityError

import pytest

from sertifikatsok.db import Database


@pytest.fixture
def database() -> Database:
    return Database.connect_to_database(":memory:")


def test_organization_child(database: Database) -> None:
    database._connection.execute(
        """
            INSERT INTO organization (orgnr, name, is_child, parent_orgnr)
                 VALUES ('991056505', 'APOTEK 1 ULRIKSDAL', TRUE, '983044778')
            """
    )


def test_organization_parent(database: Database) -> None:
    database._connection.execute(
        """
            INSERT INTO organization (orgnr, name, is_child, parent_orgnr)
                 VALUES ('983044778', 'APOTEK 1 GRUPPEN AS', FALSE, NULL)
            """
    )


def test_organization_parent_with_parent(database: Database) -> None:
    database._connection.execute(
        """
            INSERT INTO organization (orgnr, name, is_child, parent_orgnr)
                 VALUES ('970188223', 'TRONDHEIM KOMMUNE HELSE OG VELFERD', FALSE, '942110464')
            """
    )


def test_organization_childs_MUST_have_parent_check(database: Database) -> None:
    with pytest.raises(IntegrityError):
        database._connection.execute(
            """
            INSERT INTO organization (orgnr, name, is_child, parent_orgnr)
                 VALUES ('991056505', 'APOTEK 1 ULRIKSDAL', TRUE, NULL)
            """
        )


def test_certificate_foreign_key(database: Database) -> None:
    with pytest.raises(IntegrityError):
        database._connection.execute(
            """
            INSERT INTO certificate (sha1,
                                     sha2,
                                     distinguished_name,
                                     l_id)
            VALUES ('sha1', 'sha2', 'CN=hei', 39999)
        """
        )


@pytest.mark.parametrize(
    "org_values",
    [
        {
            "orgnr": "991056505",
            "name": "APOTEK 1 ULRIKSDAL",
            "is_child": True,
            "parent_orgnr": "983044778",
        },
        {
            "orgnr": "970188223",
            "name": "TRONDHEIM KOMMUNE HELSE OG VELFERD",
            "is_child": False,
            "parent_orgnr": "942110464",
        },
        {
            "orgnr": "995546973",
            "name": "WATN IT SYSTEM Magnus Horsgård Watn",
            "is_child": False,
            "parent_orgnr": None,
        },
    ],
)
def test_get_organization_mapping(
    database: Database, org_values: dict[str, str]
) -> None:
    database._connection.execute(
        """
            INSERT OR REPLACE INTO organization (orgnr, name, parent_orgnr, is_child)
            VALUES (:orgnr, :name, :parent_orgnr, :is_child)
        """,
        org_values,
    )
    database._connection.commit()
    org = database.get_organization(org_values["orgnr"])
    assert org is not None
    assert org.orgnr == org_values["orgnr"]
    assert org.name == org_values["name"]
    assert org.is_child is org_values["is_child"]
    assert org.parent_orgnr == org_values["parent_orgnr"]
