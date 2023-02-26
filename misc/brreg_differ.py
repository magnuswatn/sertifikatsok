"""
Script to check that every active organization from brreg is in the local db.
"""
import gzip
import json
import sqlite3

import httpx


def _check_if_org_exist_in_db(
    connection: sqlite3.Connection,
    orgnr: str,
    navn: str,
    parent_unit: str | None,
    is_child: bool,
) -> str | None:
    result = connection.execute(
        """
        SELECT orgnr,
               name,
               is_child,
               parent_orgnr
          FROM organization
         WHERE orgnr = :orgnr
        """,
        {"orgnr": orgnr},
    ).fetchone()
    if result is None:
        print(f"Org {orgnr} - {navn} missing")
        return orgnr
    if (result[0], result[1], bool(result[2]), result[3]) != (
        orgnr,
        navn,
        is_child,
        parent_unit,
    ):
        print(f"Org {orgnr} - {navn} exists, but not with correct data")
        return orgnr
    return None


def main() -> None:
    print("Connecting to db")
    connection = sqlite3.connect("../api/database/database.db")

    client = httpx.Client()

    print("Downloading organizations")
    parent_response = client.get(
        "https://data.brreg.no/enhetsregisteret/api/enheter/lastned",
        headers={
            "Accept": "application/vnd.brreg.enhetsregisteret.enhet.v1+gzip;charset=UTF-8"
        },
    )

    print("Parsing organizations")
    parents = json.loads(gzip.decompress(parent_response.content))
    del parent_response

    print("Diffing parent organizations")
    missing_or_wrong_parent_orgs = [
        _check_if_org_exist_in_db(
            connection,
            parent["organisasjonsnummer"],
            parent["navn"],
            parent.get("overordnetEnhet"),
            is_child=False,
        )
        for parent in parents
    ]

    print("Downloading child organizations")
    child_response = client.get(
        "https://data.brreg.no/enhetsregisteret/api/underenheter/lastned",
        headers={
            "Accept": "application/vnd.brreg.enhetsregisteret.underenhet.v1+gzip;charset=UTF-8"
        },
    )

    print("Parsing child organizations")
    childs = json.loads(gzip.decompress(child_response.content))
    del child_response

    print("Diffing child organizations")
    missing_or_wrong_child_orgs = [
        _check_if_org_exist_in_db(
            connection,
            child["organisasjonsnummer"],
            child["navn"],
            child["overordnetEnhet"],
            is_child=True,
        )
        for child in childs
    ]
    print("*** Summary ***")
    print("The following main organizations is not up to date:")
    print(",".join([x for x in missing_or_wrong_parent_orgs if x]))
    print("The following child organizations is not up to date:")
    print(",".join([x for x in missing_or_wrong_child_orgs if x]))


if __name__ == "__main__":
    main()
