import gzip
import json
import sqlite3

import httpx


def main():
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

    print("Downloading child organizations")
    child_response = client.get(
        "https://data.brreg.no/enhetsregisteret/api/underenheter/lastned",
        headers={
            "Accept": "application/vnd.brreg.enhetsregisteret.underenhet.v1+gzip;charset=UTF-8"
        },
    )

    print("Parsing child organizations")
    childs = json.loads(gzip.decompress(child_response.content))

    print("Connecting to db")
    connection = sqlite3.connect("../api/database/database.db")

    print("Inserting organizations")
    connection.executemany(
        """
            INSERT OR REPLACE
            INTO organization (orgnr, name, parent_orgnr)
            values (:orgnr, :name, :parent_orgnr)
        """,
        [
            (
                x["organisasjonsnummer"],
                x["navn"],
                x.get("overordnetEnhet"),
            )
            for x in parents + childs
        ],
    )

    connection.commit()


if __name__ == "__main__":
    main()
