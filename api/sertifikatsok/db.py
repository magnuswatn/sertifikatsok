from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from uuid import UUID

from attrs import frozen

from sertifikatsok.utils import datetime_now_utc

from .enums import BatchResult, CertificateAuthority, Environment
from .ldap import LDAP_SERVERS, LdapCertificateEntry, LdapServer
from .logging import performance_log_sync

logger = logging.getLogger(__name__)

DATABASE_FILE = "database/database.db"


@frozen
class Organization:
    orgnr: str
    name: str
    is_child: bool
    parent_orgnr: str | None


@frozen
class BatchRun:
    name: str
    uuid: UUID
    finished_time: datetime
    result: BatchResult
    data: dict | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> BatchRun:
        data = row["data"]
        return cls(
            row["name"],
            UUID(row["uuid"]),
            datetime.fromisoformat(row["finished_time"]),
            BatchResult(row["result"]),
            json.loads(row["data"]) if data is not None else None,
        )


class Database:
    """
    Instances of this class is not thread safe, but they are "coroutine safe",
    (because it blocks the event loop) so can be used by several coroutines at
    the same time.

    It's generally not a big problem that it blocks, since sqlite is so fast.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def connect_to_database(cls, database_file: str = DATABASE_FILE) -> Database:
        connection = sqlite3.connect(database_file)

        connection.execute("PRAGMA foreign_keys = ON")

        connection.row_factory = sqlite3.Row

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ldap_server (
                id            INTEGER       PRIMARY KEY,
                ldap_server   TEXT          NOT NULL UNIQUE,
                ca            TEXT          NOT NULL,
                environment   TEXT          NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS certificate (
                id                  INTEGER     PRIMARY KEY,
                sha1                TEXT        NOT NULL UNIQUE,
                sha2                TEXT        NOT NULL UNIQUE,
                distinguished_name  TEXT        NOT NULL,
                l_id                INTEGER     NOT NULL,
                FOREIGN KEY(l_id) REFERENCES ldap_server(id)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS organization (
                id            INTEGER    PRIMARY KEY,
                orgnr         TEXT       NOT NULL UNIQUE,
                name          TEXT       NOT NULL,
                is_child      BOOLEAN    NOT NULL,
                parent_orgnr  TEXT,
                CHECK (is_child IS FALSE OR parent_orgnr IS NOT NULL)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS batch_control (
                id            INTEGER    PRIMARY KEY,
                name          TEXT       NOT NULL,
                uuid          TEXT       NOT NULL UNIQUE,
                finished_time TEXT       NOT NULL,
                result        TEXT       NOT NULL,
                data          TEXT,
                CHECK (result IN ('ok', 'error'))
            )
            """
        )

        connection.executemany(
            """
            INSERT OR IGNORE INTO ldap_server (ldap_server,
                                               ca,
                                               environment)
            VALUES (:ldap_server,
                    :ca,
                    :environment)
            """,
            [
                (ldap_server.hostname, ldap_server.ca.value, environment.value)
                for environment, ldap_servers in LDAP_SERVERS.items()
                for ldap_server in ldap_servers
            ],
        )

        connection.commit()
        logger.info("Opened database '%s'", database_file)
        return cls(connection)

    @performance_log_sync()
    def insert_certificates(
        self, ldap_cert_entries: list[LdapCertificateEntry], ldap_server: str
    ) -> None:
        [ldap_server_id] = self._connection.execute(
            """
            SELECT id
              FROM ldap_server
             WHERE ldap_server = :ldap_server
            """,
            (ldap_server,),
        ).fetchone()

        self._connection.executemany(
            """
            INSERT OR IGNORE INTO certificate (sha1,
                                               sha2,
                                               distinguished_name,
                                               l_id)
            VALUES (:sha1,
                   :sha2,
                   :distinguished_name,
                   :l_id)
            """,
            [
                {
                    "sha1": ldap_cert_entry.cert_sha1sum(),
                    "sha2": ldap_cert_entry.cert_sha256sum(),
                    "distinguished_name": ldap_cert_entry.dn,
                    "l_id": ldap_server_id,
                }
                for ldap_cert_entry in ldap_cert_entries
            ],
        )
        self._connection.commit()

    @performance_log_sync()
    def find_cert_from_sha1(self, hash: str, env: Environment) -> list[LdapServer]:
        result = self._connection.execute(
            """
            SELECT l.ldap_server,
                   c.distinguished_name,
                   l.ca
              FROM certificate c,
                   ldap_server l
             WHERE c.l_id = l.id
               AND l.environment = :environment
               AND c.sha1 = :sha1
            """,
            {"sha1": hash, "environment": env.value},
        ).fetchone()

        if result is not None:
            logger.info("Found match in database for thumbprint")
            return [
                LdapServer(
                    result[0],
                    result[1],
                    CertificateAuthority(result[2]),
                    [],
                )
            ]
        logger.info("No match in database for thumbprint")
        return []

    @performance_log_sync()
    def find_cert_from_sha2(self, hash: str, env: Environment) -> list[LdapServer]:
        result = self._connection.execute(
            """
            SELECT l.ldap_server,
                   c.distinguished_name,
                   l.ca
              FROM certificate c,
                   ldap_server l
             WHERE c.l_id = l.id
               AND l.environment = :environment
               AND c.sha2 = :sha2
            """,
            {"sha2": hash, "environment": env.value},
        ).fetchone()

        if result is not None:
            logger.info("Found match in database for thumbprint")
            return [
                LdapServer(
                    result[0],
                    result[1],
                    CertificateAuthority(result[2]),
                    [],
                )
            ]
        logger.info("No match in database for thumbprint")
        return []

    @performance_log_sync()
    def get_organization(self, orgnr: str) -> Organization | None:
        result = self._connection.execute(
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

        if result is not None:
            logger.debug("Found organization: %s", result)
            return Organization(result[0], result[1], bool(result[2]), result[3])
        logger.warning("Organization with orgnr %s not found in local db", orgnr)
        return None

    def upsert_organizations(self, orgs: list[Organization]) -> None:
        self._connection.executemany(
            """
            INSERT INTO organization (orgnr, name, parent_orgnr, is_child)
                 VALUES (:orgnr, :name, :parent_orgnr, :is_child)
            ON CONFLICT (orgnr)
          DO UPDATE SET name = :name,
                        parent_orgnr = :parent_orgnr,
                        is_child = :is_child
            """,
            [
                {
                    "orgnr": org.orgnr,
                    "name": org.name,
                    "parent_orgnr": org.parent_orgnr,
                    "is_child": org.is_child,
                }
                for org in orgs
            ],
        )
        self._connection.commit()

    def add_batch_run(
        self, batch_name: str, uuid: UUID, result: BatchResult, data: dict | None
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO batch_control (name,
                                       uuid,
                                       finished_time,
                                       result,
                                       data)
                 VALUES (:name,
                         :uuid,
                         :finished_time,
                         :result,
                         :data)
            """,
            {
                "name": batch_name,
                "uuid": str(uuid),
                "finished_time": datetime_now_utc().isoformat(),
                "result": result.value,
                "data": json.dumps(data) if data is not None else None,
            },
        )
        self._connection.commit()

    def get_last_successful_batch_run(self, batch_name: str) -> BatchRun | None:
        result = self._connection.execute(
            """
            SELECT name,
                   uuid,
                   finished_time,
                   result,
                   data
              FROM batch_control
             WHERE name = :name
               AND result = :result
          ORDER BY finished_time DESC
             LIMIT 1
            """,
            {
                "name": batch_name,
                "result": BatchResult.OK.value,
            },
        ).fetchone()

        if result is not None:
            return BatchRun.from_row(result)
        return None
