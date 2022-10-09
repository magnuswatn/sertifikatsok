from __future__ import annotations

import hashlib
import logging
import sqlite3

from attrs import frozen

from .enums import CertificateAuthority, Environment
from .ldap import LDAP_SERVERS, LdapServer
from .logging import performance_log_sync

logger = logging.getLogger(__name__)

DATABASE_FILE = "database/database.db"


@frozen
class Organization:
    orgnr: str
    name: str
    is_child: bool
    parent_orgnr: str | None


class Database:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def connect_to_database(cls, database_file: str = DATABASE_FILE) -> Database:
        connection = sqlite3.connect(database_file)

        connection.execute("PRAGMA foreign_keys = ON")

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
        self, certs: list[tuple[str, list[bytes] | None]], ldap_server: str
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
                    "sha1": hashlib.sha1(cert[1][0]).hexdigest(),
                    "sha2": hashlib.sha256(cert[1][0]).hexdigest(),
                    "distinguished_name": cert[0],
                    "l_id": ldap_server_id,
                }
                for cert in certs
                if cert[1] is not None and len(cert[1]) > 0
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
