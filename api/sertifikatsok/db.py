import hashlib
import logging
import sqlite3
from typing import List, Optional, Tuple

from attrs import frozen

from .enums import CertificateAuthority, Environment
from .ldap import LDAP_SERVERS, LdapServer
from .logging import performance_log_sync

logger = logging.getLogger(__name__)

DATABASE_FILE = "data/database.db"


@frozen
class Organization:
    orgnr: str
    name: str
    parent_orgnr: Optional[str]


class Database:
    def __init__(self, connection):
        self._connection = connection

    @classmethod
    def connect_to_database(cls, database_file=DATABASE_FILE):
        connection = sqlite3.connect(database_file)

        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ldap_server (
                ID INTEGER PRIMARY KEY,
                LDAP_SERVER TEXT NOT NULL UNIQUE,
                CA TEXT NOT NULL,
                ENVIRONMENT TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS certificate (
                ID INTEGER PRIMARY KEY,
                SHA1 TEXT NOT NULL UNIQUE,
                SHA2 TEXT NOT NULL UNIQUE,
                DISTINGUISHED_NAME TEXT NOT NULL,
                L_ID INTEGER NOT NULL,
                FOREIGN KEY(l_id) REFERENCES ldap_server(id)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS organization (
                ID INTEGER PRIMARY KEY,
                ORGNR TEXT NOT NULL UNIQUE,
                NAME TEXT NOT NULL,
                PARENT_ORGNR TEXT
            )
            """
        )

        connection.executemany(
            """
            INSERT OR IGNORE
            INTO LDAP_SERVER (LDAP_SERVER, CA, ENVIRONMENT)
            values (:ldap_server, :ca, :environment)
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
        self, certs: List[Tuple[str, Optional[List[bytes]]]], ldap_server
    ):

        [ldap_server_id] = self._connection.execute(
            """
            SELECT
              id
            FROM
              ldap_server
            WHERE
              ldap_server = :ldap_server
            """,
            (ldap_server,),
        ).fetchone()

        self._connection.executemany(
            """
            INSERT OR IGNORE
            INTO certificate (
                SHA1, SHA2, DISTINGUISHED_NAME, L_ID
            )
            values (
                :sha1, :sha2, :distinguished_name, :l_id
            )
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
    def find_cert_from_sha1(self, hash, env: Environment) -> List[LdapServer]:

        result = self._connection.execute(
            """
            SELECT
              l.LDAP_SERVER,
              c.DISTINGUISHED_NAME,
              l.ca
            FROM
              certificate c,
              ldap_server l
            WHERE
              c.l_id = l.id
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
    def find_cert_from_sha2(self, hash, env: Environment) -> List[LdapServer]:
        result = self._connection.execute(
            """
            SELECT
              l.LDAP_SERVER,
              c.DISTINGUISHED_NAME,
              l.ca
            FROM
              certificate c,
              ldap_server l
            WHERE
              c.l_id = l.id
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
    def get_organization(self, orgnr: str) -> Optional[Organization]:
        result = self._connection.execute(
            """
            SELECT
              orgnr,
              name,
              parent_orgnr
            FROM
              organization
            WHERE
              orgnr = :orgnr
            """,
            {"orgnr": orgnr},
        ).fetchone()

        if result is not None:
            logger.debug("Found organization: %s", result)
            return Organization(result[0], result[1], result[2])
        logger.warning("Organization with orgnr %s not found in local db", orgnr)
        return None
