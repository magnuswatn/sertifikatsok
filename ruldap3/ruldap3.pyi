from enum import Enum
from types import TracebackType
from typing import Self

class Ruldap3Error(Exception): ...
class InvalidFilterError(Ruldap3Error): ...
class LdapSearchFailedError(Ruldap3Error): ...

class LDAPSearchScope(Enum):
    BASE = 1
    ONE = 2
    SUB = 3

class SearchEntry:
    dn: str
    attrs: dict[str, list[str]]
    bin_attrs: dict[str, list[list[int]]]

def is_ldap_filter_valid(filtr: str) -> bool: ...

class LdapConnection:
    async def __aenter__(self) -> Self: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
    async def search(
        self,
        base: str,
        filtr: str,
        attrs: list[str],
        scope: LDAPSearchScope,
        timeout_sec: int,
    ) -> list[SearchEntry]: ...
    @classmethod
    async def connect(cls, ldap_server: str, timeout_sec: int) -> Self: ...
