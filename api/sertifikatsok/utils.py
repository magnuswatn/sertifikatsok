from datetime import UTC, datetime


def escape_ldap_query(query: str) -> str:
    """Escapes an ldap query as described in RFC 4515"""
    return (
        query.replace(r"\\", r"\5c")
        .replace(r"*", r"\2A")
        .replace(r"(", r"\28")
        .replace(r")", r"\29")
        .replace("\x00", r"\00")
    )


def get_subject_order(field: str) -> int:
    """Returns the order of the subject element, for pretty printing"""
    order = {
        "organizationIdentifier": 0,
        "serialNumber": 1,
        "email": 2,
        "CN": 3,
        "GN": 4,
        "SN": 5,
        "OU": 6,
        "O": 7,
        "L": 8,
        "ST": 9,
        "C": 10,
    }
    field_name = field.split("=")[0]
    return order.get(field_name, 100)


def datetime_now_utc() -> datetime:
    return datetime.now(tz=UTC)
