def escape_ldap_query(query: str) -> str:
    """Escapes an ldap query as described in RFC 4515"""
    return (
        query.replace("\\", r"\5c")
        .replace(r"*", r"\2a")
        .replace(r"(", r"\28")
        .replace(r")", r"\29")
        .replace("\x00", r"\00")
    )


def get_subject_order(field: str) -> int:
    """Returns the order of the subject element, for pretty printing"""
    order = {
        "serialNumber": 0,
        "email": 1,
        "CN": 2,
        "OU": 3,
        "O": 4,
        "L": 5,
        "ST": 6,
        "C": 7,
    }
    field_name = field.split("=")[0]
    try:
        return order[field_name]
    except KeyError:
        return 8
