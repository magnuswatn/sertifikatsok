from datetime import UTC, datetime


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
