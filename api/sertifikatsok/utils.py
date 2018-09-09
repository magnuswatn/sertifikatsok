from cryptography.x509 import Name
from .constants import SUBJECT_FIELDS


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


def stringify_x509_name(name: Name) -> str:
    subject = []
    for field in name:
        try:
            subject.append(
                "{}={}".format(SUBJECT_FIELDS[field.oid.dotted_string], field.value)
            )
        except KeyError:
            # If we don't recognize the field, we just print the dotted string
            subject.append("{}={}".format(field.oid.dotted_string, field.value))
    return ", ".join(list(subject))
