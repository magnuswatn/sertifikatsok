from typing import List, Tuple

from bonsai import escape_filter_exp
from cryptography.x509 import Name

from .constants import SUBJECT_FIELDS
from .enums import SearchAttribute


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
    try:
        return order[field_name]
    except KeyError:
        return 10


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


def create_ldap_filter(params: List[Tuple[SearchAttribute, str]]) -> str:

    search_params = ""
    for param in params:
        attribute_value = param[0].value
        search_value = escape_filter_exp(param[1])
        search_params += f"({attribute_value}={search_value})"

    if len(params) > 1:
        search_params = f"(|{search_params})"

    return search_params


def convert_hex_serial_to_int(serial_number: str) -> str:
    serial_number = serial_number.replace(":", "").replace(" ", "")
    serial_number = str(int(serial_number, 16))
    return serial_number
