from bonsai import escape_filter_exp

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
    return order.get(field_name, 100)


def create_ldap_filter(params: list[tuple[SearchAttribute, str]]) -> str:

    search_params = ""
    for param in params:
        attribute_value = param[0].value
        search_value = escape_filter_exp(param[1])
        search_params += f"({attribute_value}={search_value})"

    if len(params) > 1:
        search_params = f"(|{search_params})"

    return search_params
