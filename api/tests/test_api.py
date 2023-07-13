from datetime import datetime
from itertools import permutations
from typing import Literal

import httpx
import pytest

Env = Literal["test", "prod"]


class Client:
    def __init__(self, httpx_client: httpx.Client) -> None:
        self.httpx_client = httpx_client

    def _search(
        self, env: str, typ: str, query: str, attr: str | None = None
    ) -> httpx.Response:
        params = {"env": env, "type": typ, "query": query}

        if attr is not None:
            params["attr"] = attr

        resp = self.httpx_client.get(
            "http://sertifikatsok:7001/api",
            params=params,
        )
        return resp

    def search_resp(
        self, env: str, typ: str, query: str, attr: str | None = None
    ) -> httpx.Response:
        resp = self._search(env, typ, query, attr)
        resp.raise_for_status()
        return resp

    def search(self, env: str, typ: str, query: str, attr: str | None = None) -> dict:
        resp = self._search(env, typ, query, attr)
        assert resp.is_success
        resp_json = resp.json()
        assert isinstance(resp_json, dict)
        return resp_json


@pytest.fixture(scope="session")
def client() -> Client:
    return Client(httpx.Client())


def _validate_ldap_urls(
    client: Client, env: str, typ: str, cert_sets: list[dict]
) -> None:
    for cert_set in cert_sets:
        ldap_url = cert_set["ldap"]
        ldap_resp = client.search(env, typ, query=ldap_url)
        ldap_url_cert_sets = ldap_resp["certificate_sets"]
        assert len(ldap_url_cert_sets) == 1
        assert ldap_url_cert_sets == [cert_set]


def _validate_individual_certs_is_searchable(
    client: Client, env: str, typ: str, cert_sets: list[dict]
) -> None:
    # When a cert has been returned from a search,
    # it should be searchable by thumbprint
    for cert_set in cert_sets:
        for cert in cert_set["certificates"]:
            for attr in ["Avtrykk (SHA-1)", "Serienummer (hex)", "Serienummer (int)"]:
                if attr == "Serienummer (hex)":
                    # https://github.com/magnuswatn/sertifikatsok/issues/270
                    continue
                val = cert["info"][attr]
                resp = client.search(env, typ, query=val)
                resp_cert_sets = resp["certificate_sets"]
                assert len(resp_cert_sets) == 1
                assert cert == resp_cert_sets[0]["certificates"][0]


@pytest.mark.parametrize("env", ["test", "prod"])
@pytest.mark.parametrize("typ", ["person", "personal"])
def test_person_search(client: Client, env: Env, typ: str) -> None:
    resp = client.search_resp(env=env, typ=typ, query="Silje Fos port")

    correlation_id = resp.headers.get("Correlation-Id")

    resp_json = resp.json()
    assert not resp_json["errors"]

    search_details = resp_json["searchDetails"]
    ldap_servers = search_details.pop("LDAP-servere forespurt")
    assert ldap_servers in [
        ", ".join(permutation)
        for permutation in permutations(
            ["ldap.test.commfides.com", "ldap.test4.buypass.no"]
            if env == "test"
            else ["ldap.commfides.com", "ldap.buypass.no"]
        )
    ]

    assert search_details == {
        "Type": "Personsertifikater",
        "Sertifikattype": "Personsertifikater",
        "Søketype": "Fritekst (common name)",
        "Søkefilter": "(cn=Silje Fos port)",
        "Miljø": "Test" if env == "test" else "Produksjon",
        "Korrelasjonsid": correlation_id,
        "hovedOrgNr": None,
    }
    cert_sets = resp_json["certificate_sets"]
    _validate_ldap_urls(client, env, typ, cert_sets)
    _validate_individual_certs_is_searchable(client, env, typ, cert_sets)

    assert len(cert_sets) == 5
    for cert_set in cert_sets:
        # timestamps should have timezone info in them
        assert datetime.fromisoformat(cert_set["valid_from"]).tzinfo
        assert datetime.fromisoformat(cert_set["valid_to"]).tzinfo


@pytest.mark.parametrize("env", ["test", "prod"])
@pytest.mark.parametrize("typ", ["person", "personal"])
def test_email_search(client: Client, typ: str, env: Env) -> None:
    resp = client.search_resp(env=env, typ=typ, query="silje@example.com")

    correlation_id = resp.headers.get("Correlation-Id")

    resp_json = resp.json()
    assert len(resp_json["errors"]) == 1
    assert resp_json["errors"][0] == (
        "Merk at Buypass ikke lenger inkluderer e-postadresse i "
        "sine sertifikater, så nyere Buypass-sertifikater "
        "vil ikke bli funnet av søk etter e-post"
    )

    search_details = resp_json["searchDetails"]
    ldap_servers = search_details.pop("LDAP-servere forespurt")
    assert ldap_servers in [
        ", ".join(permutation)
        for permutation in permutations(
            ["ldap.test.commfides.com", "ldap.test4.buypass.no"]
            if env == "test"
            else ["ldap.commfides.com", "ldap.buypass.no"]
        )
    ]

    assert search_details == {
        "Type": "Personsertifikater",
        "Sertifikattype": "Personsertifikater",
        "Søketype": "E-post-adresse",
        "Søkefilter": "(mail=silje@example.com)",
        "Miljø": "Test" if env == "test" else "Produksjon",
        "Korrelasjonsid": correlation_id,
        "hovedOrgNr": None,
    }
    cert_sets = resp_json["certificate_sets"]
    _validate_ldap_urls(client, env, typ, cert_sets)
    _validate_individual_certs_is_searchable(client, env, typ, cert_sets)

    # Only 4, as Buypass doesn't include it in SEIDv2 certs
    assert len(cert_sets) == 4
    for cert_set in cert_sets:
        # timestamps should have timezone info in them
        assert datetime.fromisoformat(cert_set["valid_from"]).tzinfo
        assert datetime.fromisoformat(cert_set["valid_to"]).tzinfo


@pytest.mark.parametrize("env", ["test", "prod"])
def test_enterprise_search(client: Client, env: Env) -> None:
    resp = client.search_resp(env=env, typ="enterprise", query="123456789")

    correlation_id = resp.headers.get("Correlation-Id")

    resp_json = resp.json()
    assert not resp_json["errors"]

    search_details = resp_json["searchDetails"]
    ldap_servers = search_details.pop("LDAP-servere forespurt")
    assert ldap_servers in [
        ", ".join(permutation)
        for permutation in permutations(
            ["ldap.test.commfides.com", "ldap.test4.buypass.no"]
            if env == "test"
            else ["ldap.commfides.com", "ldap.buypass.no"]
        )
    ]

    assert search_details == {
        "Type": "Virksomhetssertifikater",
        "Sertifikattype": "Virksomhetssertifikater",
        "Søketype": "Organisasjonsnummer",
        "Søkefilter": "(|(serialNumber=123456789)(organizationIdentifier=NTRNO-123456789))",
        "Miljø": "Test" if env == "test" else "Produksjon",
        "Korrelasjonsid": correlation_id,
        "hovedOrgNr": None,
    }
    cert_sets = resp_json["certificate_sets"]
    _validate_ldap_urls(client, env, "enterprise", cert_sets)
    _validate_individual_certs_is_searchable(client, env, "enterprise", cert_sets)

    assert len(cert_sets) == 5
    for cert_set in cert_sets:
        assert cert_set["org_number"] == "123456789"


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_specific_attr(client: Client, env: Env) -> None:
    resp = client.search_resp(
        env=env, typ="enterprise", query="Min tjeneste", attr="ou"
    )

    correlation_id = resp.headers.get("Correlation-Id")

    resp_json = resp.json()
    assert not resp_json["errors"]

    search_details = resp_json["searchDetails"]
    ldap_servers = search_details.pop("LDAP-servere forespurt")
    assert ldap_servers in [
        ", ".join(permutation)
        for permutation in permutations(
            ["ldap.test.commfides.com", "ldap.test4.buypass.no"]
            if env == "test"
            else ["ldap.commfides.com", "ldap.buypass.no"]
        )
    ]

    assert search_details == {
        "Type": "Virksomhetssertifikater",
        "Sertifikattype": "Virksomhetssertifikater",
        "Søketype": "Egendefinert attributt",
        "Søkefilter": "(ou=Min tjeneste)",
        "Miljø": "Test" if env == "test" else "Produksjon",
        "Korrelasjonsid": correlation_id,
        "hovedOrgNr": None,
    }
    cert_sets = resp_json["certificate_sets"]
    _validate_ldap_urls(client, env, "enterprise", cert_sets)
    _validate_individual_certs_is_searchable(client, env, "enterprise", cert_sets)

    assert len(cert_sets) == 5
