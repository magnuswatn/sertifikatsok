from base64 import b64decode
from datetime import datetime
from itertools import permutations
from typing import Literal

import httpx
import pytest

Env = Literal["test", "prod"]

pytestmark = pytest.mark.apitest


class Client:
    def __init__(self, httpx_client: httpx.Client) -> None:
        self.httpx_client = httpx_client

    def raw_search(self, params: dict[str, str]) -> httpx.Response:
        resp = self.httpx_client.get(
            "http://sertifikatsok:7001/api",
            params=params,
        )
        return resp

    def _search(
        self, env: str, typ: str, query: str, attr: str | None = None
    ) -> httpx.Response:
        params = {"env": env, "type": typ, "query": query}

        if attr is not None:
            params["attr"] = attr
        return self.raw_search(params)

    def search_resp(
        self, env: str, typ: str, query: str, attr: str | None = None
    ) -> httpx.Response:
        resp = self._search(env, typ, query, attr)
        resp.raise_for_status()
        return resp

    def search(self, env: str, typ: str, query: str, attr: str | None = None) -> dict:
        resp = self._search(env, typ, query, attr)
        resp.raise_for_status()
        resp_json = resp.json()
        assert isinstance(resp_json, dict)
        return resp_json

    def revocation_info(
        self, env: str, typ: str, query: str, cert: bytes
    ) -> httpx.Response:
        params = {"env": env, "type": typ, "query": query}

        resp = self.httpx_client.post(
            "http://sertifikatsok:7001/revocation_info",
            params=params,
            content=cert,
            headers={"Content-Type": "application/pkix-cert"},
        )
        return resp


@pytest.fixture(scope="session")
def client() -> Client:
    return Client(httpx.Client())


def _validate_ldap_urls(
    client: Client, env: str, typ: str, cert_sets: list[dict]
) -> None:
    for cert_set in cert_sets:
        ldap_url = cert_set["ldap"]
        ldap_resp = client.search(env, typ, query=ldap_url)
        assert not ldap_resp["errors"]
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
                val = cert["info"][attr]
                resp = client.search(env, typ, query=val)
                assert not resp["errors"]
                resp_cert_sets = resp["certificate_sets"]
                assert len(resp_cert_sets) == 1
                assert cert == resp_cert_sets[0]["certificates"][0]


@pytest.mark.parametrize("invalid", [False, True])
@pytest.mark.parametrize("param", ["env", "type", "query", "attr"])
def test_invalid_params(*, client: Client, param: str, invalid: bool) -> None:
    if (invalid and param == "query") or (not invalid and param == "attr"):
        # `query` is a string, so can't have an invalid value,
        # and `attr` is optional, so can't be missing.
        return

    params = {"env": "test", "type": "personal", "query": "Silje Fos port"}

    if invalid:
        params[param] = "invalid_value"
    else:
        params.pop(param)

    resp = client.raw_search(params)
    assert resp.status_code == 400
    resp_json = resp.json()
    assert "error" in resp_json

    match param:
        case "env":
            expected_error_msg = "Unknown environment"
        case "type":
            expected_error_msg = "Unknown certificate type"
        case "query":
            expected_error_msg = "Missing query parameter"
        case "attr":
            expected_error_msg = "Unknown search attribute"
        case _:
            raise AssertionError

    assert expected_error_msg in resp_json["error"]


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


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_nonexisting_thumbprint_should_fallback_to_serial(
    client: Client, env: Env
) -> None:
    resp = client.search_resp(
        env=env, typ="enterprise", query="48b63447e55ec1694d5cd581a9e082be293007a1"
    )

    correlation_id = resp.headers.get("Correlation-Id")

    resp_json = resp.json()
    assert len(resp_json["errors"]) == 1
    assert resp_json["errors"][0] == (
        "Søk på avtrykk/thumbprint er ikke helt pålitelig, så det er"
        " mulig at sertifikatet eksisterer, selv om det ikke ble funnet"
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
        "Type": "Virksomhetssertifikater",
        "Sertifikattype": "Virksomhetssertifikater",
        "Søketype": "Avtrykk eller sertifikatserienummer",
        "Søkefilter": "(certificateSerialNumber=415110625429250731863403542919228693486335166369)",
        "Miljø": "Test" if env == "test" else "Produksjon",
        "Korrelasjonsid": correlation_id,
        "hovedOrgNr": None,
    }
    assert len(resp_json["certificate_sets"]) == 0


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_bypass_buypass_size_limit(client: Client, env: Env) -> None:
    # Buypass only returns 20 certs each time. We should bypass (hihi) this
    # and get up to 100 certs.
    resp = client.search(env=env, typ="enterprise", query="983044778")

    assert len(resp["errors"]) == 1
    assert resp["errors"][0] == (
        "Det er mulig noen gamle sertifikater ikke vises, "
        "da søket returnerte for mange resultater"
    )

    assert len(resp["certificate_sets"]) == 50

    # There should be no duplicate certs
    assert (
        len(
            {
                cert["info"]["Avtrykk (SHA-1)"]
                for cert_set in resp["certificate_sets"]
                for cert in cert_set["certificates"]
            }
        )
        == 100
    )


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_failes_when_all_servers_fail(client: Client, env: str) -> None:
    resp = client._search(env=env, typ="enterprise", query="fail", attr="ou")

    assert resp.status_code == 500
    assert resp.json()["error"] == "En ukjent feil oppstod. Vennligst prøv igjen."


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_failes_when_all_queries_against_one_server_fail(
    client: Client, env: str
) -> None:
    resp = client._search(env=env, typ="personal", query="9578-4506-FAIL")

    assert resp.status_code == 503
    assert (
        resp.json()["error"] == "Klarte ikke kontakte Commfides. Vennligst prøv igjen."
    )


@pytest.mark.parametrize("query", ["buypassfail", "buypassfail-CA 1"])
@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_does_not_fail_when_only_some_servers_fail(
    client: Client, env: str, query: str
) -> None:
    resp = client._search(env=env, typ="enterprise", query=query, attr="ou")

    assert resp.status_code == 200
    errors = resp.json()["errors"]
    assert len(errors) == 1
    assert errors[0] == (
        "Kunne ikke hente sertfikater fra Buypass"
        if query == "buypassfail"
        else "Kunne ikke hente alle sertfikater fra Buypass"
    )


@pytest.mark.parametrize("env", ["test", "prod"])
def test_search_revoked_certs_are_marked_as_such(client: Client, env: str) -> None:
    resp = client.search_resp(env=env, typ="enterprise", query="987654321")

    resp_json = resp.json()
    assert not resp_json["errors"]

    cert_sets = resp_json["certificate_sets"]
    for cert_set in cert_sets:
        assert cert_set["status"] == "Revokert"
        for cert in cert_set["certificates"]:
            assert cert["info"]["Status"].startswith("Revokert ")


@pytest.mark.parametrize("revocation_expected", [False, True])
@pytest.mark.parametrize("env", ["test", "prod"])
def test_revocation_info(
    client: Client, *, env: str, revocation_expected: bool
) -> None:
    resp = client.search_resp(
        env=env,
        typ="enterprise",
        query="987654321" if revocation_expected else "123456789",
    )

    resp_json = resp.json()
    cert_sets = resp_json["certificate_sets"]
    for cert_set in cert_sets:
        for cert in cert_set["certificates"]:
            raw_cert = b64decode(cert["certificate"])
            revocation_info_resp = client.revocation_info(
                env=env,
                typ="enterprise",
                query="987654321" if revocation_expected else "123456789",
                cert=raw_cert,
            )
            revocation_info_resp.raise_for_status()
            revocation_info = revocation_info_resp.json()
            assert revocation_info["ocsp_result"] is not None
            assert "error" not in revocation_info["ocsp_result"]
            assert (
                revocation_info["ocsp_result"]["status"] == "REVOKED"
                if revocation_expected
                else "GOOD"
            )

            assert revocation_info["crl_result"] is not None
            assert "error" not in revocation_info["crl_result"]
            if revocation_expected:
                assert revocation_info["crl_result"]["revoked_at"] is not None
            else:
                assert revocation_info["crl_result"]["revoked_at"] is None
