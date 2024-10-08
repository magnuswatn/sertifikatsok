from __future__ import annotations

import asyncio
import datetime

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from sertifikatsok.cert import MaybeInvalidCertificate
from sertifikatsok.crypto import (
    AppCrlRetriever,
    CertRetriever,
    CertValidator,
    CrlDateValidationError,
    CrlDownloader,
    CrlError,
    CrlErrorReason,
    CrlHttpStatusError,
    RequestCrlRetriever,
    UnsupportedCriticalExtensionInCrlError,
)
from sertifikatsok.enums import CertificateStatus, Environment
from sertifikatsok.errors import SertifikatSokError
from sertifikatsok.utils import datetime_now_utc

from .testlib import CertificateAuthority, read_pem_file

ONE_DAY = datetime.timedelta(1, 0, 0)


class DummyRequestCrlRetriever:
    def __init__(
        self,
        crls: dict[str, x509.CertificateRevocationList],
        errors: list[str] | None = None,
    ):
        self.crls = crls
        self.errors = errors if errors else []

    async def retrieve(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList | None:
        return self.crls.get(url)


class TestAppCrlRetriever:
    def test_validate_normal(self, ca: CertificateAuthority) -> None:
        crl = ca.generate_crl([])
        AppCrlRetriever._validate(crl, ca.cert)

    def test_validate_expired(self, ca: CertificateAuthority) -> None:
        last_and_next_update = (
            datetime_now_utc() - ONE_DAY,
            datetime_now_utc() - datetime.timedelta(seconds=5),
        )
        crl = ca.generate_crl([], last_and_next_update)
        with pytest.raises(CrlError) as error:
            AppCrlRetriever._validate(crl, ca.cert)
        assert error.value.message
        assert "CRL failed date validation" in error.value.message
        assert isinstance(error.value.error_reason, CrlDateValidationError)
        assert error.value.error_reason.last_update, (
            error.value.error_reason.next_update == last_and_next_update
        )

    def test_validate_not_yet_valid(self, ca: CertificateAuthority) -> None:
        last_and_next_update = (
            datetime_now_utc() + datetime.timedelta(seconds=5),
            datetime_now_utc() + ONE_DAY,
        )
        crl = ca.generate_crl([], last_and_next_update)
        with pytest.raises(CrlError) as error:
            AppCrlRetriever._validate(crl, ca.cert)
        assert error.value.message
        assert "CRL failed date validation" in error.value.message
        assert isinstance(error.value.error_reason, CrlDateValidationError)
        assert error.value.error_reason.last_update, (
            error.value.error_reason.next_update == last_and_next_update
        )

    def test_validate_wrong_issuer(self, ca: CertificateAuthority) -> None:
        ca2 = CertificateAuthority.create("sertifikatsok.no CA2")
        crl = ca2.generate_crl([])
        with pytest.raises(CrlError) as error:
            AppCrlRetriever._validate(crl, ca.cert)
        assert error.value.message
        assert "CRL failed issuer validation" in error.value.message
        assert error.value.error_reason == CrlErrorReason.WRONG_ISSUER

    def test_validate_invalid_signature(self, ca: CertificateAuthority) -> None:
        # same name, but different key
        ca2 = CertificateAuthority.create("sertifikatsok.no CA")
        crl = ca2.generate_crl([])
        with pytest.raises(CrlError) as error:
            AppCrlRetriever._validate(crl, ca.cert)
        assert error.value.message
        assert "CRL failed signature validation" in error.value.message
        assert error.value.error_reason == CrlErrorReason.SIGNATURE_INVALID

    def test_validate_with_unknown_critical_extension(
        self, ca: CertificateAuthority
    ) -> None:
        # Let's pretend this is a partitioned CRL
        critical_extension = x509.IssuingDistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://crl.watn.no/crl.crl")],
            relative_name=None,
            only_contains_user_certs=True,
            only_contains_ca_certs=False,
            only_some_reasons=None,
            indirect_crl=False,
            only_contains_attribute_certs=False,
        )

        crl = ca.generate_crl([], extra_extensions=[(critical_extension, True)])

        with pytest.raises(CrlError) as error:
            AppCrlRetriever._validate(crl, ca.cert)
        assert isinstance(
            error.value.error_reason, UnsupportedCriticalExtensionInCrlError
        )
        assert error.value.error_reason.extensions == ["2.5.29.28"]
        assert error.value.message
        assert "Unsupported critical extension(s) in CRL" in error.value.message

    async def test_concurrent_retrieving(self, ca: CertificateAuthority) -> None:
        crl = ca.generate_crl([])

        class DummyCrlDownloader:
            def __init__(self) -> None:
                self.call_count = 0

            async def download_crl(self, url: str) -> bytes:
                await asyncio.sleep(0.1)
                self.call_count += 1
                return crl.public_bytes(Encoding.DER)

        crl_downloader = DummyCrlDownloader()
        app_crl_retriever = AppCrlRetriever(crl_downloader)

        async with asyncio.TaskGroup() as task_group:
            task_group.create_task(
                app_crl_retriever.retrieve("http://crl.watn.no/crl.crl", ca.cert)
            )
            task_group.create_task(
                app_crl_retriever.retrieve("http://crl.watn.no/crl.crl", ca.cert)
            )
            task_group.create_task(
                app_crl_retriever.retrieve("http://crl.watn.no/crl.crl", ca.cert)
            )

        assert crl_downloader.call_count == 1


class TestRequestCrlRetriever:
    async def test_retrieve_ok(self, ca: CertificateAuthority) -> None:
        crl = ca.generate_crl([])

        class DummyAppCrlRetriever:
            def __init__(self) -> None:
                self.count = 0

            async def retrieve(
                self, url: str, issuer: x509.Certificate
            ) -> x509.CertificateRevocationList:
                self.count += 1
                if url == "http://crl.watn.no" and issuer == ca.cert:
                    return crl
                raise SertifikatSokError("Called with wrong params")

        dummy_app_crl_retriever = DummyAppCrlRetriever()
        request_crl_retriever = RequestCrlRetriever(dummy_app_crl_retriever)
        crl1 = await request_crl_retriever.retrieve("http://crl.watn.no", ca.cert)
        crl2 = await request_crl_retriever.retrieve("http://crl.watn.no", ca.cert)
        assert crl == crl1 == crl2
        # Should be cached, so only one invocation
        assert dummy_app_crl_retriever.count == 1

    async def test_retrieve_error(self, ca: CertificateAuthority) -> None:
        class DummyAppCrlRetriever:
            def __init__(self) -> None:
                self.count = 0

            async def retrieve(
                self, url: str, issuer: x509.Certificate
            ) -> x509.CertificateRevocationList:
                self.count += 1
                raise CrlError(CrlErrorReason.MALFORMED)

        dummy_app_crl_retriever = DummyAppCrlRetriever()
        request_crl_retriever = RequestCrlRetriever(dummy_app_crl_retriever)

        crl1 = await request_crl_retriever.retrieve("http://crl.watn.no", ca.cert)
        crl2 = await request_crl_retriever.retrieve("http://crl.watn.no", ca.cert)
        assert crl1 is crl2 is None
        assert request_crl_retriever.errors == ["ERR-003"]
        # Errors should also be cached, so that we don't spam the crl server
        assert dummy_app_crl_retriever.count == 1

    async def test_wrong_url_in_cert(self, ca: CertificateAuthority) -> None:
        """
        The issuer should be included in the cache, so that if a certificate
        from issuer A has a cdp extension pointing to the crl from issuer B,
        certs from issuer A and issuer B should not get the same CRL (or lack of)
        in return.
        """
        ca2 = CertificateAuthority.create("sertifikatsok.no CA2")
        crl = ca.generate_crl([])

        class DummyAppCrlRetriever:
            async def retrieve(
                self, url: str, issuer: x509.Certificate
            ) -> x509.CertificateRevocationList:
                if issuer == ca2.cert:
                    raise CrlError(CrlErrorReason.WRONG_ISSUER, "CRL did not validate")
                else:
                    return crl

        # Retrieve the valid first, and then invalid. Invalid should get None
        request_crl_retriever1 = RequestCrlRetriever(DummyAppCrlRetriever())
        retrieved_crl1_1 = await request_crl_retriever1.retrieve(
            "http://crl.watn.no/sertifikatsok.no+CA.crl", ca.cert
        )
        retrieved_crl1_2 = await request_crl_retriever1.retrieve(
            "http://crl.watn.no/sertifikatsok.no+CA.crl", ca2.cert
        )
        assert retrieved_crl1_1 == crl
        assert retrieved_crl1_2 is None

        # Retrieve the invalid first, and then validg. Valid should get a fresh CRL
        request_crl_retriever2 = RequestCrlRetriever(DummyAppCrlRetriever())
        retrieved_crl2_1 = await request_crl_retriever2.retrieve(
            "http://crl.watn.no/sertifikatsok.no+CA.crl", ca2.cert
        )
        retrieved_crl2_2 = await request_crl_retriever2.retrieve(
            "http://crl.watn.no/sertifikatsok.no+CA.crl", ca.cert
        )
        assert retrieved_crl2_1 is None
        assert retrieved_crl2_2 == crl


class TestCertValidator:
    async def test_non_trusted_cert(self, ee_cert: MaybeInvalidCertificate) -> None:
        cert_validator = CertValidator(
            CertRetriever({}),  # no trusted certs
            DummyRequestCrlRetriever({}),
        )
        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.UNTRUSTED
        assert revocation_date is None

    async def test_invalid_signature(self, ee_cert: MaybeInvalidCertificate) -> None:
        # same name, but different key
        ca2 = CertificateAuthority.create("sertifikatsok.no CA")

        cert_validator = CertValidator(
            CertRetriever({ca2.cert.subject: ca2.cert}),
            DummyRequestCrlRetriever({}),
        )
        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.INVALID
        assert revocation_date is None

    async def test_invalid_ca_name(
        self, ca: CertificateAuthority, ee_cert: MaybeInvalidCertificate
    ) -> None:
        # same key. but different name
        ca2 = CertificateAuthority.create("sertifikatsok.no CA2", ca.key)

        cert_validator = CertValidator(
            # wrong mapping
            CertRetriever({ca.cert.subject: ca2.cert}),
            DummyRequestCrlRetriever({}),
        )
        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.INVALID
        assert revocation_date is None

    async def test_expired(self, ca: CertificateAuthority) -> None:
        cert_validator = CertValidator(
            CertRetriever({ca.cert.subject: ca.cert}),
            DummyRequestCrlRetriever({}),
        )
        ee_cert = ca.generate_ee_cert("sertifikatsok.no", expired=True)
        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.EXPIRED
        assert revocation_date is None

    async def test_invalid_crl(
        self, ca: CertificateAuthority, ee_cert: MaybeInvalidCertificate
    ) -> None:
        cert_validator = CertValidator(
            CertRetriever({ca.cert.subject: ca.cert}),
            DummyRequestCrlRetriever({}, ["ERR-003"]),  # crl not available
        )
        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.UNKNOWN
        assert revocation_date is None
        assert cert_validator.errors == ["ERR-003"]

    async def test_revoked_cert(
        self, ca: CertificateAuthority, ee_cert: MaybeInvalidCertificate
    ) -> None:
        crl = ca.generate_crl([ee_cert.cert])

        cert_validator = CertValidator(
            CertRetriever({ca.cert.subject: ca.cert}),
            DummyRequestCrlRetriever(
                {"http://crl.watn.no/sertifikatsok.no+CA.crl": crl}
            ),
        )

        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.REVOKED
        assert revocation_date is not None

    async def test_ok_cert(
        self, ca: CertificateAuthority, ee_cert: MaybeInvalidCertificate
    ) -> None:
        crl = ca.generate_crl([])

        cert_validator = CertValidator(
            CertRetriever({ca.cert.subject: ca.cert}),
            DummyRequestCrlRetriever(
                {"http://crl.watn.no/sertifikatsok.no+CA.crl": crl}
            ),
        )

        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.OK
        assert revocation_date is None

    async def test_sha1_expired_cert(self) -> None:
        class ExceptionRequestCrlRetriever:
            def __init__(self) -> None:
                self.errors: list[str] = []

            async def retrieve(
                self, url: str, issuer: x509.Certificate
            ) -> x509.CertificateRevocationList | None:
                raise SertifikatSokError("Should not get called")

        # Can't create a SHA1 cert with cryptography, so must
        # use a real one from prod.
        cert_validator = CertValidator(
            CertRetriever.create(Environment.PROD),
            ExceptionRequestCrlRetriever(),
        )

        raw_cert = read_pem_file("tests/resources/cert_sha1_sign.pem")
        ee_cert = MaybeInvalidCertificate.create(raw_cert)

        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.EXPIRED
        assert revocation_date is None

    async def test_ldap_url_cert(self, ca: CertificateAuthority) -> None:
        class ExceptionRequestCrlRetriever:
            def __init__(self) -> None:
                self.errors: list[str] = []

            async def retrieve(
                self, url: str, issuer: x509.Certificate
            ) -> x509.CertificateRevocationList | None:
                raise SertifikatSokError("Should not get called")

        cert_validator = CertValidator(
            CertRetriever({ca.cert.subject: ca.cert}),
            ExceptionRequestCrlRetriever(),
        )

        ee_cert = ca.generate_ee_cert(
            "sertifikatsok.no", crl_endpoint="ldap://ldap.watn.no/crl"
        )

        cert_status, revocation_date = await cert_validator.validate_cert(ee_cert)
        assert cert_status == CertificateStatus.UNKNOWN
        assert revocation_date is None


class TestCrlDownloader:
    async def test_ok_download(self) -> None:
        transport = httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Type": "application/pkix-crl"},
                content=b"crliboii",
            )
        )

        async with httpx.AsyncClient(transport=transport) as client:
            crl = await CrlDownloader()._download_crl_with_client(
                client, "http://crl.watn.no"
            )
        assert crl == b"crliboii"

    async def test_ok_download_alternative_content_type(self) -> None:
        transport = httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Type": "application/x-pkcs7-crl"},
                content=b"crliboii",
            )
        )

        async with httpx.AsyncClient(transport=transport) as client:
            crl = await CrlDownloader()._download_crl_with_client(
                client, "http://crl.watn.no"
            )
        assert crl == b"crliboii"

    async def test_failed_download_404(self) -> None:
        transport = httpx.MockTransport(
            lambda _: httpx.Response(
                404,
                headers={"Content-Type": "text/plain"},
                content=b"Not found",
            )
        )

        with pytest.raises(CrlError) as error:
            async with httpx.AsyncClient(transport=transport) as client:
                await CrlDownloader()._download_crl_with_client(
                    client, "http://crl.watn.no"
                )
        assert isinstance(error.value.error_reason, CrlHttpStatusError)
        assert error.value.error_reason.http_status_code == 404
        assert "status code 404 " in str(error)

    async def test_failed_download_wrong_content_type(self) -> None:
        transport = httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=b"Not found but with 200",
            )
        )

        with pytest.raises(CrlError) as error:
            async with httpx.AsyncClient(transport=transport) as client:
                await CrlDownloader()._download_crl_with_client(
                    client, "http://crl.watn.no"
                )
        assert isinstance(error.value.error_reason, CrlErrorReason)
        assert error.value.error_reason == CrlErrorReason.INVALID_CONTENT_TYPE
        assert "Got content type: text/plain " in str(error)
