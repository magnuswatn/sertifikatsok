from types import TracebackType
from typing import Self

from starlette.requests import Request

from sertifikatsok.crypto import CrlError
from sertifikatsok.enums import Environment, RequestCertType, SearchAttribute
from sertifikatsok.revocation_info import OcspError, RevocationInfoResponse

from .logging import audit_logger, correlation_id_var
from .search import CertificateSearchResponse


class AuditLogger:
    def __init__(
        self,
        env: Environment,
        type: RequestCertType,
        query: str,
        request: Request,
        attr: SearchAttribute | None = None,
    ) -> None:
        self.request = request
        self.env = env
        self.type = type
        self.query = query
        self.attr = attr
        self.results: CertificateSearchResponse | None = None
        self.revocation_info_resp: RevocationInfoResponse | None = None
        self.cert_thumbprint: str | None = None

    def set_results(self, results: CertificateSearchResponse) -> None:
        assert self.revocation_info_resp is None
        self.results = results

    def set_revocation_info_results(
        self, resp: RevocationInfoResponse, cert_thumbprint: str
    ) -> None:
        assert self.results is None
        self.revocation_info_resp = resp
        self.cert_thumbprint = cert_thumbprint

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        ex_type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if not (ip := self.request.headers.get("X-Forwarded-For")):
            ip = self.request.client.host if self.request.client else "UNKNOWN"

        version = self.request.headers.get("sertifikatsok-version")

        if self.results is not None:
            return self._exit_with_result(value, ip, version)

        if self.revocation_info_resp is not None:
            return self._exit_with_revocation_info(value, ip, version)

        audit_logger.info(
            "VERSION=%s IP=%s ENV=%s TYPE=%s QUERY='%s' RESULT=%s CORRELATION_ID=%s",
            version,
            ip,
            self.env.value,
            self.type.value,
            self.query,
            "ERROR",
            correlation_id_var.get(),
        )

    def _exit_with_result(
        self, value: BaseException | None, ip: str, version: str | None
    ) -> None:
        if value is not None or self.results is None:
            result = "ERROR"
        elif self.results.errors:
            result = "PARTIAL"
        else:
            result = "OK"

        if (
            self.results is not None
            and self.results.search.ldap_params.organization is not None
        ):
            org = self.results.search.ldap_params.organization.name
        else:
            org = ""

        search_type = (
            self.results.search.ldap_params.search_type.value
            if self.results is not None
            else ""
        )

        audit_logger.info(
            "VERSION=%s IP=%s ENV=%s TYPE=%s QUERY='%s' GUIDED_MAIN_ORG_SEARCH=%s TYPE=%s "
            "ORG='%s' NUMBER_OF_RESULTS=%d RESULT=%s CORRELATION_ID=%s",
            version,
            ip,
            self.env.value,
            self.type.value,
            self.query,
            self.request.query_params.get("guidedMainOrgSearch") is not None,
            search_type,
            org,
            len(self.results.cert_sets) if self.results else 0,
            result,
            correlation_id_var.get(),
        )

    def _exit_with_revocation_info(
        self, value: BaseException | None, ip: str, version: str | None
    ) -> None:
        assert self.revocation_info_resp

        ocsp_error = False
        if isinstance(self.revocation_info_resp.ocsp_result, OcspError):
            ocsp_error = True
            ocsp_status = "ERROR"
        else:
            ocsp_status = (
                self.revocation_info_resp.ocsp_result.status
                if self.revocation_info_resp.ocsp_result is not None
                else "NULL"
            )

        crl_error = False
        if isinstance(self.revocation_info_resp.crl_result, CrlError):
            crl_error = True
            crl_status = "ERROR"
        elif self.revocation_info_resp.crl_result is None:
            crl_status = "NULL"
        elif self.revocation_info_resp.crl_result.revoked_at is not None:
            crl_status = "REVOKED"
        else:
            crl_status = "GOOD"

        if value is not None or self.revocation_info_resp is None:
            result = "ERROR"
        elif ocsp_error or crl_error:
            result = "PARTIAL"
        else:
            result = "OK"

        audit_logger.info(
            "VERSION=%s IP=%s ENV=%s TYPE=%s QUERY='%s' CERT_THUMBPRINT=%s "
            "CRL_STATUS=%s OCSP_STATUS=%s RESULT=%s CORRELATION_ID=%s",
            version,
            ip,
            self.env.value,
            self.type.value,
            self.query,
            self.cert_thumbprint,
            crl_status,
            ocsp_status,
            result,
            correlation_id_var.get(),
        )
