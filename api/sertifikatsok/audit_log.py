from __future__ import annotations

from types import TracebackType

from starlette.requests import Request

from .logging import audit_logger, correlation_id_var
from .search import CertificateSearchResponse


class AuditLogger:
    def __init__(self, request: Request) -> None:
        self.request = request
        self.results: CertificateSearchResponse | None = None

    def set_results(self, results: CertificateSearchResponse) -> None:
        self.results = results

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(
        self,
        ex_type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if not (ip := self.request.headers.get("X-Forwarded-For")):
            if self.request.client:
                ip = self.request.client.host
            else:
                ip = "UNKNOWN"

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

        version = self.request.headers.get("sertifikatsok-version")

        audit_logger.info(
            "VERSION=%s IP=%s ENV=%s TYPE=%s QUERY='%s' GUIDED_MAIN_ORG_SEARCH=%s TYPE=%s "
            "ORG='%s' NUMBER_OF_RESULTS=%d RESULT=%s CORRELATION_ID=%s",
            version,
            ip,
            self.request.query_params.get("env"),
            self.request.query_params.get("type"),
            self.request.query_params.get("query"),
            self.request.query_params.get("guidedMainOrgSearch") is not None,
            search_type,
            org,
            len(self.results.cert_sets) if self.results else 0,
            result,
            correlation_id_var.get(),
        )
