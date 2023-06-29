from types import TracebackType
from typing import Self

from starlette.requests import Request

from sertifikatsok.enums import Environment, RequestCertType, SearchAttribute

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

    def set_results(self, results: CertificateSearchResponse) -> None:
        self.results = results

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
