from __future__ import annotations

import logging
import logging.config
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Any, ParamSpec, TypeVar

audit_logger = logging.getLogger("audit")
performance_logger = logging.getLogger("performance")
correlation_id_var = ContextVar("correlation_id", default="")


class CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = correlation_id_var.get()
        return True


@contextmanager
def correlation_context() -> Iterator[uuid.UUID]:
    correlation_id = uuid.uuid4()
    token = correlation_id_var.set(str(correlation_id))
    try:
        yield correlation_id
    finally:
        correlation_id_var.reset(token)


def configure_logging(log_level: int, log_files: str | None) -> None:
    logging.config.dictConfig(get_log_config(log_level, log_files))


def get_log_config(log_level: int, log_files: str | None) -> dict:
    """
    Configure the logging.

    Standard out is used if no log files are specified.
    """
    handlers: dict[str, Any] = {
        "app": {
            "level": log_level,
            "formatter": "default",
            "filters": ["correlation_id"],
        },
        "access": {
            "level": "INFO",
            "formatter": "default",
            "filters": ["correlation_id"],
        },
        "audit": {"level": "INFO", "formatter": "bare"},
        "performance": {"level": "INFO", "formatter": "bare"},
    }
    if log_files:
        for handler in handlers:
            handlers[handler]["class"] = "logging.FileHandler"
            handlers[handler]["filename"] = log_files.format(handler)
    else:
        for handler in handlers:
            handlers[handler]["class"] = "logging.StreamHandler"

    log_settings = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": handlers,
        "filters": {"correlation_id": {"()": CorrelationFilter}},
        "formatters": {
            "default": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s (%(correlation_id)s)"
            },
            "bare": {"format": "%(asctime)s %(message)s"},
        },
        "loggers": {
            "": {"level": log_level, "handlers": ["app"], "propagate": True},
            "performance": {
                "level": "INFO",
                "handlers": ["performance"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["access"],
                "propagate": False,
            },
            "audit": {"level": "INFO", "handlers": ["audit"], "propagate": False},
        },
    }
    return log_settings


TC = TypeVar("TC")
P = ParamSpec("P")


def performance_log(
    id_param: int | None = None,
) -> Callable[[Callable[P, Awaitable[TC]]], Callable[P, Awaitable[TC]]]:
    def config_decorator(
        func: Callable[P, Awaitable[TC]]
    ) -> Callable[P, Awaitable[TC]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> TC:
            start = time.perf_counter()
            return_value = await func(*args, **kwargs)

            time_taken = (time.perf_counter() - start) * 1000
            id_arg = args[id_param] if id_param is not None else ".."
            method = f"{func.__qualname__}({id_arg})"

            performance_logger.info(
                "METHOD=%s TIME_TAKEN=%d CORRELATION_ID=%s",
                method,
                time_taken,
                correlation_id_var.get(),
            )
            return return_value

        return wrapper

    return config_decorator


def performance_log_sync(
    id_param: int | None = None,
) -> Callable[[Callable[P, TC]], Callable[P, TC]]:
    def config_decorator(func: Callable[P, TC]) -> Callable[P, TC]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> TC:
            start = time.perf_counter()
            return_value = func(*args, **kwargs)

            time_taken = (time.perf_counter() - start) * 1000
            id_arg = args[id_param] if id_param is not None else ".."
            method = f"{func.__qualname__}({id_arg})"

            performance_logger.info(
                "METHOD=%s TIME_TAKEN=%d CORRELATION_ID=%s",
                method,
                time_taken,
                correlation_id_var.get(),
            )
            return return_value

        return wrapper

    return config_decorator
