import logging
import logging.config
import time
from contextvars import ContextVar
from functools import wraps

audit_logger = logging.getLogger("audit")
performance_logger = logging.getLogger("performance")
correlation_id_var = ContextVar("correlation_id", default="")


class CorrelationFilter(logging.Filter):
    def filter(self, record):
        record.correlation_id = correlation_id_var.get()
        return True


def configure_logging(log_level, log_files):
    """
    Configure the logging.

    Standard out is used if no log files are specified.
    """
    handlers = {
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
            "aiohttp.access": {
                "level": "INFO",
                "handlers": ["access"],
                "propagate": False,
            },
            "audit": {"level": "INFO", "handlers": ["audit"], "propagate": False},
        },
    }
    logging.config.dictConfig(log_settings)  # type:ignore


def performance_log(id_param=None):
    def config_decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
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


def performance_log_sync(id_param=None):
    def config_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
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


def audit_log(request):
    ip = request.headers.get("X-Forwarded-For")
    if not ip:
        ip = request.remote

    audit_logger.info(
        "IP=%s ENV=%s TYPE=%s QUERY='%s' CORRELATION_ID=%s",
        ip,
        request.query.get("env"),
        request.query.get("type"),
        request.query.get("query"),
        correlation_id_var.get(),
    )
