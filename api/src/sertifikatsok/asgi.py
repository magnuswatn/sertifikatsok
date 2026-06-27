import logging
import os

from sertifikatsok import is_dev
from sertifikatsok.logging import configure_logging
from sertifikatsok.web import app

app.state.dev = is_dev()

log_level = logging.DEBUG if app.state.dev else logging.INFO

configure_logging(log_level, os.getenv("SERTIFIKATSOK_LOG_FILES"))
