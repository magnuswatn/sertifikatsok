import logging

from sertifikatsok.config import AppConfig
from sertifikatsok.logging import configure_logging
from sertifikatsok.web import make_app

config = AppConfig.from_environ()

log_level = logging.DEBUG if config.dev else logging.INFO

configure_logging(log_level, config.log_files)

app = make_app(config)
