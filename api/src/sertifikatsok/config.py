import os
from pathlib import Path
from typing import Self

import environ


@environ.config()
class AppConfig:
    db_file: Path = environ.var(converter=Path, default="database/database.db")
    crls_dir: Path = environ.var(converter=Path, default="crls")
    certs_dir: Path = environ.var(converter=Path, default="certs")
    log_files: str | None = environ.var(default=None)
    dev: bool = environ.bool_var(default=False)
    version: str = environ.var(default="DEV")

    @property
    def running_on_fly(self) -> bool:
        return "FLY_MACHINE_ID" in os.environ

    @classmethod
    def from_environ(cls) -> Self:
        return environ.to_config(cls)
