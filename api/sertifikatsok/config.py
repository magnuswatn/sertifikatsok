from pathlib import Path

import environ


@environ.config()
class AppConfig:
    db_file: Path = environ.var(converter=Path, default="database/database.db")
    crls_dir: Path = environ.var(converter=Path, default="crls")
    certs_dir: Path = environ.var(converter=Path, default="certs")


def load_config(env: dict[str, str] | None = None) -> AppConfig:
    if env is not None:
        return environ.to_config(AppConfig, env)
    return environ.to_config(AppConfig)
