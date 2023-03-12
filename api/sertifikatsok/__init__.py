import os


def is_dev() -> bool:
    return bool(os.getenv("DEV"))


def get_version() -> str:
    return os.getenv("SERTIFIKATSOK_VERSION", "dev")
