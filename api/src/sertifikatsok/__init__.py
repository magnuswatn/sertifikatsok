import os


def is_dev() -> bool:
    return bool(os.getenv("DEV"))


def is_running_on_fly() -> bool:
    return "FLY_MACHINE_ID" in os.environ


def get_version() -> str:
    return os.getenv("SERTIFIKATSOK_VERSION", "dev")
