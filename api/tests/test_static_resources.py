from datetime import datetime, timedelta
from pathlib import Path

from sertifikatsok.utils import datetime_now_utc


def test_security_txt_doesnt_expire_in_the_next_five_weeks() -> None:
    security_txt = Path("../www/public/.well-known/security.txt").read_text()

    [expire_line] = [
        line for line in security_txt.splitlines() if line.startswith("Expires: ")
    ]
    _, _, expire_timestamp = expire_line.partition(": ")
    expires = datetime.fromisoformat(expire_timestamp)
    assert expires > (datetime_now_utc() + timedelta(weeks=5))
