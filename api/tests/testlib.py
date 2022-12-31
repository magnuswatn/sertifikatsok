from base64 import b64decode
from pathlib import Path


def read_pem_file(path: str) -> bytes:
    pem_lines = Path(path).read_text().splitlines()
    base64_data = "".join(pem_lines[1:-1])
    return b64decode(base64_data.encode())
