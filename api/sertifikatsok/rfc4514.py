"""
This code is based on the RFC 4514 parsing from cryptography,
but modified to be more relaxed (case-insensitive and allow
whitespace pretty much everywhere).

---
Copyright (c) Individual contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    3. Neither the name of PyCA Cryptography nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import binascii
import logging
import re
import sys

from cryptography.x509 import (
    Name,
    NameAttribute,
    NameOID,
    ObjectIdentifier,
    RelativeDistinguishedName,
)

from sertifikatsok.constants import (
    STR_TO_SUBJECT_FIELDS,
    SUBJECT_FIELDS_TO_SEARCH_ATTRS,
)
from sertifikatsok.enums import SearchAttribute

logger = logging.getLogger(__name__)


def _unescape_dn_value(val: str) -> str:
    if not val:
        return ""

    # See https://tools.ietf.org/html/rfc4514#section-3

    # special = escaped / SPACE / SHARP / EQUALS
    # escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
    def sub(m: re.Match) -> str:
        val = m.group(1)
        # Regular escape
        if len(val) == 1:
            return str(val)
        # Hex-value scape
        return chr(int(val, 16))

    return _LaxRFC4514NameParser._PAIR_RE.sub(sub, val)


class _LaxRFC4514NameParser:
    _OID_RE = re.compile(r"(0|([1-9]\d*))(\.(0|([1-9]\d*)))+")
    _DESCR_RE = re.compile(r"[a-zA-Z][a-zA-Z\d-]*")

    _PAIR = r"\\([\\ #=\"\+,;<>]|[\da-zA-Z]{2})"
    _PAIR_RE = re.compile(_PAIR)
    _LUTF1 = r"[\x01-\x1f\x21\x24-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]"
    _SUTF1 = r"[\x01-\x21\x23-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]"
    _TUTF1 = r"[\x01-\x1F\x21\x23-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]"
    _UTFMB = rf"[\x80-{chr(sys.maxunicode)}]"
    _LEADCHAR = rf"{_LUTF1}|{_UTFMB}"
    _STRINGCHAR = rf"{_SUTF1}|{_UTFMB}"
    _TRAILCHAR = rf"{_TUTF1}|{_UTFMB}"
    _STRING_RE = re.compile(
        rf"""
        (
            ({_LEADCHAR}|{_PAIR})
            (
                ({_STRINGCHAR}|{_PAIR})*
                ({_TRAILCHAR}|{_PAIR})
            )?
        )?
        """,
        re.VERBOSE,
    )
    _HEXSTRING_RE = re.compile(r"#([\da-zA-Z]{2})+")
    _WHITESPACE_RE = re.compile(r"\s")

    def __init__(self, data: str) -> None:
        self._data = data
        self._idx = 0

    def _has_data(self) -> bool:
        return self._idx < len(self._data)

    def _peek(self) -> str | None:
        if self._has_data():
            return self._data[self._idx]
        return None

    def _read_char(self, ch: str) -> None:
        if self._peek() != ch:
            raise ValueError
        self._idx += 1

    def _swallow_whitespace(self) -> None:
        while (peeked := self._peek()) and self._WHITESPACE_RE.match(peeked):
            self._idx += 1

    def _read_re(self, pat: re.Pattern) -> str:
        match = pat.match(self._data, pos=self._idx)
        if match is None:
            raise ValueError
        val = match.group()
        self._idx += len(val)
        return val

    def parse(self) -> Name:
        """
        Parses the `data` string and converts it to a Name.
        """
        rdns = [self._parse_rdn()]

        while self._has_data():
            self._read_char(",")
            rdns.append(self._parse_rdn())

        return Name(rdns)

    def _parse_rdn(self) -> RelativeDistinguishedName:
        nas = [self._parse_na()]
        self._swallow_whitespace()
        while self._peek() == "+":
            logger.warning("Parsing multi-valued RDN")
            self._read_char("+")
            self._swallow_whitespace()
            nas.append(self._parse_na())

        return RelativeDistinguishedName(nas)

    def _parse_na(self) -> NameAttribute:
        self._swallow_whitespace()
        try:
            oid_value = self._read_re(self._OID_RE)
        except ValueError as ve:
            name = self._read_re(self._DESCR_RE)
            oid = STR_TO_SUBJECT_FIELDS.get(name.upper())
            if oid is None:
                raise ValueError from ve
        else:
            oid = ObjectIdentifier(oid_value)

        self._swallow_whitespace()
        self._read_char("=")
        self._swallow_whitespace()
        if self._peek() == "#":
            value = self._read_re(self._HEXSTRING_RE)
            value = binascii.unhexlify(value[1:]).decode()
        else:
            raw_value = self._read_re(self._STRING_RE)
            value = _unescape_dn_value(raw_value)

        return NameAttribute(oid, value)


def try_parse_as_lax_rfc4514_string(
    input: str,
) -> list[tuple[SearchAttribute, str]] | None:
    # We (try to) parse the string to subject fields first,
    # and then map those to LDAP attributes, because this
    # code comes from cryptography + we want to support
    # OIDs.
    try:
        name = _LaxRFC4514NameParser(input).parse()
    except ValueError:
        logger.debug("Failed to parse string as RFC4514: %s", input, exc_info=True)
        return None

    search_attrs: list[tuple[SearchAttribute, str]] = []
    for rdns in name.rdns:
        for attr in rdns:
            if search_attr := SUBJECT_FIELDS_TO_SEARCH_ATTRS.get(attr.oid):
                assert isinstance(attr.value, str)
                search_attrs.append((search_attr, attr.value))
            elif attr.oid != NameOID.COUNTRY_NAME:
                logger.info("OID not mapped to ldap attr: %s", attr.oid.dotted_string)

    if not search_attrs:
        logger.warning("No known RFC4514 attrs left after mapping: %s", input)
        return None

    return search_attrs
