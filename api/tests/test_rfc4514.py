import pytest

from sertifikatsok.enums import SearchAttribute
from sertifikatsok.rfc4514 import try_parse_as_lax_rfc4514_string


@pytest.mark.parametrize(
    "input",
    [
        "C=NO, O=NORSK HELSENETT SF, CN=SFM, serialNumber=994598759",
        "C=NO,  O=NORSK HELSENETT SF,  CN=SFM,  serialNumber=994598759",
        "C=NO,	O=NORSK HELSENETT SF,	CN=SFM,	serialNumber=994598759",
        "C=NO,		O=NORSK HELSENETT SF,		CN=SFM,		serialNumber=994598759",
        "C=NO,O=NORSK HELSENETT SF, CN=SFM, serialNumber=994598759",
        "C = NO,O = NORSK HELSENETT SF,CN = SFM,serialNumber = 994598759",
        "C  =  NO,O  =  NORSK HELSENETT SF,CN  =  SFM,serialNumber  =  994598759",
        "C	=	NO,O	=	NORSK HELSENETT SF,CN	=	SFM,serialNumber	=	994598759",
        "C		=		NO,O		=		NORSK HELSENETT SF,CN		=		SFM,serialNumber		=		994598759",
        "C=NO,O=NORSK HELSENETT SF,CN=SFM,serialNumber=994598759",
        "c=NO,o=NORSK HELSENETT SF,cn=SFM,SERIALNUMBER=994598759",
    ],
)
def test_parse_str_with_whitespace(input: str) -> None:
    assert try_parse_as_lax_rfc4514_string(input) == [
        (SearchAttribute.O, "NORSK HELSENETT SF"),
        (SearchAttribute.CN, "SFM"),
        (SearchAttribute.SN, "994598759"),
    ]


@pytest.mark.parametrize(
    "input",
    [
        "C=NO,O=NORSK HELSENETT SF,2.5.4.3=SFM,organizationIdentifier=NTRNO-994598759",
        "2.5.4.6=NO,2.5.4.10=NORSK HELSENETT SF,2.5.4.3=SFM,2.5.4.97=NTRNO-994598759",
        "C=NO,O=NORSK HELSENETT SF,CN=SFM,2.5.4.97=NTRNO-994598759",
    ],
)
def test_parse_str_with_oids(input: str) -> None:
    assert try_parse_as_lax_rfc4514_string(input) == [
        (SearchAttribute.O, "NORSK HELSENETT SF"),
        (SearchAttribute.CN, "SFM"),
        (SearchAttribute.ORGID, "NTRNO-994598759"),
    ]


def test_parse_multi_valued_rdn(caplog: pytest.LogCaptureFixture) -> None:
    # dunnå what to do here, but certs with subjects like this
    # shouldn't exist in the eco system, so /shrug
    assert try_parse_as_lax_rfc4514_string("CN=hei+cn=hade") == [
        (SearchAttribute.CN, "hei"),
        (SearchAttribute.CN, "hade"),
    ]
    assert "Parsing multi-valued RDN" in caplog.text
