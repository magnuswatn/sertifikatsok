class SertifikatSokError(Exception):
    """Superclass for all exceptions"""


class ClientError(SertifikatSokError):
    """Signifies that the request was malformed"""


class ServerError(SertifikatSokError):
    """Signifies that the server failed to respond to the request"""


class CouldNotGetValidCRLError(SertifikatSokError):
    """Signifies that we could not download a valid crl"""


class ConfigurationError(SertifikatSokError):
    """Sertifikatsok was configured incorrectly"""


class MalformedCertificateError(SertifikatSokError):
    pass
