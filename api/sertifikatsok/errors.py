class SertifikatSokError(Exception):
    """Superclass for all exceptions"""

    pass


class ClientError(SertifikatSokError):
    """Signifies that the request was malformed"""

    pass


class ServerError(SertifikatSokError):
    """Signifies that the server failed to respond to the request"""

    pass


class CouldNotGetValidCRLError(SertifikatSokError):
    """Signifies that we could not download a valid crl"""

    pass


class ConfigurationError(SertifikatSokError):
    """Sertifikatsok was configured incorrectly"""

    pass


class MalformedCertificateError(SertifikatSokError):
    pass
