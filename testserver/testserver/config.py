import logging
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from attr import field, frozen
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import load_pem_x509_certificate

from . import ClonedCa, Env
from .ca import (
    BuypassCertIssuingImpl,
    CertificateAuthority,
    CertIssuingImpl,
    CommfidesCertIssuingImpl,
)

logger = logging.getLogger(__name__)


@frozen
class CaLoader:
    input_folder: Path
    output_folder: Path
    loaded_ca_s: dict[ClonedCa, CertificateAuthority] = field(factory=dict)

    def _load_ca(
        self,
        cloned_ca: ClonedCa,
        env: Env,
        impl: type[CertIssuingImpl],
    ) -> CertificateAuthority:
        cloned_ca_config = cloned_ca.value
        cdp, ca_cert = (
            (cloned_ca_config.cdp_test, cloned_ca_config.org_ca_cert_test)
            if env == "test"
            else (cloned_ca_config.cdp_prod, cloned_ca_config.org_ca_cert_prod)
        )

        input_file = self.input_folder.joinpath(ca_cert)
        output_file = self.output_folder.joinpath(ca_cert)
        cache_folder = self.output_folder.joinpath(".key_cache")
        key_cache_file = cache_folder.joinpath(ca_cert)

        cache_folder.mkdir(exist_ok=True)

        if output_file.exists() and key_cache_file.exists():
            logger.info("Loading cached duplicated CA %s", cloned_ca)
            cached_priv_key = load_pem_private_key(
                key_cache_file.read_bytes(), password=None
            )
            assert isinstance(cached_priv_key, RSAPrivateKey)
            ca = CertificateAuthority.create_from_cache(
                cdp,
                load_pem_x509_certificate(output_file.read_bytes()),
                cached_priv_key,
                cloned_ca_config.seid_v,
                impl,
                cloned_ca_config.ldap_name,
                env,
            )
        else:
            logger.info("Duplicating CA %s", cloned_ca)
            ca = CertificateAuthority.create_from_original(
                cdp,
                load_pem_x509_certificate(input_file.read_bytes()),
                cloned_ca_config.seid_v,
                impl,
                cloned_ca_config.ldap_name,
                env,
            )
            output_file.write_bytes(ca.impl.cert.public_bytes(Encoding.PEM))
            key_cache_file.write_bytes(
                ca.impl.private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                )
            )
        self.loaded_ca_s[cloned_ca] = ca
        return ca

    def load_buypass_ca(self, cloned_ca: ClonedCa, env: Env) -> None:
        self._load_ca(
            cloned_ca,
            env,
            BuypassCertIssuingImpl,
        )

    def load_commfides_ca(self, cloned_ca: ClonedCa, env: Env) -> None:
        self._load_ca(
            cloned_ca,
            env,
            CommfidesCertIssuingImpl,
        )


def init(env: Env) -> dict[ClonedCa, CertificateAuthority]:
    input_folder = Path(f"../api/certs/{env}")
    output_folder = Path(f"cloned_certs/{env}")

    ca_loader = CaLoader(input_folder, output_folder)

    # cryptography releases the GIL while calling
    # OpenSSL, so using threads here gives us a nice
    # speedup.
    futures: list[Future] = []
    with ThreadPoolExecutor(max_workers=4) as e:
        for ca in ClonedCa:
            if ca.is_buypass:
                futures.append(e.submit(ca_loader.load_buypass_ca, ca, env))
            else:
                futures.append(e.submit(ca_loader.load_commfides_ca, ca, env))
    for future in futures:
        # check for exceptions
        future.result()

    logger.info(
        "Finished loading CAs",
    )
    return ca_loader.loaded_ca_s
