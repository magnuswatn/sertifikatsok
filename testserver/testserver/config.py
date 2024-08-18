import logging
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from attrs import field, frozen
from cattrs.preconf.json import make_converter
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import Certificate, load_pem_x509_certificate

from . import ClonedCa, Env
from .ca import (
    BuypassCertIssuingImpl,
    CertificateAuthority,
    CertIssuingImpl,
    CommfidesCertIssuingImpl,
)

logger = logging.getLogger(__name__)

json_converter = make_converter()
json_converter.register_structure_hook(
    RSAPrivateKey, lambda v, _: load_pem_private_key(v.encode(), password=None)
)
json_converter.register_structure_hook(
    Certificate, lambda v, _: load_pem_x509_certificate(v.encode())
)
json_converter.register_unstructure_hook(
    RSAPrivateKey,
    lambda v: v.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode(),
)
json_converter.register_unstructure_hook(
    Certificate,
    lambda v: v.public_bytes(Encoding.PEM).decode(),
)


@frozen
class DuplicatedCaCache:
    key: RSAPrivateKey
    delegated_ocsp_responder_cert: Certificate
    delegated_ocsp_responder_key: RSAPrivateKey


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
        env_config = (
            cloned_ca_config.test_config
            if env == "test"
            else cloned_ca_config.prod_config
        )

        input_file = self.input_folder.joinpath(env_config.org_ca_cert)
        output_file = self.output_folder.joinpath(env_config.org_ca_cert)
        cache_folder = self.output_folder.joinpath(".key_cache")
        cache_file = cache_folder.joinpath(f"{env_config.org_ca_cert}.json")

        cache_folder.mkdir(exist_ok=True)

        if output_file.exists() and cache_file.exists():
            logger.info("Loading cached duplicated CA %s", cloned_ca)

            cached_ca = json_converter.loads(cache_file.read_bytes(), DuplicatedCaCache)

            logger.info("Loading cached duplicated CA %s", cloned_ca)

            delegated_responder = (
                cached_ca.delegated_ocsp_responder_cert,
                cached_ca.delegated_ocsp_responder_key,
            )

            ca = CertificateAuthority.create_from_cache(
                env_config.cdp,
                env_config.ocsp_url,
                cloned_ca_config.ocsp_type,
                cloned_ca_config.ocsp_lifetime,
                load_pem_x509_certificate(output_file.read_bytes()),
                cached_ca.key,
                cloned_ca_config.seid_v,
                impl,
                cloned_ca_config.ldap_name,
                delegated_responder,
                env,
            )
        else:
            logger.info("Duplicating CA %s", cloned_ca)
            ca = CertificateAuthority.create_from_original(
                env_config.cdp,
                env_config.ocsp_url,
                cloned_ca_config.ocsp_type,
                cloned_ca_config.ocsp_lifetime,
                load_pem_x509_certificate(input_file.read_bytes()),
                cloned_ca_config.seid_v,
                impl,
                cloned_ca_config.ldap_name,
                env,
                generate_delegated_responder=cloned_ca_config.ocsp_type.is_delegated_responder,
            )
            output_file.write_bytes(ca.impl.cert.public_bytes(Encoding.PEM))

            duplicated_ca_cache = DuplicatedCaCache(
                ca.impl.private_key,
                # For CAs that doesn't use a delegated OCSP signer, this
                # will store the normal CA cert + priv key. But that is ok.
                ca.ocsp_responder.cert,
                ca.ocsp_responder.private_key,
            )
            cache_file.write_text(json_converter.dumps(duplicated_ca_cache))
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
