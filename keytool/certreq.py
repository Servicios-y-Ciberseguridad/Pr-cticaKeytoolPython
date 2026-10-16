"""Generacion de solicitudes de firma de certificado (CSR)."""

from __future__ import annotations

import base64
import getpass
import re
import sys
from pathlib import Path

from .errors import (
    AliasNotFoundError,
    KeyPasswordError,
    KeytoolError,
    KeystoreNotFoundError,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
<<<<<<< HEAD
    from cryptography.x509.oid import NameOID
=======
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
except ModuleNotFoundError:
    x509 = None
    hashes = None
    serialization = None
    rsa = None
<<<<<<< HEAD
    NameOID = None

from .genkeypair import read_password, resolve_alias
from .keystore import (
    DEFAULT_KEYSTORE,
    DN_FIELDS,
    UNKNOWN_DN_VALUE,
=======

from .genkeypair import build_subject, read_password, resolve_alias
from .keystore import (
    DEFAULT_KEYSTORE,
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
    KeyEntry,
    load_keystore,
    write_bytes_atomic,
)

<<<<<<< HEAD
# Los nombres se guardan como texto para que el modulo pueda cargarse incluso
# cuando cryptography no este instalado; main intentara usar el entorno virtual.
DN_OIDS = {
    "CN": "COMMON_NAME",
    "OU": "ORGANIZATIONAL_UNIT_NAME",
    "O": "ORGANIZATION_NAME",
    "L": "LOCALITY_NAME",
    "ST": "STATE_OR_PROVINCE_NAME",
    "C": "COUNTRY_NAME",
}

=======
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
KEYTOOL_PEM_HEADER = b"-----BEGIN NEW CERTIFICATE REQUEST-----"
KEYTOOL_PEM_FOOTER = b"-----END NEW CERTIFICATE REQUEST-----"
PEM_LINE_LENGTH = 64


def resolve_store_password(storepass: str | None) -> str:
    """Usa la contrasena recibida o la solicita sin mostrarla."""
    password = storepass if storepass is not None else read_password(
        "Enter keystore password: "
    )
    if not password:
        raise ValueError("La contrasena del KeyStore no puede estar vacia.")
    return password


def open_existing_keystore(
    path: Path, storepass: str | None
) -> tuple[str, dict[str, KeyEntry]]:
    """Abre el KeyStore con un unico intento de contrasena."""
    if not path.exists():
        raise KeystoreNotFoundError(f"No existe el KeyStore: '{path}'.")

    password = resolve_store_password(storepass)
    return password, load_keystore(path, password)


def load_private_key(
    entry: KeyEntry,
    alias: str,
    storepass: str,
    keypass: str | None,
):
    """Descifra la clave privada del alias para firmar el CSR."""
    if keypass is None:
        entered = read_password(
            f"Enter key password for <{alias}> "
            "(RETURN if same as keystore password): "
        )
        password = entered or storepass
    else:
        if not keypass:
            raise ValueError("-keypass no puede estar vacio.")
        password = keypass

    try:
        private_key = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"),
            password=password.encode("utf-8"),
        )
    except (TypeError, ValueError) as exc:
        raise KeyPasswordError(
            f"Contrasena incorrecta para la clave del alias '{alias}'."
        ) from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(f"La clave del alias '{alias}' no es RSA.")
    return private_key


<<<<<<< HEAD
def build_subject(dn: dict[str, str]):
    """Convierte los campos CN, OU, O, L, ST y C en un sujeto X.509."""
    attributes = []
    for field in DN_FIELDS:
        value = dn[field]
        if field == "C" and value == UNKNOWN_DN_VALUE:
            continue
        oid = getattr(NameOID, DN_OIDS[field])
        attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)


=======
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
def resolve_output_path(output: Path | None, alias: str) -> Path:
    """Acepta una salida .csr/.pem o crea un nombre seguro desde el alias."""
    if output is None:
        safe_alias = re.sub(r"[^A-Za-z0-9._-]+", "_", alias).strip("._")
        output = Path(f"{safe_alias or 'request'}.csr")
    if output.suffix.lower() not in {".csr", ".pem"}:
        raise ValueError(
            "El archivo indicado con -file debe tener extension .csr o .pem."
        )
    return output


def ensure_key_pair_matches(private_key, entry: KeyEntry, alias: str) -> None:
    """Comprueba que las claves privada y publica pertenecen al mismo par."""
    public_key = serialization.load_pem_public_key(entry["public_key"].encode("ascii"))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError(f"La clave publica del alias '{alias}' no es RSA.")
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise ValueError(f"Las claves del alias '{alias}' no coinciden.")


def encode_keytool_pem(csr) -> bytes:
    """Codifica un CSR como el PEM RFC mostrado por Java keytool."""
    der = csr.public_bytes(serialization.Encoding.DER)
    encoded = base64.b64encode(der)
    lines = [
        encoded[index : index + PEM_LINE_LENGTH]
        for index in range(0, len(encoded), PEM_LINE_LENGTH)
    ]
    return b"\n".join([KEYTOOL_PEM_HEADER, *lines, KEYTOOL_PEM_FOOTER, b""])


def handle_certreq(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    output: Path | None = None,
) -> int:
    """Carga un alias, firma su CSR y lo guarda como PEM."""
    try:
        # 1. Autenticar el almacen y localizar la entrada.
        store_password, entries = open_existing_keystore(path, storepass)
        resolved_alias = resolve_alias(alias)
        try:
            entry = entries[resolved_alias]
        except KeyError as exc:
            raise AliasNotFoundError(
                f"No existe el alias '{resolved_alias}' en el KeyStore."
            ) from exc

        # 2. Descifrar la clave y construir la solicitud con el DN guardado.
        private_key = load_private_key(
            entry, resolved_alias, store_password, keypass
        )
        ensure_key_pair_matches(private_key, entry, resolved_alias)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(build_subject(entry["dn"]))
            .sign(private_key, hashes.SHA256())
        )

        # 3. Exportar solo la solicitud publica; la clave privada no se escribe.
        output_path = resolve_output_path(output, resolved_alias)
        if output_path.resolve() == path.resolve():
            raise ValueError("El archivo CSR no puede sobrescribir el KeyStore.")
        write_bytes_atomic(
            output_path,
            encode_keytool_pem(csr),
        )
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except (KeytoolError, OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nError: operacion cancelada; no se genero el CSR.", file=sys.stderr)
        return 1

    print(
        f"Exito: CSR del alias '{resolved_alias}' guardado en '{output_path}' "
        "en formato PEM compatible con keytool."
    )
    return 0
