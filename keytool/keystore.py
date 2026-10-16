"""Persistencia cifrada y validacion de entradas del KeyStore."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import TypedDict, cast

from .errors import (
    AliasNotFoundError,
    DuplicateAliasError,
    InvalidKeystoreError,
    KeystoreAuthenticationError,
    KeystoreNotFoundError,
)

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ModuleNotFoundError as exc:
    InvalidTag = None
    AESGCM = None
    Scrypt = None
    CRYPTO_IMPORT_ERROR = exc
else:
    CRYPTO_IMPORT_ERROR = None

DEFAULT_KEYSTORE = Path("keystore.myks")
STORE_HEADER = b"MYKEYSTORE\x01"
STORE_SALT_SIZE = 16
STORE_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
DN_FIELDS = ("CN", "OU", "O", "L", "ST", "C")
UNKNOWN_DN_VALUE = "Unknown"

<<<<<<< HEAD
class KeyEntry(TypedDict):
=======
class RequiredKeyEntry(TypedDict):
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
    private_key: str
    public_key: str
    dn: dict[str, str]

<<<<<<< HEAD
=======

class KeyEntry(RequiredKeyEntry, total=False):
    certificate: str

def ensure_crypto_available() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise ModuleNotFoundError(
            "No se pudo importar 'cryptography' con este interprete de Python."
        ) from CRYPTO_IMPORT_ERROR

>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
def derive_store_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        password.encode("utf-8")
    )

def load_keystore(path: Path, password: str) -> dict[str, KeyEntry]:
    """Load and validate a version-1 AES-GCM encrypted keystore."""
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise KeystoreNotFoundError(f"No existe el KeyStore: '{path}'.") from exc

    offset = len(STORE_HEADER)
    minimum_size = offset + STORE_SALT_SIZE + STORE_NONCE_SIZE + AES_GCM_TAG_SIZE
    if not data.startswith(STORE_HEADER) or len(data) < minimum_size:
        raise InvalidKeystoreError("Formato de KeyStore no valido.")

    salt_start = offset
    nonce_start = salt_start + STORE_SALT_SIZE
    ciphertext_start = nonce_start + STORE_NONCE_SIZE
    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]
    try:
        plaintext = AESGCM(derive_store_key(password, salt)).decrypt(
            nonce, data[ciphertext_start:], STORE_HEADER
        )
    except InvalidTag as exc:
        raise KeystoreAuthenticationError(
            "Contrasena incorrecta o KeyStore alterado."
        ) from exc

    try:
        entries = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidKeystoreError("Contenido de KeyStore no valido.") from exc
    if not isinstance(entries, dict):
        raise InvalidKeystoreError("Contenido de KeyStore no valido.")

    store: dict[str, KeyEntry] = {}
    for alias, entry in entries.items():
        if (
            not isinstance(alias, str)
            or not alias.strip()
            or not isinstance(entry, dict)
            or not isinstance(entry.get("private_key"), str)
            or not isinstance(entry.get("public_key"), str)
            or not isinstance(entry.get("dn"), dict)
        ):
            raise InvalidKeystoreError("Entrada de KeyStore no valida.")
        dn = entry["dn"]
        if set(dn) != set(DN_FIELDS) or any(
            not isinstance(value, str) or not value.strip() for value in dn.values()
        ):
            raise InvalidKeystoreError("DN de KeyStore no valido.")
        store[alias] = cast(KeyEntry, entry)
    return store


def load_keystore_entry(path: Path, alias: str, password: str) -> KeyEntry:
    """Return one keystore entry after authenticating and decrypting the store."""
    normalized_alias = alias.strip()
    if not normalized_alias:
        raise ValueError("El alias no puede estar vacio.")
    entries = load_keystore(path, password)
    try:
        return entries[normalized_alias]
    except KeyError as exc:
        raise AliasNotFoundError(
            f"No existe el alias '{normalized_alias}' en el KeyStore."
        ) from exc


def change_keystore_alias(
    path: Path, password: str, alias: str, destalias: str
) -> None:
    """Renombra una entrada sin descifrar su clave privada."""
    source_alias = alias.strip()
    destination_alias = destalias.strip()
    if not source_alias:
        raise ValueError("El alias actual no puede estar vacio.")
    if not destination_alias:
        raise ValueError("El alias de destino no puede estar vacio.")

    entries = load_keystore(path, password)
    try:
        entry = entries[source_alias]
    except KeyError as exc:
        raise AliasNotFoundError(
            f"No existe el alias '{source_alias}' en el KeyStore."
        ) from exc
    if destination_alias in entries:
        raise DuplicateAliasError(f"El alias '{destination_alias}' ya existe.")

    del entries[source_alias]
    entries[destination_alias] = entry
    save_keystore(path, password, entries)


def write_bytes_atomic(path: Path, data: bytes) -> None:
    """Escribe bytes completos y reemplaza el destino solo al terminar."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def save_keystore(path: Path, password: str, entries: dict[str, KeyEntry]) -> None:
    """Cifra y guarda el KeyStore en su formato binario versionado."""
    salt = os.urandom(STORE_SALT_SIZE)
    nonce = os.urandom(STORE_NONCE_SIZE)
    plaintext = json.dumps(entries, ensure_ascii=True).encode("utf-8")
    ciphertext = AESGCM(derive_store_key(password, salt)).encrypt(
        nonce, plaintext, STORE_HEADER
    )
    write_bytes_atomic(path, STORE_HEADER + salt + nonce + ciphertext)
