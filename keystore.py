"""Persistencia cifrada y validacion de entradas del KeyStore."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import TypedDict

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


class KeyEntry(TypedDict):
    private_key: str
    public_key: str
    dn: dict[str, str]


def ensure_crypto_available() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise ModuleNotFoundError(
            "No se pudo importar 'cryptography' con este interprete de Python."
        ) from CRYPTO_IMPORT_ERROR


def derive_store_key(password: str, salt: bytes) -> bytes:
    ensure_crypto_available()
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        password.encode("utf-8")
    )


def load_keystore(path: Path, password: str) -> dict[str, KeyEntry]:
    """Load and validate a version-1 AES-GCM encrypted keystore."""
    ensure_crypto_available()
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"No existe el KeyStore: '{path}'.") from exc

    offset = len(STORE_HEADER)
    minimum_size = offset + STORE_SALT_SIZE + STORE_NONCE_SIZE + AES_GCM_TAG_SIZE
    if not data.startswith(STORE_HEADER) or len(data) < minimum_size:
        raise ValueError("Formato de KeyStore no valido.")

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
        raise ValueError("Contrasena incorrecta o KeyStore alterado.") from exc

    try:
        entries = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Contenido de KeyStore no valido.") from exc
    if not isinstance(entries, dict):
        raise ValueError("Contenido de KeyStore no valido.")

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
            raise ValueError("Entrada de KeyStore no valida.")
        dn = entry["dn"]
        if set(dn) != set(DN_FIELDS) or any(
            not isinstance(value, str) or not value.strip() for value in dn.values()
        ):
            raise ValueError("DN de KeyStore no valido.")
        store[alias] = KeyEntry(
            private_key=entry["private_key"], public_key=entry["public_key"], dn=dn
        )
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
        raise ValueError(f"No existe el alias '{normalized_alias}' en el KeyStore.") from exc


def save_keystore(path: Path, password: str, entries: dict[str, KeyEntry]) -> None:
    """Write a version-1 keystore: header, salt, nonce, then AES-GCM ciphertext."""
    ensure_crypto_available()
    salt = os.urandom(STORE_SALT_SIZE)
    nonce = os.urandom(STORE_NONCE_SIZE)
    plaintext = json.dumps(entries, ensure_ascii=True).encode("utf-8")
    ciphertext = AESGCM(derive_store_key(password, salt)).encrypt(
        nonce, plaintext, STORE_HEADER
    )

    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            temporary.write(STORE_HEADER + salt + nonce + ciphertext)
            temporary.flush()
            os.fsync(temporary.fileno())
        except OSError:
            temporary.close()
            temporary_path.unlink()
            raise
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)