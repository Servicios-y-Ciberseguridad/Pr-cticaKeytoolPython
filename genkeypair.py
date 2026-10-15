"""Flujo interactivo y generacion de pares RSA."""

from __future__ import annotations

import getpass
import sys
import warnings
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ModuleNotFoundError:
    serialization = None
    rsa = None

from keystore import (
    DEFAULT_KEYSTORE,
    DN_FIELDS,
    UNKNOWN_DN_VALUE,
    KeyEntry,
    ensure_crypto_available,
    load_keystore,
    save_keystore,
)

MAX_PASSWORD_ATTEMPTS = 3;
MAX_ALIAS_ATTEMPTS = 3;

def read_password(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning);

        return getpass.getpass(prompt);

def read_prompt(prompt: str) -> str:
    return input(prompt).strip();

def resolve_key_algorithm(keyalg: str | None) -> str:
    while keyalg.upper() != "RSA":
        print("Solo se admite -keyalg RSA en esta implementacion.");

        keyalg = read_prompt("Enter key algorithm: ");

    return keyalg.upper();

def is_key_size_correct(ksize: int) -> bool:
    return ksize is 2048 or ksize is 3072 or ksize is 4096 or ksize is 7680 or ksize is 15360;

def resolve_key_size(keysize: int) -> int:
    while not is_key_size_correct(keysize):
        print("Tamaño de llave invalido (2048, 3072, 4096, 7680, 15360)");

        keysize = read_prompt("Enter key size: ");

    return keysize;

def parse_dname(dname: str) -> dict[str, str]:
    parts = [part.strip() for part in dname.split(",") if part.strip()];

    values: dict[str, str] = {};

    for part in parts:
        key, separator, value = part.partition("=")
        field = key.strip().upper()
        normalized = value.strip()
        if not separator or field not in DN_FIELDS or not normalized:
            raise ValueError(
                "-dname debe usar el formato CN=..., OU=..., O=..., L=..., ST=..., C=..."
            )
        if field in values:
            raise ValueError(f"-dname repite el campo '{field}'.")
        values[field] = normalized
    if set(values) != set(DN_FIELDS):
        raise ValueError("-dname debe incluir exactamente CN, OU, O, L, ST y C.")
    return values


def validate_country(dn: dict[str, str]) -> None:
    country = dn["C"]
    if country == UNKNOWN_DN_VALUE:
        return
    if len(country) != 2 or not country.isascii() or not country.isalpha():
        raise ValueError("C debe ser un codigo de pais de dos letras (p. ej. ES).")
    dn["C"] = country.upper()


def read_dname_interactively() -> dict[str, str]:
    prompts = {
        "CN": "What is your first and last name? [Unknown]: ",
        "OU": "What is the name of your organizational unit? [Unknown]: ",
        "O": "What is the name of your organization? [Unknown]: ",
        "L": "What is the name of your City or Locality? [Unknown]: ",
        "ST": "What is the name of your State or Province? [Unknown]: ",
        "C": "What is the two-letter country code for this unit? [Unknown]: ",
    }
    while True:
        dn = {
            field: input(prompts[field]).strip() or UNKNOWN_DN_VALUE
            for field in DN_FIELDS
        }
        validate_country(dn)
        rendered = ", ".join(f"{field}={dn[field]}" for field in DN_FIELDS)
        confirmation = input(f"Is {rendered} correct? [no/yes]: ").strip().lower()
        if confirmation in {"y", "yes", "s", "si", "sí"}:
            return dn
        if confirmation in {"", "n", "no"}:
            continue


def resolve_dname(dname: str | None) -> dict[str, str]:
    if dname is not None:
        parsed = parse_dname(dname)
        validate_country(parsed)
        return parsed
    return read_dname_interactively()


def read_store_password(path: Path, storepass: str | None) -> str:
    password = storepass if storepass is not None else read_password("Enter keystore password: ")
    if not password:
        raise ValueError("La contrasena no puede estar vacia.")
    if not path.exists():
        if len(password) < 8:
            raise ValueError("La contrasena debe tener al menos 8 caracteres.")
        if storepass is None and read_password("Re-enter new password: ") != password:
            raise ValueError("Las contrasenas no coinciden.")
    return password

def open_keystore_with_password(
    path: Path, storepass: str | None
) -> tuple[str, dict[str, KeyEntry]]:
    if not path.exists():
        if storepass is not None:
            return read_store_password(path, storepass), {}
        last_error: ValueError | None = None
        for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
            try:
                return read_store_password(path, None), {}
            except ValueError as exc:
                last_error = exc
                if str(exc) not in {
                    "La contrasena debe tener al menos 8 caracteres.",
                    "Las contrasenas no coinciden.",
                }:
                    raise
                remaining_attempts = MAX_PASSWORD_ATTEMPTS - attempt
                if remaining_attempts == 0:
                    raise ValueError(f"{exc} Se agotaron los 3 intentos.") from exc
                print(
                    f"Error: {exc} Intentos restantes: {remaining_attempts}.",
                    file=sys.stderr,
                )
        assert last_error is not None
        raise last_error

    if storepass is not None:
        password = read_store_password(path, storepass)
        return password, load_keystore(path, password)
    last_error = None
    for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
        password = read_store_password(path, None)
        try:
            return password, load_keystore(path, password)
        except ValueError as exc:
            last_error = exc
            if str(exc) != "Contrasena incorrecta o KeyStore alterado.":
                raise
            remaining_attempts = MAX_PASSWORD_ATTEMPTS - attempt
            if remaining_attempts == 0:
                raise ValueError(
                    "Contrasena incorrecta o KeyStore alterado. Se agotaron los 3 intentos."
                ) from exc
            print(
                f"Error: contrasena incorrecta. Intentos restantes: {remaining_attempts}.",
                file=sys.stderr,
            )
    assert last_error is not None
    raise last_error


def resolve_key_password(keypass: str | None, storepass: str, alias: str) -> str:
    if keypass is not None:
        if not keypass:
            raise ValueError("-keypass no puede estar vacio.")
        return keypass
    password = read_password(
        f"Enter key password for <{alias}> (RETURN if same as keystore password): "
    )
    if password == "":
        return storepass
    if read_password("Re-enter key password: ") != password:
        raise ValueError("Las contrasenas de la clave no coinciden.")
    return password


def resolve_alias(alias: str | None) -> str:
    if alias is not None:
        resolved = alias.strip()
        if not resolved:
            raise ValueError("Los campos solicitados no pueden estar vacios.")
        return resolved
    typed = input("Enter key alias [mykey]: ")
    if typed == "":
        return "mykey"
    resolved = typed.strip()
    if not resolved:
        raise ValueError("Los campos solicitados no pueden estar vacios.")
    return resolved


def resolve_unique_alias(alias: str | None, entries: dict[str, KeyEntry]) -> str:
    if alias is not None:
        resolved = resolve_alias(alias)
        if resolved in entries:
            raise ValueError(f"El alias '{resolved}' ya existe.")
        return resolved
    last_alias = ""
    for attempt in range(1, MAX_ALIAS_ATTEMPTS + 1):
        resolved = resolve_alias(None)
        last_alias = resolved
        if resolved not in entries:
            return resolved
        remaining_attempts = MAX_ALIAS_ATTEMPTS - attempt
        if remaining_attempts == 0:
            raise ValueError(f"El alias '{resolved}' ya existe. Se agotaron los 3 intentos.")
        print(
            f"Error: El alias '{resolved}' ya existe. Intentos restantes: {remaining_attempts}.",
            file=sys.stderr,
        )
    raise ValueError(f"El alias '{last_alias}' ya existe.")


def handle_genkeypair(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    dname: str | None = None,
    keyalg: str | None = None,
    keysize: int | None = None,
) -> int:
    """Genera un par RSA y guarda la entrada en un almacen cifrado."""
    try:
        ensure_crypto_available()
        algorithm = resolve_key_algorithm(keyalg)
        resolved_keysize = resolve_key_size(keysize)
        password, entries = open_keystore_with_password(path, storepass)
        alias = resolve_unique_alias(alias, entries)
        key_password = resolve_key_password(keypass, password, alias)
        dn = resolve_dname(dname)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=resolved_keysize
        )
        entries[alias] = KeyEntry(
            private_key=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(key_password.encode("utf-8")),
            ).decode("ascii"),
            public_key=private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
            dn=dn,
        )
        save_keystore(path, password, entries)
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print(
            "\nError: operacion cancelada; no se ha guardado la entrada.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Exito: par {algorithm} de {resolved_keysize} bits guardado con alias '{alias}' en '{path}'."
    )
    return 0