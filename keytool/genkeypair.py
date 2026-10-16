"""Flujo interactivo y generacion de pares RSA."""

from __future__ import annotations

import getpass;
import sys;
import warnings;
from datetime import datetime, timedelta, timezone;
from pathlib import Path;

from .errors import DuplicateAliasError, KeytoolError;

try:
    from cryptography import x509;
    from cryptography.hazmat.primitives import hashes, serialization;
    from cryptography.hazmat.primitives.asymmetric import rsa;
    from cryptography.x509.oid import NameOID;
except ModuleNotFoundError:
    x509 = None;
    hashes = None;
    serialization = None;
    rsa = None;
    NameOID = None;

from .keystore import (
    DEFAULT_KEYSTORE,
    DN_FIELDS,
    UNKNOWN_DN_VALUE,
    KeyEntry,
    load_keystore,
    save_keystore,
);

MAX_PASSWORD_ATTEMPTS = 1;
MAX_ALIAS_ATTEMPTS = 3;
SUPPORTED_KEY_SIZES = (2048, 3072, 4096, 7680, 15360);
CERTIFICATE_VALIDITY_DAYS = 90;
DN_OIDS = {
    "CN": "COMMON_NAME",
    "OU": "ORGANIZATIONAL_UNIT_NAME",
    "O": "ORGANIZATION_NAME",
    "L": "LOCALITY_NAME",
    "ST": "STATE_OR_PROVINCE_NAME",
    "C": "COUNTRY_NAME",
};

def build_subject(dn: dict[str, str]) -> x509.Name:
    """Construye el sujeto compartido por certificados y solicitudes CSR."""
    attributes = [];

    for field in DN_FIELDS:
        value = dn[field];

        if field == "C" and value == UNKNOWN_DN_VALUE:
            continue;
        
        oid = getattr(NameOID, DN_OIDS[field]);
        attributes.append(x509.NameAttribute(oid, value));
    
    return x509.Name(attributes);

def build_self_signed_certificate(private_key: rsa.RSAPrivateKey, dn: dict[str, str]) -> x509.Certificate:
    subject = build_subject(dn);
    now = datetime.now(timezone.utc).replace(microsecond=0);

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERTIFICATE_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    );

def read_password(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning);

        return getpass.getpass(prompt);

def read_required(prompt: str) -> str:
    value = input(prompt).strip();

    if not value:
        raise ValueError("Los campos solicitados no pueden estar vacios.");

    return value;

def resolve_key_algorithm(keyalg: str | None) -> str:
    """Valida RSA; en modo interactivo vuelve a preguntar si es necesario."""
    if keyalg is not None:
        algorithm = keyalg.strip().upper();

        if algorithm != "RSA":
            raise ValueError("Solo se admite -keyalg RSA en esta implementacion.");
    
        return algorithm;

    while True:
        algorithm = read_required("Enter key algorithm: ").upper();

        if algorithm == "RSA":
            return algorithm;
    
        print("Error: algoritmo no valido; solo se admite RSA.", file=sys.stderr);

def is_key_size_supported(keysize: int) -> bool:
    """Indica si el tamano RSA pertenece a la lista admitida."""
    return keysize in SUPPORTED_KEY_SIZES;

def resolve_key_size(keysize: int | None) -> int:
    if keysize is not None:
        if not is_key_size_supported(keysize):
            allowed = ", ".join(map(str, SUPPORTED_KEY_SIZES));

            raise ValueError(f"-keysize debe ser uno de estos valores: {allowed}.");
    
        return keysize;

    while True:
        allowed = ", ".join(map(str, SUPPORTED_KEY_SIZES));
        entered = input(f"Enter key size ({allowed}) [2048]: ").strip();

        try:
            resolved = 2048 if entered == "" else int(entered);
        except ValueError:
            resolved = 0;
        
        if is_key_size_supported(resolved):
            return resolved;
    
        print(
            f"Error: tamano no valido; valores admitidos: {allowed}.",
            file=sys.stderr,
        );

def parse_dname(dname: str) -> dict[str, str]:
    parts = [part.strip() for part in dname.split(",") if part.strip()];
    values: dict[str, str] = {};

    for part in parts:
        key, separator, value = part.partition("=");
        field = key.strip().upper();
        normalized = value.strip();

        if not separator or field not in DN_FIELDS or not normalized:
            raise ValueError(
                "-dname debe usar el formato CN=..., OU=..., O=..., L=..., ST=..., C=..."
            );
    
        if field in values:
            raise ValueError(f"-dname repite el campo '{field}'.");
    
        values[field] = normalized;
    
    if set(values) != set(DN_FIELDS):
        raise ValueError("-dname debe incluir exactamente CN, OU, O, L, ST y C.");

    return values;

def validate_country(dn: dict[str, str]) -> None:
    country = dn["C"];

    if country == UNKNOWN_DN_VALUE:
        return;

    if len(country) != 2 or not country.isascii() or not country.isalpha():
        raise ValueError("C debe ser un codigo de pais de dos letras (p. ej. ES).");

    dn["C"] = country.upper();

def read_dname_interactively() -> dict[str, str]:
    prompts = {
        "CN": "What is your first and last name? [Unknown]: ",
        "OU": "What is the name of your organizational unit? [Unknown]: ",
        "O": "What is the name of your organization? [Unknown]: ",
        "L": "What is the name of your City or Locality? [Unknown]: ",
        "ST": "What is the name of your State or Province? [Unknown]: ",
        "C": "What is the two-letter country code for this unit? [Unknown]: ",
    };

    while True:
        dn = {
            field: input(prompts[field]).strip() or UNKNOWN_DN_VALUE
            for field in DN_FIELDS
        };

        validate_country(dn);
        rendered = ", ".join(f"{field}={dn[field]}" for field in DN_FIELDS);
        confirmation = input(f"Is {rendered} correct? [no/yes]: ").strip().lower();

        if confirmation in {"y", "yes", "s", "si", "sí"}:
            return dn;
    
        if confirmation in {"", "n", "no"}:
            continue;


def resolve_dname(dname: str | None) -> dict[str, str]:
    if dname is not None:
        parsed = parse_dname(dname);
        validate_country(parsed);

        return parsed;

    return read_dname_interactively();

def read_new_store_password(
    supplied: str | None,
    prompt: str = "Enter new keystore password: ",
    *,
    current_password: str | None = None,
) -> str:
    password = supplied if supplied is not None else read_password(prompt);
    
    if not password:
        raise ValueError("La contrasena no puede estar vacia.");

    if len(password) < 8:
        raise ValueError("La contrasena debe tener al menos 8 caracteres.");

    if password == current_password:
        raise ValueError("La contrasena nueva debe ser distinta de la actual.");

    if supplied is None and read_password("Re-enter new password: ") != password:
        raise ValueError("Las contrasenas no coinciden.");

    return password;

def read_store_password(path: Path, spwrd: str | None) -> str:
    if not path.exists():
        return read_new_store_password(spwrd, "Enter keystore password: ");

    password = spwrd if spwrd is not None else read_password("Enter keystore password: ");

    if not password:
        raise ValueError("La contrasena no puede estar vacia.");

    return password;

def open_keystore_with_password(path: Path, storepass: str | None) -> tuple[str, dict[str, KeyEntry]]:
    """Abre o crea el KeyStore con un unico intento por ejecucion."""
    if not path.exists():
        return read_store_password(path, storepass), {};

    password = read_store_password(path, storepass);

    return password, load_keystore(path, password);

def resolve_key_password(keypass: str | None, storepass: str, alias: str) -> str:
    if keypass is not None:
        if not keypass:
            raise ValueError("-keypass no puede estar vacio.");
    
        return keypass;

    password = read_password(f"Enter key password for <{alias}> (RETURN if same as keystore password): ");

    if password == "":
        return storepass;

    if read_password("Re-enter key password: ") != password:
        raise ValueError("Las contrasenas de la clave no coinciden.");

    return password;

def resolve_alias(alias: str | None) -> str:
    if alias is not None:
        resolved = alias.strip();

        if not resolved:
            raise ValueError("Los campos solicitados no pueden estar vacios.");
    
        return resolved;

    typed = input("Enter key alias [mykey]: ");

    if typed == "":
        return "mykey";

    resolved = typed.strip();

    if not resolved:
        raise ValueError("Los campos solicitados no pueden estar vacios.");

    return resolved;


def resolve_unique_alias(alias: str | None, entries: dict[str, KeyEntry]) -> str:
    if alias is not None:
        resolved = resolve_alias(alias);

        if resolved in entries:
            raise DuplicateAliasError(f"El alias '{resolved}' ya existe.");
    
        return resolved;

    last_alias = "";

    for attempt in range(1, MAX_ALIAS_ATTEMPTS + 1):
        resolved = resolve_alias(None);

        last_alias = resolved;

        if resolved not in entries:
            return resolved;
    
        remaining_attempts = MAX_ALIAS_ATTEMPTS - attempt;

        if remaining_attempts == 0:
            raise DuplicateAliasError(f"El alias '{resolved}' ya existe. Se agotaron los 3 intentos.");
    
        print(
            f"Error: El alias '{resolved}' ya existe. Intentos restantes: {remaining_attempts}.",
            file=sys.stderr,
        );
    
    raise DuplicateAliasError(f"El alias '{last_alias}' ya existe.");


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
        algorithm = resolve_key_algorithm(keyalg);
        resolved_keysize = resolve_key_size(keysize);
        password, entries = open_keystore_with_password(path, storepass);
        alias = resolve_unique_alias(alias, entries);
        key_password = resolve_key_password(keypass, password, alias);
        dn = resolve_dname(dname);
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=resolved_keysize);

        certificate = build_self_signed_certificate(private_key, dn);
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
            certificate=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        );

        save_keystore(path, password, entries);
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        );

        return 1;
    except (KeytoolError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr);

        return 1;
    except (EOFError, KeyboardInterrupt):
        print(
            "\nError: operacion cancelada; no se ha guardado la entrada.",
            file=sys.stderr,
        );

        return 1;

    print(
        f"Exito: par {algorithm} de {resolved_keysize} bits guardado con alias '{alias}' en '{path}'."
    );

    return 0;