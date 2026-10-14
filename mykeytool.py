"""Interfaz de linea de comandos para el simulador de Java Keytool."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import tempfile
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypedDict

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ModuleNotFoundError as exc:
    InvalidTag = None;
    serialization = None;
    rsa = None;
    AESGCM = None;
    Scrypt = None;
    CRYPTO_IMPORT_ERROR = exc;
else:
    CRYPTO_IMPORT_ERROR = None;

CommandHandler = Callable[[], int]
DEFAULT_KEYSTORE = Path("keystore.myks")
STORE_HEADER = b"MYKEYSTORE\x01"
STORE_SALT_SIZE = 16
STORE_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
DN_FIELDS = ("CN", "OU", "O", "L", "ST", "C")
UNKNOWN_DN_VALUE = "Unknown"
MAX_PASSWORD_ATTEMPTS = 3
MAX_ALIAS_ATTEMPTS = 3

class KeyEntry(TypedDict):
    private_key: str
    public_key: str
    dn: dict[str, str]

def isCryptoLibraryAvaliable() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        return False;
    else:
        return True;

def derive_store_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"));

def load_keystore(path: Path, password: str) -> dict[str, KeyEntry]:
    """Load and validate a version-1 AES-GCM encrypted keystore."""
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"No existe el KeyStore: '{path}'.") from exc

    offset = len(STORE_HEADER)
    minimum_size = (offset + STORE_SALT_SIZE + STORE_NONCE_SIZE + AES_GCM_TAG_SIZE)

    if not data.startswith(STORE_HEADER) or len(data) < minimum_size:
        raise ValueError("Formato de KeyStore no valido.")
    
    salt_start = offset
    nonce_start = salt_start + STORE_SALT_SIZE
    ciphertext_start = nonce_start + STORE_NONCE_SIZE
    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]

    try:
        plaintext = AESGCM(derive_store_key(password, salt)).decrypt(nonce, data[ciphertext_start:], STORE_HEADER)
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
    if not isCryptoLibraryAvaliable():
            raise ModuleNotFoundError("No se pudo importar 'cryptography' con este interprete de Python.") from CRYPTO_IMPORT_ERROR;

    salt = os.urandom(STORE_SALT_SIZE)
    nonce = os.urandom(STORE_NONCE_SIZE)

    plaintext = json.dumps(entries, ensure_ascii=True).encode("utf-8")
    ciphertext = AESGCM(derive_store_key(password, salt)).encrypt(
        nonce, plaintext, STORE_HEADER
    )

    # El temporal solo contiene datos cifrados y se reemplaza en el mismo volumen.
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

def read_password(prompt: str) -> str:
    # getpass no debe recurrir a una entrada con eco si no hay terminal seguro.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)

        return getpass.getpass(prompt)

def requireValue(prompt: str) -> str:
    return input(prompt).strip();

def resolveKeyAlgorithm(keyalg: str | None) -> str:    
    alg = keyalg.strip() if keyalg is not None else requireValue("Enter key algorithm: ");

    while (alg.upper() != "RSA"):
        print("Error: Value not accepted, accepted values (RSA).");

        alg = requireValue("Enter key algorithm: ");

    return alg.upper();

def isKeySizeCorrect(keysize: int) -> bool:
    return True if keysize == 2048 or keysize == 3072 or keysize == 7680 or keysize == 15360 else False;

def resolveKeySize(ks: int | None) -> int:
    keySize = ks if ks is not None else int(requireValue("Enter key size: "));

    while (not isKeySizeCorrect(keySize)):
        print("Error: Value not accepted, accepted values (2048, 3072, 7680, 15360).");
    
        keySize = int(requireValue("Enter key size: "));
    
    return keySize;

def parse_dname(dname: str) -> dict[str, str]:
    parts = [part.strip() for part in dname.split(",") if part.strip()]
    values: dict[str, str] = {}
    for part in parts:
        key, separator, value = part.partition("=")
        field = key.strip().upper()
        normalized = value.strip()
        if not separator or field not in DN_FIELDS or not normalized:
            raise ValueError("-dname debe usar el formato CN=..., OU=..., O=..., L=..., ST=..., C=...")
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
    if storepass is not None:
        password = storepass
    else:
        password = read_password("Enter keystore password: ")
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
            password = read_store_password(path, storepass)
            return password, {}
        last_error: ValueError | None = None
        for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
            try:
                password = read_store_password(path, None)
                return password, {}
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
    last_error: ValueError | None = None
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


def handleGenkeypair(
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
        );

        save_keystore(path, password, entries);

    except getpass.GetPassWarning:
        print("Error: no hay un terminal disponible para ocultar la contrasena.", file=sys.stderr);

        return 1;
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr);

        return 1;
    except (EOFError, KeyboardInterrupt):
        print("\nError: operacion cancelada; no se ha guardado la entrada.", file=sys.stderr);

        return 1;

    print(f"Exito: par {algorithm} de {resolved_keysize} bits guardado con alias '{alias}' en '{path}'.");

    return 0;

def handle_certreq() -> int:
    """Punto de entrada para la futura generacion de solicitudes CSR."""
    print("Comando --certreq seleccionado.")
    print("La generacion de solicitudes CSR se implementara en el siguiente modulo.")
    return 0;


def printGenkeypairHelp() -> None:
    print(
        "usage: mykeytool.py -genkeypair -keyalg KEYALG [-keystore KEYSTORE] "
        "[-alias ALIAS] [-dname DNAME] [-storepass STOREPASS] [-keypass KEYPASS] "
        "[-keysize KEYSIZE]",
        file=sys.stderr,
    );

    print("", file=sys.stderr);
    print("Required for -genkeypair:", file=sys.stderr);
    print("  -keyalg KEYALG    algoritmo de la clave (solo RSA)", file=sys.stderr);
    print("", file=sys.stderr);
    print("Optional for -genkeypair:", file=sys.stderr);
    print("  -keystore KEYSTORE", file=sys.stderr);
    print("  -alias ALIAS", file=sys.stderr);
    print("  -dname DNAME", file=sys.stderr);
    print("  -storepass STOREPASS", file=sys.stderr);
    print("  -keypass KEYPASS", file=sys.stderr);
    print("  -keysize KEYSIZE", file=sys.stderr);

def printMainHelp() -> None:
    print("usage: mykeytool.py [command]", file=sys.stdout)
    print("", file=sys.stdout)
    print("Comandos disponibles:", file=sys.stdout)
    print("  -genkeypair, --genkeypair    genera un par de claves", file=sys.stdout)
    print("  -certreq, --certreq          genera una solicitud CSR", file=sys.stdout)
    print("", file=sys.stdout)
    print("Usa 'mykeytool.py -genkeypair -h' para ver sus argumentos.", file=sys.stdout)

#Generate the avaliable command list
def buildParser() -> argparse.ArgumentParser:
    """Construye y devuelve el analizador de argumentos de la aplicacion."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description=(
            "Simulador en Python de las funciones esenciales de Java Keytool. "
            "Selecciona una operacion para gestionar el KeyStore."
        ),
        epilog="Ejemplo: python3 mykeytool.py --genkeypair",
    );

    commands = parser.add_mutually_exclusive_group(required=False);
    commands.add_argument(
        "-genkeypair",
        "--genkeypair",
        action="store_const",
        const="genkeypair",
        dest="command",
        help="genera un par de claves RSA y lo guarda en el KeyStore",
    );

    commands.add_argument(
        "-certreq",
        "--certreq",
        action="store_const",
        const="certreq",
        dest="command",
        help="genera una solicitud de firma de certificado (CSR)",
    );

    parser.add_argument(
        "-keystore",
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    );

    parser.add_argument("-alias", help="alias de la entrada a generar")
    parser.add_argument("-dname", help="DN en formato CN=..., OU=..., O=..., L=..., ST=..., C=...")
    parser.add_argument("-storepass", help="contrasena del KeyStore")
    parser.add_argument("-keypass", help="contrasena de la clave generada")
    parser.add_argument("-keyalg", help="algoritmo de la clave (solo RSA)")
    parser.add_argument("-keysize", type=int, help="tamano de clave en bits")

    return parser

def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    if not isCryptoLibraryAvaliable():
        raise ModuleNotFoundError("No se pudo importar 'cryptography' con este interprete de Python.") from CRYPTO_IMPORT_ERROR;

    arg_list = list(argv if argv is not None else sys.argv[1:]);

    parser = buildParser();

    if any(flag in arg_list for flag in ("-genkeypair", "--genkeypair")) and any(
        flag in arg_list for flag in ("-h", "--help")
        ):

        printGenkeypairHelp();

        return 0;

    args = parser.parse_args(arg_list)

    if args.command is None and not any(flag in arg_list for flag in ("-h", "--help")):
        printMainHelp();

        return 0;
    elif args.command is None:
        printMainHelp();

        return 0;

    handlers: dict[str, CommandHandler] = {
        "genkeypair": lambda: handleGenkeypair(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            dname=args.dname,
            keyalg=args.keyalg,
            keysize=args.keysize,
        ),

        "certreq": handle_certreq,
    };

    return handlers[args.command]();

if __name__ == "__main__":
    main();