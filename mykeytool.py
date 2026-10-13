"""Interfaz de linea de comandos para el simulador de Java Keytool."""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypedDict

from certreq import handle_certreq
from genkeypair import (
    MAX_ALIAS_ATTEMPTS,
    MAX_PASSWORD_ATTEMPTS,
    handle_genkeypair,
    open_keystore_with_password,
    parse_dname,
    read_dname_interactively,
    read_password,
    read_required,
    read_store_password,
    resolve_alias,
    resolve_dname,
    resolve_key_algorithm,
    resolve_key_password,
    resolve_key_size,
    resolve_unique_alias,
    validate_country,
)
from keystore import (
    AES_GCM_TAG_SIZE,
    CRYPTO_IMPORT_ERROR,
    DEFAULT_KEYSTORE,
    DN_FIELDS,
    STORE_HEADER,
    STORE_NONCE_SIZE,
    STORE_SALT_SIZE,
    UNKNOWN_DN_VALUE,
    KeyEntry,
    derive_store_key,
    ensure_crypto_available,
    load_keystore,
    load_keystore_entry,
    save_keystore,
)

CommandHandler = Callable[[], int]


class GenKeyPairOptions(TypedDict, total=False):
    alias: str
    storepass: str
    keypass: str
    dname: str
    keyalg: str
    keysize: int


def handoff_to_project_venv(argv: Sequence[str] | None) -> int | None:
    if CRYPTO_IMPORT_ERROR is None:
        return None
    venv_python = Path(__file__).with_name(".venv") / "Scripts" / "python.exe"
    current = Path(sys.executable).resolve()
    if not venv_python.exists() or current == venv_python.resolve():
        return None
    command = [str(venv_python), str(Path(__file__).resolve()), *(argv or sys.argv[1:])]
    return subprocess.run(command, check=False).returncode


def print_genkeypair_help() -> None:
    print(
        "usage: mykeytool.py -genkeypair -keyalg KEYALG [-keystore KEYSTORE] "
        "[-alias ALIAS] [-dname DNAME] [-storepass STOREPASS] [-keypass KEYPASS] "
        "[-keysize KEYSIZE]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Required for -genkeypair:", file=sys.stderr)
    print("  -keyalg KEYALG    algoritmo de la clave (solo RSA)", file=sys.stderr)
    print("", file=sys.stderr)
    print("Optional for -genkeypair:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -alias ALIAS", file=sys.stderr)
    print("  -dname DNAME", file=sys.stderr)
    print("  -storepass STOREPASS", file=sys.stderr)
    print("  -keypass KEYPASS", file=sys.stderr)
    print("  -keysize KEYSIZE", file=sys.stderr)


def print_main_help() -> None:
    print("usage: mykeytool.py [command]", file=sys.stdout)
    print("", file=sys.stdout)
    print("Comandos disponibles:", file=sys.stdout)
    print("  -genkeypair, --genkeypair    genera un par de claves", file=sys.stdout)
    print("  -certreq, --certreq          genera una solicitud CSR", file=sys.stdout)
    print("", file=sys.stdout)
    print("Usa 'mykeytool.py -genkeypair -h' para ver sus argumentos.", file=sys.stdout)


def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el analizador de argumentos de la aplicacion."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description=(
            "Simulador en Python de las funciones esenciales de Java Keytool. "
            "Selecciona una operacion para gestionar el KeyStore."
        ),
        epilog="Ejemplo: python3 mykeytool.py --genkeypair",
    )
    commands = parser.add_mutually_exclusive_group(required=False)
    commands.add_argument(
        "-genkeypair",
        "--genkeypair",
        action="store_const",
        const="genkeypair",
        dest="command",
        help="genera un par de claves RSA y lo guarda en el KeyStore",
    )
    commands.add_argument(
        "-certreq",
        "--certreq",
        action="store_const",
        const="certreq",
        dest="command",
        help="genera una solicitud de firma de certificado (CSR)",
    )
    parser.add_argument(
        "-keystore",
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    )
    parser.add_argument("-alias", help="alias de la entrada a generar")
    parser.add_argument(
        "-dname", help="DN en formato CN=..., OU=..., O=..., L=..., ST=..., C=..."
    )
    parser.add_argument("-storepass", help="contrasena del KeyStore")
    parser.add_argument("-keypass", help="contrasena de la clave generada")
    parser.add_argument("-keyalg", help="algoritmo de la clave (solo RSA)")
    parser.add_argument("-keysize", type=int, help="tamano de clave en bits")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    handoff_result = handoff_to_project_venv(argv)
    if handoff_result is not None:
        return handoff_result
    arg_list = list(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    if any(flag in arg_list for flag in ("-genkeypair", "--genkeypair")) and any(
        flag in arg_list for flag in ("-h", "--help")
    ):
        print_genkeypair_help()
        return 0
    args = parser.parse_args(arg_list)
    if args.command is None:
        print_main_help()
        return 0

    handlers: dict[str, CommandHandler] = {
        "genkeypair": lambda: handle_genkeypair(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            dname=args.dname,
            keyalg=args.keyalg,
            keysize=args.keysize,
        ),
        "certreq": handle_certreq,
    }
    return handlers[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())