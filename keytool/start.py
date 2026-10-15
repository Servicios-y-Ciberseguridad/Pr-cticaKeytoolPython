"""Interfaz de linea de comandos para el simulador de Java Keytool."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path

# Fachada del programa: conserva accesibles las funciones del prototipo TXT,
# pero cada responsabilidad se implementa en su modulo correspondiente.
from .changealias import handle_changealias
from .certreq import handle_certreq
from .listing import handle_list
from .genkeypair import (
    MAX_ALIAS_ATTEMPTS,
    MAX_PASSWORD_ATTEMPTS,
    SUPPORTED_KEY_SIZES,
    handle_genkeypair,
    is_key_size_supported,
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
from .keystore import (
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

def is_crypto_library_available() -> bool:
    """Indica si la dependencia cryptography esta disponible."""
    return CRYPTO_IMPORT_ERROR is None;

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
    allowed_sizes = ", ".join(map(str, SUPPORTED_KEY_SIZES))
    print(f"  -keysize KEYSIZE  valores admitidos: {allowed_sizes}", file=sys.stderr)

def print_certreq_help() -> None:
    print(
        "usage: mykeytool.py -certreq [-keystore KEYSTORE] [-alias ALIAS] "
        "[-storepass STOREPASS] [-keypass KEYPASS] [-file FILE]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Optional for -certreq:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -alias ALIAS", file=sys.stderr)
    print("  -storepass STOREPASS", file=sys.stderr)
    print("  -keypass KEYPASS", file=sys.stderr)
    print("  -file FILE        archivo .csr o .pem (por defecto: <alias>.csr)", file=sys.stderr)

def print_changealias_help() -> None:
    print(
        "usage: mykeytool.py -changealias [-keystore KEYSTORE] "
        "[-storepass STOREPASS] [-alias ALIAS] [-destalias DESTALIAS]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Optional for -changealias:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -storepass STOREPASS", file=sys.stderr)
    print("  -alias ALIAS        alias actual", file=sys.stderr)
    print("  -destalias DESTALIAS alias nuevo", file=sys.stderr)


def print_list_help() -> None:
    print(
        "usage: mykeytool.py -list [-keystore KEYSTORE] [-storepass STOREPASS] "
        "[-alias ALIAS] [-v | --verbose]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Optional for -list / --list:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -storepass STOREPASS  se solicita sin eco si se omite", file=sys.stderr)
    print("  -alias ALIAS          limita la consulta a una entrada", file=sys.stderr)
    print("  -v, --verbose         muestra detalles publicos", file=sys.stderr)


def print_main_help() -> None:
    print("usage: mykeytool.py [command]", file=sys.stdout)
    print("", file=sys.stdout)
    print("Comandos disponibles:", file=sys.stdout)
    print("  -genkeypair, --genkeypair    genera un par de claves", file=sys.stdout)
    print("  -certreq, --certreq          genera una solicitud CSR", file=sys.stdout)
    print("  -changealias, --changealias  cambia el alias de una entrada", file=sys.stdout)
    print("  -list, --list                lista las entradas del KeyStore", file=sys.stdout)
    print("", file=sys.stdout)
    print(
        "Usa 'mykeytool.py <comando> -h' para ver sus argumentos.",
        file=sys.stdout,
    )

def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el analizador de argumentos de la aplicacion."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description=(
            "Simulador en Python de las funciones esenciales de Java Keytool."
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

    commands.add_argument(
        "-changealias",
        "--changealias",
        action="store_const",
        const="changealias",
        dest="command",
        help="cambia el alias de una entrada del KeyStore",
    );

    commands.add_argument(
        "-list",
        "--list",
        action="store_const",
        const="list",
        dest="command",
        help="lista las entradas del KeyStore tras autenticarlo",
    )

    parser.add_argument(
        "-keystore",
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    )
    parser.add_argument("-alias", help="alias de la entrada")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="detalles publicos para -list"
    )
    parser.add_argument("-destalias", help="alias nuevo para -changealias")
    parser.add_argument(
        "-dname", help="DN en formato CN=..., OU=..., O=..., L=..., ST=..., C=..."
    )
    parser.add_argument("-storepass", help="contrasena del KeyStore")
    parser.add_argument("-keypass", help="contrasena de la clave del alias")
    parser.add_argument("-keyalg", help="algoritmo de la clave (solo RSA)")
    parser.add_argument("-keysize", type=int, help="tamano de clave en bits")
    parser.add_argument(
        "-file",
        "--file",
        type=Path,
        help="archivo .csr o .pem de salida para -certreq",
    );

    return parser;

def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    if not is_crypto_library_available():
        return -1;

    arg_list = list(argv if argv is not None else sys.argv[1:])
    if any(flag in arg_list for flag in ("-h", "--help")):
        if any(flag in arg_list for flag in ("-genkeypair", "--genkeypair")):
            print_genkeypair_help()
            return 0
        if any(flag in arg_list for flag in ("-certreq", "--certreq")):
            print_certreq_help()
            return 0
        if any(flag in arg_list for flag in ("-changealias", "--changealias")):
            print_changealias_help()
            return 0
        if any(flag in arg_list for flag in ("-list", "--list")):
            print_list_help()
            return 0
    args = build_parser().parse_args(arg_list)

    if args.command is None:
        print_main_help();

        return 0;
    
    if args.command == "genkeypair":
        return handle_genkeypair(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            dname=args.dname,
            keyalg=args.keyalg,
            keysize=args.keysize,
        );
    elif args.command == "certreq":
        return handle_certreq(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            output=args.file,
        );

    if args.command == "list":
        return handle_list(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            verbose=args.verbose,
        )

    return handle_changealias(
        args.keystore,
        alias=args.alias,
        destalias=args.destalias,
        storepass=args.storepass,
    );