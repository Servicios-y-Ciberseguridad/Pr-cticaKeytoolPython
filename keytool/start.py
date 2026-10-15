"""Interfaz de linea de comandos para el simulador de Java Keytool."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

# Fachada del programa: conserva accesibles las funciones del prototipo TXT,
# pero cada responsabilidad se implementa en su modulo correspondiente.
from .changealias import handle_changealias;
from .certreq import handle_certreq;
from .exportcert import handle_exportcert;
from .listing import handle_list;
from .storepasswd import handle_storepasswd;
from .gencert import DEFAULT_VALIDITY_DAYS, handle_gencert;
from .genkeypair import (SUPPORTED_KEY_SIZES, handle_genkeypair);

from .keystore import (CRYPTO_IMPORT_ERROR, DEFAULT_KEYSTORE);

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

def print_exportcert_help() -> None:
    print(
        "usage: mykeytool.py -exportcert [-keystore KEYSTORE] [-storepass STOREPASS] "
        "[-alias ALIAS] [-file FILE] [-rfc]",
        file=sys.stderr,
    )
    print("  -keystore KEYSTORE  archivo del almacen", file=sys.stderr)
    print("  -storepass STOREPASS se solicita sin eco si se omite", file=sys.stderr)
    print("  -alias ALIAS        alias del certificado (se solicita si se omite)", file=sys.stderr)
    print("  -file FILE          salida (por defecto: <alias>.cer)", file=sys.stderr)
    print("  -rfc                salida PEM/Base64; por defecto DER binario", file=sys.stderr)

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
    print("  -exportcert, --exportcert    exporta un certificado X.509", file=sys.stdout)
    print("  -gencert, --gencert          firma un certificado desde un CSR", file=sys.stdout)
    print("  -changealias, --changealias  cambia el alias de una entrada", file=sys.stdout)
    print("  -list, --list                lista las entradas del KeyStore", file=sys.stdout)
    print("  -storepasswd, --storepasswd  cambia la contrasena del KeyStore", file=sys.stdout)
    print("", file=sys.stdout)
    print(
        "Usa 'mykeytool.py <comando> -h' para ver sus argumentos.",
        file=sys.stdout,
    )

def print_storepasswd_help() -> None:
    print(
        "usage: mykeytool.py -storepasswd [-keystore KEYSTORE] "
        "[-storepass STOREPASS] [-new NEW_PASSWORD]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Optional for -storepasswd / --storepasswd:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -storepass STOREPASS  contrasena actual; se solicita sin eco si se omite", file=sys.stderr)
    print("  -new NEW_PASSWORD     al menos 8 caracteres; se solicita dos veces sin eco si se omite", file=sys.stderr)

def print_gencert_help() -> None:
    print(
        "usage: mykeytool.py -gencert -infile REQUEST -outfile CERTIFICATE "
        "[-keystore KEYSTORE] [-alias ALIAS] [-storepass STOREPASS] "
        "[-keypass KEYPASS] [-rfc] [-validity DAYS]",
        file=sys.stderr,
    )
    print("  -infile REQUEST       CSR PKCS#10 en PEM o DER (obligatorio)", file=sys.stderr)
    print("  -outfile CERTIFICATE  archivo de salida (obligatorio)", file=sys.stderr)
    print("  -keystore KEYSTORE    almacen del emisor", file=sys.stderr)
    print("  -alias ALIAS          alias firmante (se solicita si se omite)", file=sys.stderr)
    print("  -storepass STOREPASS  se solicita sin eco si se omite", file=sys.stderr)
    print("  -keypass KEYPASS      se solicita sin eco si se omite", file=sys.stderr)
    print("  -rfc                  salida PEM; por defecto DER", file=sys.stderr)
    print(
        f"  -validity DAYS        dias positivos; por defecto {DEFAULT_VALIDITY_DAYS}",
        file=sys.stderr,
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
    );

    commands.add_argument(
        "-exportcert",
        "--exportcert",
        action="store_const",
        const="exportcert",
        dest="command",
        help="exporta el certificado X.509 publico de un alias",
    );

    commands.add_argument(
        "-storepasswd",
        "--storepasswd",
        action="store_const",
        const="storepasswd",
        dest="command",
        help="cambia la contrasena que protege el KeyStore",
    );

    commands.add_argument(
        "-gencert", "--gencert",
        action="store_const",
        const="gencert",
        dest="command",
        help="genera un certificado X.509 a partir de un CSR",
    );

    parser.add_argument(
        "-keystore",
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    );
    parser.add_argument("-alias", help="alias de la entrada");
    parser.add_argument("-v", "--verbose", action="store_true", help="detalles publicos para -list");
    parser.add_argument("-destalias", help="alias nuevo para -changealias");
    parser.add_argument("-dname", help="DN en formato CN=..., OU=..., O=..., L=..., ST=..., C=...");
    parser.add_argument("-storepass", help="contrasena del KeyStore");
    parser.add_argument("-new", dest="new_password", help="contrasena nueva del KeyStore");
    parser.add_argument("-keypass", help="contrasena de la clave del alias");
    parser.add_argument("-keyalg", help="algoritmo de la clave (solo RSA)");
    parser.add_argument("-keysize", type=int, help="tamano de clave en bits");
    parser.add_argument("-infile", type=Path, help="CSR PEM o DER para -gencert");
    parser.add_argument("-outfile", type=Path, help="certificado de salida para -gencert");
    parser.add_argument("-rfc", action="store_true", help="exporta el certificado en PEM");
    parser.add_argument(
        "-validity", type=int, default=DEFAULT_VALIDITY_DAYS,
        metavar="DAYS", help="dias de validez para -gencert (por defecto: 90)",
    );
    parser.add_argument(
        "-file",
        "--file",
        type=Path,
        help="archivo de salida para -certreq o -exportcert",
    );

    return parser;

def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    if not is_crypto_library_available():
        return -1;

    arg_list = list(argv if argv is not None else sys.argv[1:]);

    if any(flag in arg_list for flag in ("-h", "--help")):
        if any(flag in arg_list for flag in ("-genkeypair", "--genkeypair")):
            print_genkeypair_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-certreq", "--certreq")):
            print_certreq_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-exportcert", "--exportcert")):
            print_exportcert_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-gencert", "--gencert")):
            print_gencert_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-changealias", "--changealias")):
            print_changealias_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-list", "--list")):
            print_list_help();

            return 0;
    
        if any(flag in arg_list for flag in ("-storepasswd", "--storepasswd")):
            print_storepasswd_help();

            return 0;

    args = build_parser().parse_args(arg_list);

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

    if args.command == "exportcert":
        return handle_exportcert(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            output=args.file,
            rfc=args.rfc,
        );

    if args.command == "gencert":
        return handle_gencert(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            infile=args.infile,
            outfile=args.outfile,
            rfc=args.rfc,
            validity=args.validity,
        );

    if args.command == "storepasswd":
        return handle_storepasswd(
            args.keystore,
            storepass=args.storepass,
            new_password=args.new_password,
        );

    if args.command == "list":
        return handle_list(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            verbose=args.verbose,
        );

    return handle_changealias(
        args.keystore,
        alias=args.alias,
        destalias=args.destalias,
        storepass=args.storepass,
    );