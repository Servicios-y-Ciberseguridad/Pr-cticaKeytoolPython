"""Exportacion del certificado publico asociado a un alias."""

from __future__ import annotations

import getpass
import re
import sys
from pathlib import Path

from .certreq import open_existing_keystore
from .errors import AliasNotFoundError, KeytoolError
from .genkeypair import resolve_alias
from .keystore import DEFAULT_KEYSTORE, write_bytes_atomic
from .listing import load_entry_certificate

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
except ModuleNotFoundError:
    UnsupportedAlgorithm = None
    serialization = None


def resolve_output_path(output: Path | None, alias: str) -> Path:
    """Usa el archivo indicado o genera un nombre seguro a partir del alias."""
    if output is not None:
        return output
    safe_alias = re.sub(r"[^A-Za-z0-9._-]+", "_", alias).strip("._")
    return Path(f"{safe_alias or 'certificate'}.cer")


def validate_output_path(output: Path, keystore: Path) -> None:
    if output.resolve() == keystore.resolve() or (
        output.exists() and keystore.exists() and output.samefile(keystore)
    ):
        raise ValueError("El certificado no puede sobrescribir el KeyStore.")


def handle_exportcert(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
    output: Path | None = None,
    rfc: bool = False,
) -> int:
    """Exporta solo el certificado publico de un alias, sin acceder a su clave."""
    try:
        _, entries = open_existing_keystore(path, storepass)
        resolved_alias = resolve_alias(alias)
        try:
            entry = entries[resolved_alias]
        except KeyError as exc:
            raise AliasNotFoundError(
                f"No existe el alias '{resolved_alias}' en el KeyStore."
            ) from exc

        certificate = load_entry_certificate(entry)
        if certificate is None:
            raise ValueError(
                f"El alias '{resolved_alias}' no tiene certificado X.509 para exportar."
            )
        output_path = resolve_output_path(output, resolved_alias)
        validate_output_path(output_path, path)
        encoding = serialization.Encoding.PEM if rfc else serialization.Encoding.DER
        write_bytes_atomic(output_path, certificate.public_bytes(encoding))
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except (KeytoolError, ValueError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("Error: no se pudo leer o escribir el archivo solicitado.", file=sys.stderr)
        return 1
    except UnsupportedAlgorithm:
        print("Error: algoritmo criptografico no admitido.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nError: operacion cancelada; no se exporto el certificado.", file=sys.stderr)
        return 1

    print(
        f"Exito: certificado X.509 del alias '{resolved_alias}' guardado en "
        f"'{output_path}' en formato {'PEM' if rfc else 'DER'}."
    )
    return 0
