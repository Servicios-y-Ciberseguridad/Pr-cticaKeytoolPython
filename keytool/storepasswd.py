"""Cambio de la contrasena que protege el KeyStore completo."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from .errors import KeytoolError
from .genkeypair import read_new_store_password, read_password
from .keystore import DEFAULT_KEYSTORE, load_keystore, save_keystore


def handle_storepasswd(
    path: Path = DEFAULT_KEYSTORE,
    *,
    storepass: str | None = None,
    new_password: str | None = None,
) -> int:
    """Autentica una sola vez y vuelve a cifrar sin alterar las entradas."""
    try:
        password = (
            storepass if storepass is not None
            else read_password("Enter keystore password: ")
        )
        if not password:
            raise ValueError("La contrasena no puede estar vacia.")
        entries = load_keystore(path, password)
        replacement = read_new_store_password(new_password, current_password=password)
        save_keystore(path, replacement, entries)
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except OSError:
        print("Error: no se pudo leer o guardar el KeyStore.", file=sys.stderr)
        return 1
    except (KeytoolError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print(
            "\nError: operacion cancelada; no se ha cambiado la contrasena.",
            file=sys.stderr,
        )
        return 1

    print("Exito: contrasena del KeyStore cambiada.")
    return 0
