"""Cambio de alias de una entrada existente del KeyStore."""
from __future__ import annotations;

import getpass;
import sys;
from pathlib import Path;

from .errors import KeytoolError;
from .genkeypair import read_store_password;
from .keystore import (
    DEFAULT_KEYSTORE,
    change_keystore_alias,
);

def resolve_alias_argument(alias: str | None, prompt: str, label: str) -> str:
    value = alias if alias is not None else input(prompt);
    resolved = value.strip();

    if not resolved:
        raise ValueError(f"El {label} no puede estar vacio.");

    return resolved;

def handle_changealias(path: Path = DEFAULT_KEYSTORE, *, alias: str | None = None, destalias: str | None = None, storepass: str | None = None,) -> int:
    """Renombra una entrada existente y guarda el KeyStore de forma atómica."""
    try:
        password = read_store_password(path, storepass);
        
        source_alias = resolve_alias_argument(
            alias, "Enter existing key alias: ", "alias actual"
        )
        destination_alias = resolve_alias_argument(
            destalias, "Enter destination key alias: ", "alias de destino"
        )
        change_keystore_alias(path, password, source_alias, destination_alias)
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except (KeytoolError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print(
            "\nError: operacion cancelada; no se ha cambiado el alias.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Exito: alias '{source_alias}' cambiado a '{destination_alias}' "
        f"en '{path}'."
    )
    return 0