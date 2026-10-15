"""Eliminacion de una entrada existente del KeyStore."""
from __future__ import annotations

import getpass
import sys
from pathlib import Path

from .certreq import resolve_store_password
from .errors import KeytoolError, KeystoreNotFoundError
from .keystore import DEFAULT_KEYSTORE, delete_keystore_entry

def resolve_delete_alias(alias: str | None) -> str:
    value = alias if alias is not None else input("Enter key alias: ");
    resolved = value.strip();

    if not resolved:
        raise ValueError("El alias no puede estar vacio.");

    return resolved;

def handle_deletekey(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
) -> int:
    """Elimina un alias y guarda el KeyStore de forma atomica."""
    try:
        if not path.exists():
            raise KeystoreNotFoundError(f"No existe el KeyStore: '{path}'.");
    
        password = resolve_store_password(storepass);
        resolved_alias = resolve_delete_alias(alias);

        delete_keystore_entry(path, password, resolved_alias);
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
            "\nError: operacion cancelada; no se ha eliminado la entrada.",
            file=sys.stderr,
        );

        return 1;

    print(f"Exito: alias '{resolved_alias}' eliminado del KeyStore '{path}'.");

    return 0;