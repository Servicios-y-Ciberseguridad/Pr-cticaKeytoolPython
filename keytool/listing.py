"""Consulta autenticada de los datos publicos del KeyStore."""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path

from .certreq import open_existing_keystore
from .errors import AliasNotFoundError, InvalidKeystoreError, KeytoolError
from .keystore import DEFAULT_KEYSTORE, DN_FIELDS, KeyEntry, ensure_crypto_available

try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ModuleNotFoundError:
    x509 = None
    UnsupportedAlgorithm = None
    hashes = None
    serialization = None
    rsa = None


def load_entry_certificate(entry: KeyEntry) -> x509.Certificate | None:
    certificate_pem = entry.get("certificate")
    if certificate_pem is None:
        return None
    if not isinstance(certificate_pem, str):
        raise InvalidKeystoreError("Certificado del KeyStore no valido.")
    try:
        return x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidKeystoreError("Certificado del KeyStore no valido.") from exc


def public_entry_details(
    entry: KeyEntry, certificate: x509.Certificate | None
) -> list[str]:
    """Formatea solo metadatos publicos, nunca el contenido de la entrada."""
    try:
        public_key = serialization.load_pem_public_key(
            entry["public_key"].encode("ascii")
        )
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidKeystoreError("Clave publica del KeyStore no valida.") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise InvalidKeystoreError("Algoritmo de clave publica no admitido; se requiere RSA.")

    dn = ", ".join(f"{field}={entry['dn'][field]}" for field in DN_FIELDS)
    lines = [
        f"  DN: {json.dumps(dn, ensure_ascii=True)}",
        "  Algoritmo: RSA",
        f"  Tamano de clave publica: {public_key.key_size} bits",
    ]
    if certificate is None:
        lines.append("  Certificado: no disponible")
        return lines
    lines.extend([
        f"  Sujeto: {json.dumps(certificate.subject.rfc4514_string(), ensure_ascii=True)}",
        f"  Emisor: {json.dumps(certificate.issuer.rfc4514_string(), ensure_ascii=True)}",
        f"  Numero de serie: {certificate.serial_number:X}",
        f"  Valido desde: {certificate.not_valid_before_utc.isoformat()}",
        f"  Valido hasta: {certificate.not_valid_after_utc.isoformat()}",
        f"  Algoritmo de firma (OID): {certificate.signature_algorithm_oid.dotted_string}",
    ])
    return lines


def handle_list(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
    verbose: bool = False,
) -> int:
    """Lista entradas sin descifrar sus claves privadas ni modificar el archivo."""
    try:
        ensure_crypto_available()
        _, entries = open_existing_keystore(path, storepass)
        if alias is not None:
            resolved_alias = alias.strip()
            if not resolved_alias:
                raise ValueError("El alias no puede estar vacio.")
            if resolved_alias not in entries:
                raise AliasNotFoundError(
                    f"No existe el alias '{resolved_alias}' en el KeyStore."
                )
            aliases = [resolved_alias]
        else:
            aliases = sorted(entries)

        count = len(aliases)
        noun = "entry" if count == 1 else "entries"
        lines = [
            "Keystore type: MYKEYSTORE (version 1)",
            "Keystore provider: Python cryptography",
            "",
            f"Your keystore contains {count} {noun}",
        ]
        for name in aliases:
            entry = entries[name]
            certificate = load_entry_certificate(entry)
            display_name = json.dumps(name, ensure_ascii=True)[1:-1]
            lines.extend([
                "",
                f"{display_name}, creation date unavailable, PrivateKeyEntry,",
            ])
            if certificate is None:
                fingerprint = "unavailable (no certificate)"
            else:
                fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":").upper()
            lines.append(f"Certificate fingerprint (SHA-256): {fingerprint}")
            if verbose:
                lines.extend(public_entry_details(entry, certificate))
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
        print("\nError: operacion cancelada; no se listo el KeyStore.", file=sys.stderr)
        return 1

    print("\n".join(lines))
    return 0
