"""Emision de certificados X.509 a partir de solicitudes PKCS#10."""

from __future__ import annotations

import getpass
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .certreq import (
    ensure_key_pair_matches,
    load_private_key,
    open_existing_keystore,
)
from .errors import AliasNotFoundError, KeytoolError
from .genkeypair import build_subject, resolve_alias
from .keystore import DEFAULT_KEYSTORE, ensure_crypto_available, write_bytes_atomic
from .listing import load_entry_certificate

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

DEFAULT_VALIDITY_DAYS = 90


def load_csr(path: Path) -> x509.CertificateSigningRequest:
    data = path.read_bytes()
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            csr = x509.load_pem_x509_csr(data)
        else:
            csr = x509.load_der_x509_csr(data)
        if not csr.is_signature_valid:
            raise ValueError("Firma del CSR no valida; la solicitud fue alterada.")
        # Fuerza la validacion de los campos y extensiones antes de firmar.
        csr.subject
        csr.public_key()
        csr.extensions
    except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension, x509.InvalidVersion) as exc:
        raise ValueError("CSR no valido o firma incorrecta.") from exc
    return csr


def issuer_can_certify(certificate: x509.Certificate | None) -> bool:
    if certificate is None:
        return False
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    if not constraints.value.ca:
        return False
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return True
    return usage.value.key_cert_sign


def validate_output_path(output: Path, keystore: Path, request: Path) -> None:
    for protected in (keystore, request):
        if output.resolve() == protected.resolve() or (
            output.exists() and protected.exists() and output.samefile(protected)
        ):
            raise ValueError(
                "El certificado no puede sobrescribir el KeyStore ni el CSR de entrada."
            )


def handle_gencert(
    path: Path = DEFAULT_KEYSTORE,
    *,
    alias: str | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    infile: Path | None = None,
    outfile: Path | None = None,
    rfc: bool = False,
    validity: int = DEFAULT_VALIDITY_DAYS,
) -> int:
    """Firma un certificado de entidad final y exporta solo datos publicos."""
    try:
        ensure_crypto_available()
        if infile is None or outfile is None:
            raise ValueError("-gencert requiere -infile REQUEST y -outfile CERTIFICATE.")
        if validity <= 0:
            raise ValueError("-validity debe ser un numero positivo de dias.")
        start = datetime.now(timezone.utc).replace(microsecond=0)
        try:
            end = start + timedelta(days=validity)
        except OverflowError as exc:
            raise ValueError("-validity supera el intervalo de fechas admitido.") from exc
        validate_output_path(outfile, path, infile)
        csr = load_csr(infile)
        store_password, entries = open_existing_keystore(path, storepass)
        resolved_alias = resolve_alias(alias)
        try:
            entry = entries[resolved_alias]
        except KeyError as exc:
            raise AliasNotFoundError(
                f"No existe el alias '{resolved_alias}' en el KeyStore."
            ) from exc;
        
        private_key = load_private_key(entry, resolved_alias, store_password, keypass)
        ensure_key_pair_matches(private_key, entry, resolved_alias)
        issuer_certificate = load_entry_certificate(entry)
        issuer_public_key = private_key.public_key()
        if issuer_certificate is not None:
            if issuer_certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != issuer_public_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                raise ValueError("El certificado del emisor no coincide con su clave.")
            issuer = issuer_certificate.subject
        else:
            issuer = build_subject(entry["dn"])

        public_key = csr.public_key()
        can_certify = issuer_can_certify(issuer_certificate)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        encoding = serialization.Encoding.PEM if rfc else serialization.Encoding.DER
        write_bytes_atomic(outfile, certificate.public_bytes(encoding))
    except getpass.GetPassWarning:
        print(
            "Error: no hay un terminal disponible para ocultar la contrasena.",
            file=sys.stderr,
        )
        return 1
    except OSError:
        print("Error: no se pudo leer o escribir el archivo solicitado.", file=sys.stderr)
        return 1
    except UnsupportedAlgorithm:
        print("Error: algoritmo criptografico no admitido.", file=sys.stderr)
        return 1
    except x509.DuplicateExtension:
        print("Error: extensiones X.509 duplicadas.", file=sys.stderr)
        return 1
    except x509.InvalidVersion:
        print("Error: version X.509 no valida.", file=sys.stderr)
        return 1
    except (KeytoolError, ValueError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nError: operacion cancelada; no se genero el certificado.", file=sys.stderr)
        return 1

    if not can_certify:
        print(
            "Aviso: el emisor no es una CA con permiso de firma de certificados; "
            "la firma es verificable, pero no establece una cadena CA valida.",
            file=sys.stderr,
        )
    print(f"Exito: certificado X.509 guardado en formato {'PEM' if rfc else 'DER'}.")
    return 0
