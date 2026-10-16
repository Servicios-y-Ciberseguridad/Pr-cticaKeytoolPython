import contextlib
import copy
import getpass
import io
import os
import shutil
import subprocess
import tempfile
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

import mykeytool
from keytool.certreq import encode_keytool_pem
from keytool.gencert import DEFAULT_VALIDITY_DAYS
from keytool.genkeypair import build_subject
from keytool.keystore import DN_FIELDS, KeyEntry, save_keystore


class GenCertTests(unittest.TestCase):
    store_password = "gencert-store-password"
    key_password = "gencert-private-key-password"

    @classmethod
    def setUpClass(cls):
        cls.issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.request_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Certificate issuer"),
        ])
        cls.request_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Requested subject"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSR organization"),
        ])
        cls.csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(cls.request_name)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
            .sign(cls.request_key, hashes.SHA256())
        )
        now = datetime.now(timezone.utc)
        cls.issuer_certificate = (
            x509.CertificateBuilder()
            .subject_name(cls.issuer_name)
            .issuer_name(cls.issuer_name)
            .public_key(cls.issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.issuer_key, hashes.SHA256())
        )
        cls.entry = KeyEntry(
            private_key=cls.issuer_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(cls.key_password.encode()),
            ).decode("ascii"),
            public_key=cls.issuer_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii"),
            dn=dict(zip(DN_FIELDS, ["Legacy DN", "TI", "Empresa", "Madrid", "Madrid", "ES"])),
            certificate=cls.issuer_certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii"),
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / "store.myks"
        self.request = self.directory / "input.csr"
        self.output = self.directory / "certificate.bin"
        self.request.write_bytes(self.csr.public_bytes(serialization.Encoding.PEM))
        self.save_entry(self.entry)

    def save_entry(self, entry):
        save_keystore(self.path, self.store_password, {"issuer": entry})
        self.before = self.path.read_bytes()

    def run_command(self, *options, interactive=False, command="-gencert"):
        argv = [
            command, "-keystore", str(self.path), "-alias", "issuer",
            "-infile", str(self.request), "-outfile", str(self.output),
        ]
        if not interactive:
            argv.extend(["-storepass", self.store_password, "-keypass", self.key_password])
        argv.extend(options)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = mykeytool.main(argv)
        combined = stdout.getvalue() + stderr.getvalue()
        for secret in (self.store_password, self.key_password, self.entry["private_key"], "PRIVATE KEY"):
            self.assertNotIn(secret, combined)
        self.assertNotIn("Traceback", combined)
        self.assertEqual(self.path.read_bytes(), self.before)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_error(self, result, message):
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], "")
        self.assertIn(message, result[2])
        self.assertFalse(self.output.exists())

    def load_output(self, pem=False):
        data = self.output.read_bytes()
        for secret in (b"PRIVATE KEY", self.store_password.encode(), self.key_password.encode()):
            self.assertNotIn(secret, data)
        return (
            x509.load_pem_x509_certificate(data) if pem
            else x509.load_der_x509_certificate(data)
        )

    def test_subject_public_key_issuer_signature_and_default_validity(self):
        before = datetime.now(timezone.utc).replace(microsecond=0)
        result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(result[2], "")
        cert = self.load_output()
        self.assertEqual(cert.subject, self.csr.subject)
        self.assertEqual(cert.issuer, self.issuer_certificate.subject)
        self.assertNotEqual(cert.issuer, build_subject(self.entry["dn"]))
        self.assertEqual(
            cert.public_key().public_numbers(), self.request_key.public_key().public_numbers()
        )
        self.assertEqual(cert.signature_hash_algorithm.name, "sha256")
        cert.verify_directly_issued_by(self.issuer_certificate)
        self.issuer_key.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256()
        )
        self.assertGreaterEqual(cert.not_valid_before_utc, before)
        self.assertLessEqual(cert.not_valid_before_utc, datetime.now(timezone.utc))
        self.assertEqual(
            cert.not_valid_after_utc - cert.not_valid_before_utc,
            timedelta(days=DEFAULT_VALIDITY_DAYS),
        )
        self.assertGreater(cert.serial_number, 0)
        self.assertLessEqual(cert.serial_number.bit_length(), 159)
        first_serial = cert.serial_number
        self.assertEqual(self.run_command()[0], 0)
        self.assertNotEqual(self.load_output().serial_number, first_serial)

    def test_formats_accept_standard_pem_keytool_pem_and_der_csr(self):
        for request in (
            self.csr.public_bytes(serialization.Encoding.PEM),
            encode_keytool_pem(self.csr),
            self.csr.public_bytes(serialization.Encoding.DER),
        ):
            for pem in (False, True):
                with self.subTest(request_header=request[:25], pem=pem):
                    self.request.write_bytes(request)
                    result = self.run_command(
                        *(["-rfc"] if pem else []), command="--gencert"
                    )
                    self.assertEqual(result[0], 0, result[2])
                    cert = self.load_output(pem)
                    self.assertEqual(cert.subject, self.request_name)
                    self.assertEqual(
                        self.output.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----"), pem
                    )

    def test_custom_validity_and_extensions_do_not_grant_csr_ca_request(self):
        result = self.run_command("-validity", "12")
        self.assertEqual(result[0], 0, result[2])
        cert = self.load_output()
        self.assertEqual(cert.not_valid_after_utc - cert.not_valid_before_utc, timedelta(days=12))
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(constraints.critical)
        self.assertFalse(constraints.value.ca)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.digital_signature)
        self.assertTrue(usage.value.key_encipherment)
        self.assertFalse(usage.value.key_cert_sign)
        self.assertFalse(usage.value.crl_sign)
        self.assertEqual(
            cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
            x509.SubjectKeyIdentifier.from_public_key(self.request_key.public_key()),
        )
        self.assertEqual(
            cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value,
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuer_key.public_key()),
        )
        with self.assertRaises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    def test_ec_request_preserves_key_without_rsa_encipherment_usage(self):
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.request_name).sign(key, hashes.SHA256())
        )
        self.request.write_bytes(csr.public_bytes(serialization.Encoding.DER))
        result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        cert = self.load_output()
        self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertFalse(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment)

    def test_legacy_dn_used_without_certificate_with_non_ca_warning(self):
        entry = copy.deepcopy(self.entry)
        del entry["certificate"]
        self.save_entry(entry)
        result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        self.assertIn("no es una CA", result[2])
        cert = self.load_output()
        self.assertEqual(cert.issuer, build_subject(entry["dn"]))
        self.issuer_key.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_non_ca_certificate_is_allowed_with_warning(self):
        from keytool.genkeypair import build_self_signed_certificate

        entry = copy.deepcopy(self.entry)
        entry["certificate"] = build_self_signed_certificate(
            self.issuer_key, entry["dn"]
        ).public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.save_entry(entry)
        result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        self.assertIn("no establece una cadena CA valida", result[2])
        cert = self.load_output()
        cert.verify_directly_issued_by(x509.load_pem_x509_certificate(entry["certificate"].encode()))

    def test_ca_without_key_cert_sign_permission_produces_warning(self):
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(self.issuer_name).issuer_name(self.issuer_name)
            .public_key(self.issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.issuer_key, hashes.SHA256())
        )
        entry = copy.deepcopy(self.entry)
        entry["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
        self.save_entry(entry)
        result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        self.assertIn("no es una CA con permiso", result[2])

    def test_altered_csr_signature_and_malformed_csr_are_rejected(self):
        data = self.csr.public_bytes(serialization.Encoding.DER)
        for request in (data[:-1] + bytes([data[-1] ^ 1]), b"not a CSR"):
            with self.subTest(request=request[:10]):
                self.request.write_bytes(request)
                self.assert_error(self.run_command(), "CSR no valido")

    def test_wrong_store_password_is_only_attempted_once(self):
        with patch("getpass.getpass", return_value="wrong-password") as prompt:
            result = self.run_command(interactive=True)
        self.assert_error(result, "incorrecta")
        prompt.assert_called_once()

    def test_wrong_key_password_and_missing_alias(self):
        self.assert_error(self.run_command("-keypass", "wrong-password"), "Contrasena incorrecta")
        self.assert_error(self.run_command("-alias", "absent"), "No existe el alias")

    def test_unsupported_algorithms_are_reported_without_backend_trace(self):
        with patch(
            "keytool.gencert.x509.load_pem_x509_csr",
            side_effect=UnsupportedAlgorithm("Unsupported CSR algorithm"),
        ):
            self.assert_error(self.run_command(), "CSR no valido")
        with patch(
            "keytool.gencert.load_private_key",
            side_effect=UnsupportedAlgorithm("Unsupported signing algorithm"),
        ):
            self.assert_error(self.run_command(), "algoritmo criptografico no admitido")

    def test_interactive_passwords_and_alias(self):
        with (
            patch("getpass.getpass", side_effect=[self.store_password, self.key_password]) as prompt,
            patch("builtins.input", return_value="issuer") as input_mock,
        ):
            # Omite el alias tambien para comprobar el mismo flujo que certreq.
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = mykeytool.main([
                    "-gencert", "-keystore", str(self.path),
                    "-infile", str(self.request), "-outfile", str(self.output),
                ])
        self.assertEqual(result, 0)
        self.assertEqual(prompt.call_count, 2)
        input_mock.assert_called_once()
        self.load_output().verify_directly_issued_by(self.issuer_certificate)

    def test_invalid_validity_is_reported_without_writing(self):
        for days in ("0", "-1", str(10**100)):
            with self.subTest(days=days):
                self.assert_error(self.run_command("-validity", days), "-validity")

    def test_missing_paths_and_missing_required_file_arguments(self):
        self.request.unlink()
        self.assert_error(self.run_command(), "no se pudo leer")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            result = mykeytool.main(["-gencert"])
        self.assertEqual(result, 1)
        self.assertIn("requiere -infile", errors.getvalue())

    def test_output_cannot_overwrite_store_or_request_including_hardlink(self):
        hardlink = self.directory / "linked.myks"
        os.link(self.path, hardlink)
        request_before = self.request.read_bytes()
        for output in (self.path, self.request, hardlink):
            with self.subTest(output=output):
                self.assert_error(
                    self.run_command("-outfile", str(output)), "no puede sobrescribir"
                )
        self.assertEqual(self.request.read_bytes(), request_before)

    def test_mismatched_issuer_certificate_and_corrupt_certificate(self):
        other_cert = (
            x509.CertificateBuilder()
            .subject_name(self.issuer_name).issuer_name(self.issuer_name)
            .public_key(self.request_key.public_key()).serial_number(1)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(self.issuer_key, hashes.SHA256())
        )
        for value, message in (
            (other_cert.public_bytes(serialization.Encoding.PEM).decode(), "no coincide"),
            ("not a certificate", "Certificado del KeyStore no valido"),
        ):
            with self.subTest(message=message):
                entry = copy.deepcopy(self.entry)
                entry["certificate"] = value
                self.save_entry(entry)
                self.assert_error(self.run_command(), message)

    def test_atomic_output_is_complete_and_preserves_previous_output_on_failure(self):
        original = b"previous certificate"
        self.output.write_bytes(original)
        for target in ("os.fsync", "os.replace"):
            with self.subTest(target=target):
                with patch(f"keytool.keystore.{target}", side_effect=OSError("Disk full")):
                    result = self.run_command()
                self.assertEqual(result[0], 1)
                self.assertEqual(result[1], "")
                self.assertEqual(self.output.read_bytes(), original)
                self.assertEqual(list(self.directory.glob("*.tmp")), [])
        replace = os.replace

        def inspect_replace(source, destination):
            self.assertEqual(destination, self.output)
            self.assertEqual(source.parent, destination.parent)
            self.assertEqual(destination.read_bytes(), original)
            x509.load_der_x509_certificate(source.read_bytes()).verify_directly_issued_by(
                self.issuer_certificate
            )
            replace(source, destination)

        with patch("keytool.keystore.os.replace", side_effect=inspect_replace):
            self.assertEqual(self.run_command()[0], 0)

    def test_cancellation_and_insecure_terminal_do_not_write(self):
        for interruption in (EOFError, KeyboardInterrupt):
            with self.subTest(interruption=interruption):
                with patch("getpass.getpass", side_effect=interruption):
                    self.assert_error(self.run_command(interactive=True), "cancelada")

        def insecure_getpass(prompt):
            warnings.warn("No terminal", getpass.GetPassWarning)
            self.fail("Must not fall back to echoed input")

        with patch("getpass.getpass", side_effect=insecure_getpass):
            self.assert_error(self.run_command(interactive=True), "ocultar")

    def test_general_and_specific_help(self):
        for command in ("-gencert", "--gencert"):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(mykeytool.main([command, "--help"]), 0)
            for option in ("-infile", "-outfile", "-rfc", "-validity", "90"):
                self.assertIn(option, output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(mykeytool.main([]), 0)
        self.assertIn("-gencert, --gencert", output.getvalue())

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL no disponible")
    def test_certificate_is_readable_and_verifiable_with_openssl(self):
        ca_path = self.directory / "issuer.pem"
        ca_path.write_bytes(self.issuer_certificate.public_bytes(serialization.Encoding.PEM))
        for pem in (False, True):
            with self.subTest(pem=pem):
                result = self.run_command(*(["-rfc"] if pem else []))
                self.assertEqual(result[0], 0, result[2])
                inspected = subprocess.run(
                    ["openssl", "x509", "-inform", "PEM" if pem else "DER",
                     "-in", str(self.output), "-noout", "-subject", "-issuer"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(inspected.returncode, 0, inspected.stderr)
                self.assertIn("Requested subject", inspected.stdout)
                certificate_pem = self.directory / "verify.pem"
                certificate_pem.write_bytes(
                    self.load_output(pem).public_bytes(serialization.Encoding.PEM)
                )
                verified = subprocess.run(
                    ["openssl", "verify", "-CAfile", str(ca_path), str(certificate_pem)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(verified.returncode, 0, verified.stderr)


if __name__ == "__main__":
    unittest.main()
