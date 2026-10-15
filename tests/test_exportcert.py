import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import mykeytool
from keytool.keystore import DN_FIELDS, KeyEntry, save_keystore


class ExportCertTests(unittest.TestCase):
    store_password = "export-store-password"
    private_secret = "PRIVATE KEY MUST NOT BE READ"

    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        cls.certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Export test"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Export issuer"),
            ]))
            .public_key(key.public_key())
            .serial_number(12345)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / "store.myks"
        self.output = self.directory / "certificate.bin"
        self.entry = KeyEntry(
            private_key=self.private_secret,
            public_key="public key is not needed for export",
            dn=dict(zip(DN_FIELDS, ["Export test", "TI", "Empresa", "Madrid", "Madrid", "ES"])),
            certificate=self.certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii"),
        )
        self.save_entries({"public-alias": self.entry})

    def save_entries(self, entries):
        save_keystore(self.path, self.store_password, entries)
        self.before = self.path.read_bytes()

    def run_command(self, *options, interactive=False, command="-exportcert"):
        argv = [
            command, "-keystore", str(self.path),
            "-alias", "public-alias", "-file", str(self.output),
        ]
        if not interactive:
            argv.extend(["-storepass", self.store_password])
        argv.extend(options)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                side_effect=AssertionError("Export must not load private keys"),
            ),
        ):
            result = mykeytool.main(argv)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(self.store_password, combined)
        self.assertNotIn(self.private_secret, combined)
        self.assertNotIn("Traceback", combined)
        self.assertEqual(self.path.read_bytes(), self.before)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_error(self, result, message):
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], "")
        self.assertIn(message, result[2])
        self.assertFalse(self.output.exists())

    def test_der_and_pem_are_valid_and_represent_same_certificate(self):
        der_result = self.run_command()
        self.assertEqual(der_result[0], 0, der_result[2])
        der = self.output.read_bytes()
        self.assertNotIn(self.private_secret.encode(), der)
        der_certificate = x509.load_der_x509_certificate(der)

        pem_result = self.run_command("-rfc", command="--exportcert")
        self.assertEqual(pem_result[0], 0, pem_result[2])
        pem = self.output.read_bytes()
        self.assertTrue(pem.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertTrue(pem.rstrip().endswith(b"-----END CERTIFICATE-----"))
        pem_certificate = x509.load_pem_x509_certificate(pem)
        self.assertEqual(
            der_certificate.public_bytes(serialization.Encoding.DER),
            pem_certificate.public_bytes(serialization.Encoding.DER),
        )

    def test_missing_alias_and_certificate_are_reported_without_traceback(self):
        self.assert_error(self.run_command("-alias", "missing"), "No existe el alias")
        self.save_entries({
            "public-alias": KeyEntry(
                private_key=self.private_secret,
                public_key="public key",
                dn=self.entry["dn"],
            )
        })
        self.assert_error(
            self.run_command(),
            "no tiene certificado X.509 para exportar",
        )

    def test_wrong_password_and_missing_store_are_reported(self):
        result = self.run_command("-storepass", "wrong-password")
        self.assert_error(result, "Contrasena incorrecta")
        missing_path = self.directory / "missing.myks"
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            result_code = mykeytool.main([
                "-exportcert", "-keystore", str(missing_path),
                "-storepass", self.store_password, "-alias", "public-alias",
                "-file", str(self.output),
            ])
        self.assertEqual(result_code, 1)
        self.assertIn("No existe el KeyStore", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_prompts_for_omitted_password_and_alias_and_defaults_output_name(self):
        self.output.unlink(missing_ok=True)
        original_directory = Path.cwd()
        try:
            os.chdir(self.directory)
            with (
                patch("getpass.getpass", return_value=self.store_password) as password_prompt,
                patch("builtins.input", return_value="public-alias") as alias_prompt,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = mykeytool.main([
                    "-exportcert", "-keystore", str(self.path), "-rfc"
                ])
        finally:
            os.chdir(original_directory)
        self.assertEqual(result, 0)
        password_prompt.assert_called_once()
        alias_prompt.assert_called_once()
        self.assertTrue((self.directory / "public-alias.cer").exists())
        x509.load_pem_x509_certificate(
            (self.directory / "public-alias.cer").read_bytes()
        )

    def test_output_cannot_overwrite_keystore_or_its_hardlink(self):
        hardlink = self.directory / "linked.myks"
        os.link(self.path, hardlink)
        for output in (self.path, hardlink):
            with self.subTest(output=output):
                result = self.run_command("-file", str(output))
                self.assertEqual(result[0], 1)
                self.assertEqual(result[1], "")
                self.assertIn("no puede sobrescribir el KeyStore", result[2])

    def test_atomic_write_failure_preserves_existing_output(self):
        existing = b"previous output"
        self.output.write_bytes(existing)
        with patch("keytool.keystore.os.replace", side_effect=OSError("Disk full")):
            result = self.run_command()
        self.assertEqual(result[0], 1)
        self.assertIn("no se pudo leer o escribir", result[2])
        self.assertEqual(self.output.read_bytes(), existing)

    def test_help_shows_command_and_options(self):
        for command in ("-exportcert", "--exportcert"):
            with self.subTest(command=command):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    result = mykeytool.main([command, "--help"])
                self.assertEqual(result, 0)
                self.assertIn("-rfc", output.getvalue())
                self.assertIn("-file FILE", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            mykeytool.main([])
        self.assertIn("-exportcert, --exportcert", output.getvalue())


if __name__ == "__main__":
    unittest.main()
