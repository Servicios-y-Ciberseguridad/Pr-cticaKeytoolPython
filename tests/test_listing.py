import contextlib
import getpass
import io
import json
import tempfile
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import mykeytool
from keytool.keystore import KeyEntry, save_keystore


class ListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_pem = cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        cls.key_password = "separate-key-password"
        cls.private_pem = cls.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(cls.key_password.encode()),
        ).decode("ascii")

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "test.myks"
        self.password = "listing-store-password"

    def entry(self):
        return KeyEntry(
            private_key=self.private_pem,
            public_key=self.public_pem,
            dn=dict(zip(mykeytool.DN_FIELDS, [
                "Ana", "TI", "Empresa", "Madrid", "Madrid", "ES"
            ])),
        )

    def run_list(self, *options, command="-list", password=None, interactive=False):
        argv = [command, "-keystore", str(self.path), *options]
        if not interactive:
            argv.extend(["-storepass", self.password if password is None else password])
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            patch("cryptography.hazmat.primitives.serialization.load_pem_private_key",
                  side_effect=AssertionError("Listing must not decrypt private keys")),
            patch("builtins.input", side_effect=AssertionError("Unexpected prompt")),
        ):
            result = mykeytool.main(argv)
        combined = output.getvalue() + errors.getvalue()
        for secret in (
            self.password, self.key_password, self.private_pem,
            "PRIVATE KEY", "private_key", "salt", "nonce",
        ):
            self.assertNotIn(secret, combined)
        self.assertNotIn("Traceback", combined)
        return result, output.getvalue(), errors.getvalue()

    def assert_error(self, result, message):
        code, output, errors = result
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn(message, errors)

    def test_empty_store(self):
        save_keystore(self.path, self.password, {})
        self.assertEqual(self.run_list(), (0, "Entradas: 0\n", ""))

    def test_lists_all_aliases_in_stable_order_without_modifying_store(self):
        save_keystore(self.path, self.password, {
            "zeta": self.entry(), "alpha": self.entry(), "Beta": self.entry()
        })
        before = self.path.read_bytes()
        result = self.run_list(command="--list")
        self.assertEqual(result, (
            0, 'Entradas: 3\nAlias: "Beta"\nAlias: "alpha"\nAlias: "zeta"\n', ""
        ))
        self.assertEqual(self.path.read_bytes(), before)

    def test_filters_one_alias_and_normalizes_whitespace(self):
        save_keystore(self.path, self.password, {
            "alpha": self.entry(), "zeta": self.entry()
        })
        self.assertEqual(self.run_list("-alias", " zeta "), (
            0, 'Entradas: 1\nAlias: "zeta"\n', ""
        ))

    def test_verbose_reports_public_key_and_dn_without_certificate(self):
        save_keystore(self.path, self.password, {"alpha": self.entry()})
        for flag in ("-v", "--verbose"):
            with self.subTest(flag=flag):
                code, output, errors = self.run_list(flag)
                self.assertEqual(code, 0, errors)
                self.assertIn("CN=Ana, OU=TI, O=Empresa", output)
                self.assertIn("Algoritmo: RSA", output)
                self.assertIn("Tamano de clave publica: 2048 bits", output)
                self.assertIn("Certificado: no disponible", output)
                self.assertNotIn(self.public_pem, output)

    def test_verbose_certificate_reports_public_metadata_only(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ana")])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(1234)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(self.private_key, hashes.SHA256())
        )
        entry = dict(self.entry())
        entry["certificate"] = certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii")
        entry["extra_secret"] = "must-not-appear-in-output"
        save_keystore(self.path, self.password, {"certified": entry})

        code, output, errors = self.run_list("-v")

        self.assertEqual(code, 0, errors)
        for expected in (
            'Sujeto: "CN=Ana"', 'Emisor: "CN=Test CA"', "Numero de serie: 4D2",
            now.isoformat(), (now + timedelta(days=30)).isoformat(),
            certificate.signature_algorithm_oid.dotted_string,
            certificate.fingerprint(hashes.SHA256()).hex().upper(),
        ):
            self.assertIn(expected, output)
        self.assertNotIn("must-not-appear-in-output", output)
        self.assertNotIn("BEGIN CERTIFICATE", output)

    def test_missing_alias(self):
        save_keystore(self.path, self.password, {"alpha": self.entry()})
        self.assert_error(self.run_list("-alias", "missing"), "No existe el alias")

    def test_blank_alias(self):
        save_keystore(self.path, self.password, {})
        self.assert_error(self.run_list("-alias", " "), "alias no puede estar vacio")

    def test_wrong_password_authenticates_even_with_missing_alias(self):
        save_keystore(self.path, self.password, {"hidden-alias": self.entry()})
        for options in ((), ("-v",), ("-alias", "missing")):
            with self.subTest(options=options):
                result = self.run_list(*options, password="wrong-password")
                self.assert_error(result, "Contrasena incorrecta o KeyStore alterado")
                self.assertNotIn("hidden-alias", result[2])
                self.assertNotIn("wrong-password", result[2])
                self.assertNotIn("No existe el alias", result[2])

    def test_missing_store_does_not_create_file_or_prompt(self):
        with patch("keytool.genkeypair.read_password",
                   side_effect=AssertionError("Unexpected password prompt")):
            self.assert_error(
                self.run_list(interactive=True), "No existe el KeyStore"
            )
        self.assertFalse(self.path.exists())

    def test_invalid_store_header(self):
        self.path.write_bytes(b"not-a-keystore")
        self.assert_error(self.run_list(), "Formato de KeyStore no valido")

    def test_tampered_and_truncated_store(self):
        save_keystore(self.path, self.password, {"alpha": self.entry()})
        data = self.path.read_bytes()
        for damaged in (data[:-1] + bytes([data[-1] ^ 1]), data[:-10]):
            with self.subTest(length=len(damaged)):
                self.path.write_bytes(damaged)
                self.assert_error(self.run_list("-v"), "KeyStore alterado")

    def test_prompts_once_for_store_password_without_echo(self):
        save_keystore(self.path, self.password, {})
        with patch("mykeytool.getpass.getpass", return_value=self.password) as prompt:
            self.assertEqual(self.run_list(interactive=True), (0, "Entradas: 0\n", ""))
        prompt.assert_called_once_with("Enter keystore password: ")

    def test_no_terminal_fails_instead_of_echoing_password(self):
        save_keystore(self.path, self.password, {})

        def warn_no_terminal(*args, **kwargs):
            warnings.warn("Cannot control echo", getpass.GetPassWarning)

        with patch("mykeytool.getpass.getpass", side_effect=warn_no_terminal):
            self.assert_error(self.run_list(interactive=True), "ocultar la contrasena")

    def test_cancelled_password_input(self):
        save_keystore(self.path, self.password, {})
        for exception in (EOFError, KeyboardInterrupt):
            with self.subTest(exception=exception):
                with patch("mykeytool.getpass.getpass", side_effect=exception):
                    self.assert_error(self.run_list(interactive=True), "cancelada")

    def test_empty_password(self):
        save_keystore(self.path, self.password, {})
        self.assert_error(self.run_list(password=""), "no puede estar vacia")

    def test_invalid_public_data_has_no_partial_output_or_raw_error(self):
        for field, value, message in (
            ("public_key", "invalid-public-data", "Clave publica"),
            ("public_key", "\u00f1", "Clave publica"),
            ("certificate", "invalid-certificate-data", "Certificado"),
            ("certificate", 42, "Certificado"),
            ("certificate", "\u00f1", "Certificado"),
        ):
            with self.subTest(field=field, value=value):
                damaged = dict(self.entry())
                damaged[field] = value
                save_keystore(self.path, self.password, {
                    "alpha": self.entry(), "zeta": damaged
                })
                result = self.run_list("-v")
                self.assert_error(result, message)
                self.assertNotIn(str(value), result[2])
                self.assertEqual(self.run_list()[0], 0)
                self.assertEqual(self.run_list("-v", "-alias", "alpha")[0], 0)

    def test_control_characters_in_public_fields_are_escaped(self):
        alias = "alpha\nAlias: fake\x1b[2J"
        entry = self.entry()
        entry["dn"]["CN"] = "Ana\nEmisor: fake"
        save_keystore(self.path, self.password, {alias: entry})
        code, output, errors = self.run_list("-v")
        self.assertEqual(code, 0, errors)
        self.assertIn(f"Alias: {json.dumps(alias)}\n", output)
        self.assertIn("Ana\\nEmisor: fake", output)
        self.assertNotIn("\x1b", output)

    def test_specific_help_and_general_help(self):
        for argv in (["-list", "-h"], ["--list", "--help"], []):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(output),
                    patch("mykeytool.getpass.getpass",
                          side_effect=AssertionError("Unexpected prompt")),
                ):
                    self.assertEqual(mykeytool.main(argv), 0)
                self.assertIn("-list", output.getvalue())
                if argv:
                    for option in ("-keystore", "-storepass", "-alias", "--verbose"):
                        self.assertIn(option, output.getvalue())


if __name__ == "__main__":
    unittest.main()
