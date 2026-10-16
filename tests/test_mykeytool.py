import base64
import contextlib
import io
import tempfile
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
<<<<<<< HEAD
from cryptography.hazmat.primitives import serialization
=======
from cryptography.hazmat.primitives import hashes, serialization
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

import mykeytool
from keytool.errors import (
    AliasNotFoundError,
    DuplicateAliasError,
    InvalidKeystoreError,
    KeyPasswordError,
    KeystoreAuthenticationError,
    KeystoreNotFoundError,
)
from keytool.certreq import load_private_key, resolve_output_path
<<<<<<< HEAD
=======
from keytool.genkeypair import build_subject


class CliArgumentTests(unittest.TestCase):
    commands = (
        "genkeypair", "certreq", "changealias", "list",
        "exportcert", "storepasswd", "gencert",
    )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / "arguments.myks"

    def assert_parse_error(self, arguments, expected_error):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("builtins.input") as input_mock,
            patch("mykeytool.getpass.getpass") as password_mock,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as raised,
        ):
            mykeytool.main(["-keystore", str(self.path), *arguments])

        diagnostic = f"Arguments: {arguments!r}\nstderr: {errors.getvalue()}"
        self.assertEqual(raised.exception.code, 2, diagnostic)
        self.assertEqual(output.getvalue(), "", diagnostic)
        self.assertIn("usage:", errors.getvalue(), diagnostic)
        self.assertIn(expected_error, errors.getvalue(), diagnostic)
        self.assertNotIn("Traceback", errors.getvalue(), diagnostic)
        input_mock.assert_not_called()
        password_mock.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [], diagnostic)

    def test_rejects_unknown_arguments(self):
        for argument in ("--unknown-option", "unexpected-positional"):
            with self.subTest(argument=argument):
                self.assert_parse_error(
                    ["--genkeypair", argument], "unrecognized arguments"
                )

    def test_rejects_multiple_commands(self):
        for index, command in enumerate(self.commands):
            for other in self.commands[index + 1:]:
                with self.subTest(command=command, other=other):
                    self.assert_parse_error(
                        [f"--{command}", f"--{other}"], "not allowed with argument"
                    )

    def test_rejects_options_without_values(self):
        for option in (
            "-keystore", "-alias", "-destalias", "-dname", "-storepass",
            "-new", "-keypass", "-keyalg", "-keysize", "-infile",
            "-outfile", "-validity", "-file",
        ):
            with self.subTest(option=option):
                self.assert_parse_error(
                    ["--genkeypair", option], "expected one argument"
                )

    def test_rejects_non_integer_numeric_arguments(self):
        for option in ("-keysize", "-validity"):
            for value in ("abc", "2048.5"):
                with self.subTest(option=option, value=value):
                    self.assert_parse_error(
                        ["--genkeypair", option, value], "invalid int value"
                    )

    def test_general_help_exits_successfully_without_prompting(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                output = io.StringIO()
                errors = io.StringIO()
                with (
                    patch("builtins.input") as input_mock,
                    patch("mykeytool.getpass.getpass") as password_mock,
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                    self.assertRaises(SystemExit) as raised,
                ):
                    mykeytool.main([flag])
                self.assertEqual(raised.exception.code, 0)
                for command in self.commands:
                    self.assertIn(f"--{command}", output.getvalue())
                self.assertEqual(errors.getvalue(), "")
                input_mock.assert_not_called()
                password_mock.assert_not_called()
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_command_help_supports_both_spellings_without_prompting(self):
        for command in self.commands:
            for prefix in ("-", "--"):
                with self.subTest(command=command, prefix=prefix):
                    output = io.StringIO()
                    errors = io.StringIO()
                    with (
                        patch("builtins.input") as input_mock,
                        patch("mykeytool.getpass.getpass") as password_mock,
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        result = mykeytool.main([f"{prefix}{command}", "--help"])
                    self.assertEqual(result, 0, errors.getvalue())
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn(f"usage: mykeytool.py -{command}", errors.getvalue())
                    input_mock.assert_not_called()
                    password_mock.assert_not_called()
                    self.assertEqual(list(self.directory.iterdir()), [])
>>>>>>> d8219a1dddcd361b0d6e1b37b99964532f93dcac


class GenKeyPairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "test.myks"
        self.password = "test-password-123"

    def generate(self, alias="miClave", password=None, dn=None):
        password = self.password if password is None else password
        if not self.path.exists():
            passwords = [password, password, ""]
        elif password == self.password:
            passwords = [password, ""]
        else:
            passwords = [password] * mykeytool.MAX_PASSWORD_ATTEMPTS
        fields = dn if dn is not None else ["Ana", "TI", "Empresa", "Madrid", "Madrid", "es"]
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", side_effect=passwords) as getpass_mock,
            patch("builtins.input", side_effect=[alias, *fields, "yes"]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "--genkeypair",
                "--keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertNotIn(password, output.getvalue() + errors.getvalue())
        self.assertTrue(getpass_mock.called)
        return result, output.getvalue(), errors.getvalue()

    def test_generates_encrypted_rsa_2048_entry_and_dn(self):
        result, output, errors = self.generate()
        self.assertEqual(result, 0, errors)
        self.assertIn("Exito", output)
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=self.password.encode("utf-8")
        )
        public = serialization.load_pem_public_key(entry["public_key"].encode("ascii"))
        self.assertIsInstance(private, rsa.RSAPrivateKey)
        self.assertIsInstance(public, rsa.RSAPublicKey)
        self.assertEqual(private.key_size, 2048)
        self.assertEqual(public.key_size, 2048)
        self.assertEqual(private.public_key().public_numbers(), public.public_numbers())
        self.assertEqual(public.public_numbers().e, 65537)
        self.assertEqual(entry["dn"], dict(zip(mykeytool.DN_FIELDS, [
            "Ana", "TI", "Empresa", "Madrid", "Madrid", "ES"
        ])))
        certificate = x509.load_pem_x509_certificate(entry["certificate"].encode("ascii"))
        self.assertEqual(certificate.subject, build_subject(entry["dn"]))
        self.assertEqual(certificate.issuer, certificate.subject)
        self.assertEqual(
            certificate.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            entry["public_key"].encode("ascii"),
        )
        certificate.verify_directly_issued_by(certificate)
        self.assertEqual(certificate.signature_hash_algorithm.name, "sha256")
        self.assertGreater(certificate.serial_number, 0)
        self.assertLessEqual(certificate.serial_number.bit_length(), 159)
        self.assertEqual(
            certificate.not_valid_after_utc - certificate.not_valid_before_utc,
            timedelta(days=90),
        )
        now = datetime.now(timezone.utc)
        self.assertLessEqual(certificate.not_valid_before_utc, now)
        self.assertGreater(certificate.not_valid_before_utc, now - timedelta(minutes=1))
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(constraints.critical)
        self.assertFalse(constraints.value.ca)
        encrypted = self.path.read_bytes()
        for secret in (b"miClave", b"PRIVATE KEY", b"Empresa", self.password.encode()):
            self.assertNotIn(secret, encrypted)
        with self.assertRaisesRegex(KeystoreAuthenticationError, "incorrecta"):
            mykeytool.load_keystore(self.path, "wrong-password")

    def test_generated_certificate_is_listed_without_decrypting_private_key(self):
        self.assertEqual(self.generate()[0], 0)
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        certificate = x509.load_pem_x509_certificate(entry["certificate"].encode("ascii"))
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":").upper()
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("cryptography.hazmat.primitives.serialization.load_pem_private_key",
                  side_effect=AssertionError("Must not decrypt private keys")),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-list", "-keystore", str(self.path),
                "-storepass", self.password, "-alias", "miClave",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn(f"Certificate fingerprint (SHA-256): {fingerprint}", output.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue())
        self.assertNotIn(self.password, output.getvalue())

    def test_self_signed_certificate_handles_unknown_country(self):
        self.assertEqual(self.generate(dn=["", "", "", "", "", ""])[0], 0)
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        certificate = x509.load_pem_x509_certificate(entry["certificate"].encode("ascii"))
        self.assertEqual(certificate.subject, build_subject(entry["dn"]))
        self.assertEqual(certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME), [])
        certificate.verify_directly_issued_by(certificate)

    def test_loads_one_entry_by_alias_and_store_password(self):
        self.assertEqual(self.generate()[0], 0)

        entry = mykeytool.load_keystore_entry(
            self.path, "miClave", self.password
        )

        self.assertEqual(entry["dn"]["CN"], "Ana")
        with self.assertRaisesRegex(AliasNotFoundError, "No existe el alias"):
            mykeytool.load_keystore_entry(self.path, "missing", self.password)
        with self.assertRaisesRegex(KeystoreAuthenticationError, "incorrecta"):
            mykeytool.load_keystore_entry(self.path, "miClave", "wrong-password")

    def test_missing_keystore_is_reported(self):
        with self.assertRaisesRegex(KeystoreNotFoundError, "No existe el KeyStore"):
            mykeytool.load_keystore(self.path, self.password)

    def test_save_load_round_trip_uses_versioned_encrypted_format(self):
        entries = {
            "private-alias": mykeytool.KeyEntry(
                private_key="private-key-secret",
                public_key="public-key-data",
                dn={field: f"{field}-value" for field in mykeytool.DN_FIELDS},
            )
        }

        mykeytool.save_keystore(self.path, self.password, entries)

        data = self.path.read_bytes()
        encrypted_data_start = (
            len(mykeytool.STORE_HEADER)
            + mykeytool.STORE_SALT_SIZE
            + mykeytool.STORE_NONCE_SIZE
        )
        self.assertTrue(data.startswith(mykeytool.STORE_HEADER))
        self.assertGreaterEqual(
            len(data),
            encrypted_data_start + mykeytool.AES_GCM_TAG_SIZE,
        )
        for secret in (b"private-alias", b"private-key-secret", self.password.encode()):
            self.assertNotIn(secret, data)
        self.assertEqual(mykeytool.load_keystore(self.path, self.password), entries)

    def test_authenticated_invalid_json_is_reported_as_invalid_store(self):
        salt = bytes(mykeytool.STORE_SALT_SIZE)
        nonce = bytes(mykeytool.STORE_NONCE_SIZE)
        ciphertext = AESGCM(mykeytool.derive_store_key(self.password, salt)).encrypt(
            nonce, b"{not-json", mykeytool.STORE_HEADER
        )
        self.path.write_bytes(
            mykeytool.STORE_HEADER + salt + nonce + ciphertext
        )

        with self.assertRaisesRegex(InvalidKeystoreError, "Contenido de KeyStore no valido"):
            mykeytool.load_keystore(self.path, self.password)

    def test_supports_keytool_style_arguments(self):
        output = io.StringIO()
        errors = io.StringIO()
        argv = [
            "-genkeypair",
            "-keystore",
            str(self.path),
            "-alias",
            "mykey",
            "-storepass",
            self.password,
            "-keypass",
            self.password,
            "-keyalg",
            "RSA",
            "-keysize",
            "3072",
            "-dname",
            "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=es",
        ]
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(argv)
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("3072 bits", output.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=self.password.encode("utf-8")
        )
        self.assertEqual(private.key_size, 3072)
        self.assertEqual(entry["dn"]["C"], "ES")

    def test_prompts_for_missing_keyalg(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch(
                "builtins.input",
                side_effect=["RSA", "2048", "miClave", "Ana", "TI", "Empresa", "Madrid", "Madrid", "es", "yes"],
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["-genkeypair", "-keystore", str(self.path)])
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("Exito", output.getvalue())

    def test_prompts_for_missing_keysize(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch(
                "builtins.input",
                side_effect=["4096", "miClave", "Ana", "TI", "Empresa", "Madrid", "Madrid", "es", "yes"],
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=self.password.encode("utf-8")
        )
        self.assertEqual(private.key_size, 4096)

    def test_shows_genkeypair_help_with_short_help_flag(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["-genkeypair", "-h"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Required for -genkeypair", errors.getvalue())
        self.assertIn("-keyalg KEYALG", errors.getvalue())

    def test_shows_genkeypair_help_with_long_help_flag(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["-genkeypair", "--help"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Optional for -genkeypair", errors.getvalue())
        self.assertIn("-alias ALIAS", errors.getvalue())

    def test_shows_general_help_without_arguments(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([])
        self.assertEqual(result, 0)
        self.assertIn("Comandos disponibles", output.getvalue())
        self.assertIn("--genkeypair", output.getvalue())
        self.assertNotIn("-alias ALIAS", output.getvalue())
        self.assertEqual(errors.getvalue(), "")

    def test_uses_default_alias_when_not_provided(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "es",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entries = mykeytool.load_keystore(self.path, self.password)
        self.assertIn("mykey", entries)

    def test_reprompts_until_distinguished_name_is_confirmed(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "miClave",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "es",
            "no",
            "Ana Dos",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "es",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        self.assertEqual(entry["dn"]["CN"], "Ana Dos")

    def test_rejects_unsupported_key_algorithm(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-alias",
                "mykey",
                "-storepass",
                self.password,
                "-keypass",
                self.password,
                "-keyalg",
                "EC",
                "-dname",
                "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES",
            ])
        self.assertEqual(result, 1)
        self.assertIn("Solo se admite -keyalg RSA", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_main_facade_exposes_crypto_and_keysize_checks_from_txt(self):
        self.assertTrue(mykeytool.is_crypto_library_available())
        for keysize in (2048, 3072, 4096, 7680, 15360):
            self.assertTrue(mykeytool.is_key_size_supported(keysize))
        self.assertFalse(mykeytool.is_key_size_supported(1024))

    def test_key_size_prompt_displays_every_supported_option(self):
        with patch("builtins.input", return_value="") as input_mock:
            self.assertEqual(mykeytool.resolve_key_size(None), 2048)
        prompt = input_mock.call_args.args[0]
        for keysize in mykeytool.SUPPORTED_KEY_SIZES:
            self.assertIn(str(keysize), prompt)

    def test_rejects_unsupported_key_size(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-alias",
                "mykey",
                "-storepass",
                self.password,
                "-keypass",
                self.password,
                "-keyalg",
                "RSA",
                "-keysize",
                "1024",
                "-dname",
                "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES",
            ])
        self.assertEqual(result, 1)
        self.assertIn("valores", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_interactive_algorithm_and_key_size_are_requested_until_valid(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "EC",
            "RSA",
            "1024",
            "2048",
            "miClave",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "ES",
            "yes",
        ]
        with (
            patch(
                "mykeytool.getpass.getpass",
                side_effect=[self.password, self.password, ""],
            ),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
            ])
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("algoritmo no valido", errors.getvalue())
        self.assertIn("tamano no valido", errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"),
            password=self.password.encode("utf-8"),
        )
        self.assertEqual(private.key_size, 2048)

    def test_preserves_existing_entries(self):
        self.assertEqual(self.generate()[0], 0)
        original = mykeytool.load_keystore(self.path, self.password)["miClave"]
        self.assertEqual(self.generate(alias="segunda")[0], 0)
        entries = mykeytool.load_keystore(self.path, self.password)
        self.assertEqual(set(entries), {"miClave", "segunda"})
        self.assertEqual(entries["miClave"], original)

    def test_duplicate_alias_and_wrong_password_preserve_file(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        entries = mykeytool.load_keystore(self.path, self.password)
        with self.assertRaisesRegex(DuplicateAliasError, "ya existe"):
            mykeytool.resolve_unique_alias("miClave", entries)
        for kwargs, message in [({}, "ya existe"), ({"password": "wrong-password"}, "incorrecta")]:
            result, output, errors = self.generate(**kwargs)
            self.assertEqual(result, 1)
            self.assertNotIn("Exito", output)
            self.assertIn(message, errors)
            self.assertNotIn("Traceback", errors)
            self.assertEqual(self.path.read_bytes(), before)

    def test_genkeypair_fails_after_one_wrong_store_password(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch(
                "mykeytool.getpass.getpass",
                return_value="wrong-password",
            ) as getpass_mock,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 1)
        self.assertEqual(getpass_mock.call_count, 1)
        self.assertIn("incorrecta", errors.getvalue())
        self.assertNotIn("Intentos restantes", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_duplicate_alias_allows_three_interactive_attempts(self):
        self.assertEqual(self.generate()[0], 0)
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "miClave",
            "miClave",
            "segunda",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "ES",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, ""]),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("Intentos restantes: 2", errors.getvalue())
        entries = mykeytool.load_keystore(self.path, self.password)
        self.assertIn("segunda", entries)

    def test_duplicate_alias_fails_after_three_interactive_attempts(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        output = io.StringIO()
        errors = io.StringIO()
        answers = ["miClave", "miClave", "miClave"]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password]),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 1)
        self.assertIn("Se agotaron los 3 intentos", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_tampered_or_invalid_store_is_not_overwritten(self):
        self.assertEqual(self.generate()[0], 0)
        data = self.path.read_bytes()
        tampered = data[:-1] + bytes([data[-1] ^ 1])
        for invalid in (tampered, b"", b"not-a-keystore"):
            self.path.write_bytes(invalid)
            result, output, errors = self.generate()
            self.assertEqual(result, 1)
            self.assertNotIn("Traceback", errors)
            self.assertEqual(self.path.read_bytes(), invalid)

    def test_empty_fields_and_invalid_country_fail(self):
        for alias, fields in [
            (" ", None),
            ("valid", ["Ana", "TI", "Empresa", "Madrid", "Madrid", "ESP"]),
        ]:
            with self.subTest(alias=alias, fields=fields):
                self.assertEqual(self.generate(alias=alias, dn=fields)[0], 1)
                self.assertFalse(self.path.exists())

    def test_blank_distinguished_name_fields_become_unknown_after_confirmation(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "",
            "",
            "",
            "",
            "",
            "",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch("builtins.input", side_effect=["mykey", *answers]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        self.assertEqual(
            entry["dn"],
            dict(zip(mykeytool.DN_FIELDS, [mykeytool.UNKNOWN_DN_VALUE] * len(mykeytool.DN_FIELDS))),
        )

    def test_blank_confirmation_reasks_all_distinguished_name_fields(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "ES",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch("builtins.input", side_effect=["mykey", *answers]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        self.assertEqual(entry["dn"]["CN"], "Ana")
        self.assertEqual(entry["dn"]["C"], "ES")

    def test_no_confirmation_reasks_all_distinguished_name_fields(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "",
            "",
            "",
            "",
            "",
            "",
            "no",
            "Ana Dos",
            "Seguridad",
            "Empresa",
            "Sevilla",
            "Andalucia",
            "ES",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password, ""]),
            patch("builtins.input", side_effect=["mykey", *answers]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        self.assertEqual(entry["dn"]["CN"], "Ana Dos")
        self.assertEqual(entry["dn"]["OU"], "Seguridad")

    def test_short_or_mismatched_password_fails(self):
        self.assertEqual(self.generate(password="short")[0], 1)
        with (
            patch(
                "mykeytool.getpass.getpass",
                side_effect=[self.password, "different"] * mykeytool.MAX_PASSWORD_ATTEMPTS,
            ),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path, keyalg="RSA", keysize=2048), 1)
        self.assertIn("no coinciden", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_insecure_password_fallback_is_rejected(self):
        def insecure_getpass(prompt):
            warnings.warn("No secure terminal", getpass_warning)
            self.fail("getpass continued with an insecure fallback")

        getpass_warning = mykeytool.getpass.GetPassWarning
        with (
            patch("mykeytool.getpass.getpass", side_effect=insecure_getpass),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path, keyalg="RSA", keysize=2048), 1)
        self.assertIn("ocultar", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_cancelled_input_fails_without_writing(self):
        with (
            patch("mykeytool.getpass.getpass", side_effect=KeyboardInterrupt),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path, keyalg="RSA", keysize=2048), 1)
        self.assertIn("cancelada", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_failed_replace_preserves_store_and_cleans_temporary(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        with patch("mykeytool.os.replace", side_effect=PermissionError("Acceso denegado")):
            result, output, errors = self.generate(alias="segunda")
        self.assertEqual(result, 1)
        self.assertIn("Acceso denegado", errors)
        self.assertNotIn("Exito", output)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_custom_key_password_is_required_to_load_private_key(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-alias",
                "mykey",
                "-storepass",
                self.password,
                "-keypass",
                "other-password-123",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-dname",
                "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES",
            ])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(
                entry["private_key"].encode("ascii"), password=None
            )
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=b"other-password-123"
        )
        self.assertEqual(private.key_size, 2048)

    def test_certreq_generates_valid_pem_with_expected_subject_and_public_key(self):
        self.assertEqual(self.generate()[0], 0)
        csr_path = self.path.with_suffix(".csr")
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "--certreq",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-storepass",
                self.password,
                "-keypass",
                self.password,
                "-file",
                str(csr_path),
            ])

        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("Exito", output.getvalue())
        self.assertNotIn(self.password, output.getvalue() + errors.getvalue())
        pem = csr_path.read_bytes()
        self.assertTrue(
            pem.startswith(b"-----BEGIN NEW CERTIFICATE REQUEST-----\n")
        )
        self.assertTrue(pem.endswith(b"-----END NEW CERTIFICATE REQUEST-----\n"))
        self.assertNotIn(b"PRIVATE KEY", pem)

        lines = pem.splitlines()
        encoded_lines = lines[1:-1]
        self.assertTrue(encoded_lines)
        self.assertTrue(all(len(line) == 64 for line in encoded_lines[:-1]))
        self.assertLessEqual(len(encoded_lines[-1]), 64)
        der = base64.b64decode(b"".join(encoded_lines), validate=True)

        csr = x509.load_pem_x509_csr(pem)
        self.assertEqual(der, csr.public_bytes(serialization.Encoding.DER))
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(csr.signature_hash_algorithm.name, "sha256")
        expected_subject = {
            NameOID.COMMON_NAME: "Ana",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "TI",
            NameOID.ORGANIZATION_NAME: "Empresa",
            NameOID.LOCALITY_NAME: "Madrid",
            NameOID.STATE_OR_PROVINCE_NAME: "Madrid",
            NameOID.COUNTRY_NAME: "ES",
        }
        for oid, expected in expected_subject.items():
            self.assertEqual(csr.subject.get_attributes_for_oid(oid)[0].value, expected)

        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        stored_public = serialization.load_pem_public_key(
            entry["public_key"].encode("ascii")
        )
        self.assertEqual(
            csr.public_key().public_numbers(),
            stored_public.public_numbers(),
        )

    def test_certreq_prompts_for_store_password_alias_and_key_password(self):
        self.assertEqual(self.generate()[0], 0)
        csr_path = self.path.with_suffix(".csr")
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch(
                "mykeytool.getpass.getpass",
                side_effect=[self.password, ""],
            ) as getpass_mock,
            patch("builtins.input", side_effect=["miClave"]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-certreq",
                "-keystore",
                str(self.path),
                "-file",
                str(csr_path),
            ])

        self.assertEqual(result, 0, errors.getvalue())
        self.assertEqual(getpass_mock.call_count, 2)
        self.assertTrue(csr_path.exists())

    def test_certreq_fails_after_one_wrong_store_password(self):
        self.assertEqual(self.generate()[0], 0)
        csr_path = self.path.with_suffix(".csr")
        errors = io.StringIO()
        with (
            patch(
                "mykeytool.getpass.getpass",
                return_value="wrong-password",
            ) as getpass_mock,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-certreq",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-file",
                str(csr_path),
            ])

        self.assertEqual(result, 1)
        self.assertEqual(getpass_mock.call_count, 1)
        self.assertIn("incorrecta", errors.getvalue())
        self.assertNotIn("Intentos restantes", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertFalse(csr_path.exists())

    def test_certreq_uses_alias_csr_as_default_output(self):
        self.assertEqual(resolve_output_path(None, "miClave"), Path("miClave.csr"))
        self.assertEqual(
            resolve_output_path(None, "equipo/produccion"),
            Path("equipo_produccion.csr"),
        )
        self.assertEqual(
            resolve_output_path(Path("peticion.pem"), "miClave"),
            Path("peticion.pem"),
        )

    def test_certreq_rejects_missing_alias_without_creating_output(self):
        self.assertEqual(self.generate()[0], 0)
        csr_path = self.path.with_suffix(".csr")
        before = self.path.read_bytes()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-certreq",
                "-keystore",
                str(self.path),
                "-alias",
                "no-existe",
                "-storepass",
                self.password,
                "-file",
                str(csr_path),
            ])
        self.assertEqual(result, 1)
        self.assertIn("No existe el alias 'no-existe'", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertFalse(csr_path.exists())
        self.assertEqual(self.path.read_bytes(), before)

    def test_certreq_rejects_wrong_store_password_without_traceback(self):
        self.assertEqual(self.generate()[0], 0)
        csr_path = self.path.with_suffix(".csr")
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-certreq",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-storepass",
                "wrong-password",
                "-file",
                str(csr_path),
            ])
        self.assertEqual(result, 1)
        self.assertIn("incorrecta", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertFalse(csr_path.exists())

    def test_certreq_rejects_wrong_alias_password_without_private_key_leak(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            generated = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-storepass",
                self.password,
                "-keypass",
                "other-password-123",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-dname",
                "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES",
            ])
        self.assertEqual(generated, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        with self.assertRaisesRegex(KeyPasswordError, "Contrasena incorrecta"):
            load_private_key(
                entry, "miClave", self.password, "wrong-key-password"
            )

        csr_path = self.path.with_suffix(".csr")
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-certreq",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-storepass",
                self.password,
                "-keypass",
                "wrong-key-password",
                "-file",
                str(csr_path),
            ])
        self.assertEqual(result, 1)
        self.assertIn("alias 'miClave'", errors.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue() + errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertFalse(csr_path.exists())

    def test_certreq_reports_missing_or_damaged_keystore(self):
        csr_path = self.path.with_suffix(".csr")
        for content, expected in [(None, "No existe"), (b"broken", "Formato")]:
            with self.subTest(expected=expected):
                if content is not None:
                    self.path.write_bytes(content)
                errors = io.StringIO()
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(errors),
                ):
                    result = mykeytool.main([
                        "-certreq",
                        "-keystore",
                        str(self.path),
                        "-alias",
                        "miClave",
                        "-storepass",
                        self.password,
                        "-file",
                        str(csr_path),
                    ])
                self.assertEqual(result, 1)
                self.assertIn(expected, errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
                self.assertFalse(csr_path.exists())

    def test_changealias_renames_entry_without_touching_private_key(self):
        self.assertEqual(self.generate()[0], 0)
        entries = mykeytool.load_keystore(self.path, self.password)
        entries["miClave"]["certificate"] = "associated-certificate"
        mykeytool.save_keystore(self.path, self.password, entries)
        original_entry = mykeytool.load_keystore(self.path, self.password)["miClave"]

        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch(
                "keytool.certreq.serialization.load_pem_private_key",
                side_effect=AssertionError(
                    "changealias must not decrypt private keys"
                ),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "--changealias",
                "-keystore",
                str(self.path),
                "-storepass",
                self.password,
                "-alias",
                "miClave",
                "-destalias",
                "nuevaClave",
            ])

        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("Exito", output.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue() + errors.getvalue())
        renamed_entries = mykeytool.load_keystore(self.path, self.password)
        self.assertNotIn("miClave", renamed_entries)
        self.assertEqual(renamed_entries["nuevaClave"], original_entry)

    def test_changealias_prompts_for_aliases_when_omitted(self):
        self.assertEqual(self.generate()[0], 0)
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", return_value=self.password),
            patch("builtins.input", side_effect=["miClave", "nuevaClave"]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["-changealias", "-keystore", str(self.path)])

        self.assertEqual(result, 0, errors.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue() + errors.getvalue())
        entries = mykeytool.load_keystore(self.path, self.password)
        self.assertIn("nuevaClave", entries)
        self.assertNotIn("miClave", entries)

    def test_changealias_rejects_missing_or_duplicate_alias_without_changes(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        for source, destination, message in [
            ("missing", "newAlias", "No existe el alias 'missing'"),
            ("miClave", "miClave", "ya existe"),
        ]:
            with self.subTest(source=source, destination=destination):
                output = io.StringIO()
                errors = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                ):
                    result = mykeytool.main([
                        "-changealias",
                        "-keystore",
                        str(self.path),
                        "-storepass",
                        self.password,
                        "-alias",
                        source,
                        "-destalias",
                        destination,
                    ])
                self.assertEqual(result, 1)
                self.assertIn(message, errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
                self.assertNotIn("PRIVATE KEY", output.getvalue() + errors.getvalue())
                self.assertEqual(self.path.read_bytes(), before)

    def test_changealias_rejects_empty_destination_without_changes(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-changealias",
                "-keystore",
                str(self.path),
                "-storepass",
                self.password,
                "-alias",
                "miClave",
                "-destalias",
                "  ",
            ])

        self.assertEqual(result, 1)
        self.assertIn("alias de destino no puede estar vacio", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_changealias_wrong_store_password_preserves_file_without_traceback(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", return_value="wrong-password") as password_prompt,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-changealias",
                "-keystore",
                str(self.path),
                "-alias",
                "miClave",
                "-destalias",
                "nuevaClave",
            ])

        self.assertEqual(result, 1)
        self.assertEqual(password_prompt.call_count, 1)
        self.assertIn("incorrecta", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue() + errors.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_shows_certreq_help(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["--certreq", "--help"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Optional for -certreq", errors.getvalue())
        self.assertIn("-file FILE", errors.getvalue())

    def test_shows_changealias_help(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["--changealias", "--help"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("-destalias DESTALIAS", errors.getvalue())

if __name__ == "__main__":
    unittest.main()
