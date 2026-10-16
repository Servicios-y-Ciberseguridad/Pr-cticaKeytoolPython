import contextlib
import getpass
import io
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import mykeytool
from keytool.errors import KeystoreAuthenticationError
from keytool.genkeypair import build_self_signed_certificate, read_store_password
from keytool.keystore import (
    DN_FIELDS,
    STORE_HEADER,
    STORE_NONCE_SIZE,
    STORE_SALT_SIZE,
    KeyEntry,
    derive_store_key,
    load_keystore,
    save_keystore,
)


class StorePasswordTests(unittest.TestCase):
    password = "original-store-password"
    new_password = "replacement-store-password"
    key_password = "independent-key-password"

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        dn = dict(zip(DN_FIELDS, ["Ana", "TI", "Empresa", "Madrid", "Madrid", "ES"]))
        certificate = build_self_signed_certificate(cls.private_key, dn).public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii")
        cls.entries = {
            alias: KeyEntry(
                private_key=cls.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(password.encode()),
                ).decode("ascii"),
                public_key=public_pem,
                dn=dn,
                certificate=certificate,
            )
            for alias, password in (
                ("same-as-original-store", cls.password),
                ("independent", cls.key_password),
            )
        }

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "test.myks"
        save_keystore(self.path, self.password, self.entries)
        self.before = self.path.read_bytes()

    def run_command(self, *options, command="-storepasswd"):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            patch("builtins.input", side_effect=AssertionError("Unexpected echoed input")),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                side_effect=AssertionError("Must not decrypt individual keys"),
            ),
        ):
            result = mykeytool.main([command, "-keystore", str(self.path), *options])
        combined = output.getvalue() + errors.getvalue()
        for secret in (self.password, self.new_password, self.key_password, "PRIVATE KEY"):
            self.assertNotIn(secret, combined)
        self.assertNotIn("Traceback", combined)
        return result, output.getvalue(), errors.getvalue()

    def assert_unchanged(self, result, message):
        code, output, errors = result
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn(message, errors)
        self.assertEqual(self.path.read_bytes(), self.before)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_changes_password_and_preserves_all_entries_and_key_passwords(self):
        for command in ("-storepasswd", "--storepasswd"):
            with self.subTest(command=command):
                save_keystore(self.path, self.password, self.entries)
                before = self.path.read_bytes()
                with patch("getpass.getpass", side_effect=AssertionError("Unexpected prompt")):
                    result = self.run_command(
                        "-storepass", self.password, "-new", self.new_password,
                        command=command,
                    )
                self.assertEqual(result[0], 0, result[2])
                self.assertIn("Exito", result[1])
                entries = load_keystore(self.path, self.new_password)
                self.assertEqual(entries, self.entries)
                with self.assertRaises(KeystoreAuthenticationError):
                    load_keystore(self.path, self.password)
                after = self.path.read_bytes()
                salt_start = len(STORE_HEADER)
                nonce_start = salt_start + STORE_SALT_SIZE
                ciphertext_start = nonce_start + STORE_NONCE_SIZE
                self.assertNotEqual(
                    before[salt_start:nonce_start], after[salt_start:nonce_start]
                )
                self.assertNotEqual(
                    before[nonce_start:ciphertext_start], after[nonce_start:ciphertext_start]
                )
                self.assertNotEqual(before[ciphertext_start:], after[ciphertext_start:])
                self.assertNotEqual(
                    derive_store_key(self.password, before[salt_start:nonce_start]),
                    derive_store_key(self.new_password, after[salt_start:nonce_start]),
                )
                for alias, password in (
                    ("same-as-original-store", self.password),
                    ("independent", self.key_password),
                ):
                    private = serialization.load_pem_private_key(
                        entries[alias]["private_key"].encode("ascii"),
                        password.encode(),
                    )
                    self.assertEqual(
                        private.private_numbers(), self.private_key.private_numbers()
                    )

    def test_prompts_for_current_password_and_new_password_twice(self):
        with patch(
            "getpass.getpass",
            side_effect=[self.password, self.new_password, self.new_password],
        ) as prompt:
            result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(prompt.call_count, 3)
        self.assertEqual(load_keystore(self.path, self.new_password), self.entries)

    def test_supplied_current_password_only_prompts_for_new_password(self):
        with patch(
            "getpass.getpass", side_effect=[self.new_password, self.new_password]
        ) as prompt:
            result = self.run_command("-storepass", self.password)
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(prompt.call_count, 2)

    def test_wrong_current_password_is_attempted_once_before_new_password_prompt(self):
        with (
            patch("getpass.getpass", return_value="incorrect-current-password") as prompt,
            patch("keytool.storepasswd.load_keystore", wraps=load_keystore) as load,
        ):
            result = self.run_command()
        self.assert_unchanged(result, "incorrecta")
        prompt.assert_called_once()
        load.assert_called_once_with(self.path, "incorrect-current-password")

    def test_wrong_supplied_current_password_does_not_prompt(self):
        with patch("getpass.getpass", side_effect=AssertionError("Unexpected prompt")):
            result = self.run_command("-storepass", "incorrect-current-password")
        self.assert_unchanged(result, "incorrecta")

    def test_confirmation_mismatch_preserves_original(self):
        with patch("getpass.getpass", side_effect=[self.new_password, "mismatch"]):
            result = self.run_command("-storepass", self.password)
        self.assert_unchanged(result, "no coinciden")

    def test_same_password_is_rejected_without_writing(self):
        for interactive in (False, True):
            with self.subTest(interactive=interactive):
                options = ["-storepass", self.password]
                if not interactive:
                    options.extend(["-new", self.password])
                with (
                    patch("getpass.getpass", side_effect=[self.password, self.password]) as prompt,
                    patch("keytool.storepasswd.save_keystore") as save,
                ):
                    result = self.run_command(*options)
                self.assert_unchanged(result, "debe ser distinta de la actual")
                self.assertEqual(prompt.call_count, 1 if interactive else 0)
                save.assert_not_called()

    def test_new_password_has_same_length_rules_as_creation(self):
        for password, message in (
            ("", "vacia"), ("1234567", "al menos 8"), ("12345678", None)
        ):
            with self.subTest(length=len(password)):
                if message:
                    with self.assertRaisesRegex(ValueError, message):
                        read_store_password(self.path.parent / "missing.myks", password)
                    result = self.run_command(
                        "-storepass", self.password, "-new", password
                    )
                    self.assert_unchanged(result, message)
                else:
                    self.assertEqual(
                        read_store_password(self.path.parent / "missing.myks", password),
                        password,
                    )
                    result = self.run_command("-storepass", self.password, "-new", password)
                    self.assertEqual(result[0], 0, result[2])
                    self.assertEqual(load_keystore(self.path, password), self.entries)

    def test_invalid_interactive_new_password_is_not_retried(self):
        with patch("getpass.getpass", return_value="short") as prompt:
            result = self.run_command("-storepass", self.password)
        self.assert_unchanged(result, "al menos 8")
        prompt.assert_called_once()

    def test_atomic_replace_receives_complete_encrypted_file(self):
        import os

        replace = os.replace

        def inspect_replace(source, destination):
            self.assertEqual(destination, self.path)
            self.assertEqual(source.parent, self.path.parent)
            self.assertEqual(self.path.read_bytes(), self.before)
            self.assertEqual(load_keystore(source, self.new_password), self.entries)
            replace(source, destination)

        with patch("keytool.keystore.os.replace", side_effect=inspect_replace) as replace_mock:
            result = self.run_command(
                "-storepass", self.password, "-new", self.new_password
            )
        self.assertEqual(result[0], 0, result[2])
        replace_mock.assert_called_once()
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_write_errors_preserve_original_and_clean_temporary_files(self):
        for target in (
            "tempfile.NamedTemporaryFile", "os.fsync", "os.replace"
        ):
            with self.subTest(target=target):
                with patch(
                    f"keytool.keystore.{target}",
                    side_effect=PermissionError(f"Sensitive context: {self.new_password}"),
                ):
                    result = self.run_command(
                        "-storepass", self.password, "-new", self.new_password
                    )
                self.assert_unchanged(result, "no se pudo leer o guardar")

    def test_partial_write_preserves_original_and_cleans_temporary_file(self):
        temporary = tempfile.NamedTemporaryFile(dir=self.path.parent, delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        self.addCleanup(temporary.close)
        write = temporary.write

        def partial_write(data):
            write(data[:len(data) // 2])
            raise OSError("Disk full")

        with (
            patch("keytool.keystore.tempfile.NamedTemporaryFile", return_value=temporary),
            patch.object(temporary, "write", side_effect=partial_write),
        ):
            result = self.run_command(
                "-storepass", self.password, "-new", self.new_password
            )
        self.assert_unchanged(result, "no se pudo leer o guardar")

    def test_cancellation_at_each_prompt_preserves_original(self):
        for interruption in (EOFError, KeyboardInterrupt):
            for prior_answers in ([], [self.password], [self.password, self.new_password]):
                with self.subTest(interruption=interruption, prompt=len(prior_answers)):
                    with patch("getpass.getpass", side_effect=[*prior_answers, interruption]):
                        result = self.run_command()
                    self.assert_unchanged(result, "cancelada")

    def test_insecure_terminal_is_rejected_before_echo(self):
        def insecure_getpass(prompt):
            warnings.warn("No secure terminal", getpass.GetPassWarning)
            self.fail("Insecure fallback must not be used")

        with patch("getpass.getpass", side_effect=insecure_getpass):
            result = self.run_command()
        self.assert_unchanged(result, "ocultar")

    def test_empty_current_password_preserves_original(self):
        result = self.run_command("-storepass", "", "-new", self.new_password)
        self.assert_unchanged(result, "vacia")

    def test_missing_store_is_not_created(self):
        self.path.unlink()
        with patch("getpass.getpass", side_effect=AssertionError("Unexpected prompt")):
            result = self.run_command("-storepass", self.password)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], "")
        self.assertFalse(self.path.exists())

    def test_invalid_store_is_not_modified(self):
        self.before = b"not a keystore"
        self.path.write_bytes(self.before)
        result = self.run_command("-storepass", self.password, "-new", self.new_password)
        self.assert_unchanged(result, "Formato")

    def test_empty_keystore_can_change_password(self):
        save_keystore(self.path, self.password, {})
        result = self.run_command("-storepass", self.password, "-new", self.new_password)
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(load_keystore(self.path, self.new_password), {})

    def test_help_lists_command_and_options_without_prompting(self):
        for command in ("-storepasswd", "--storepasswd"):
            with self.subTest(command=command):
                with patch("getpass.getpass", side_effect=AssertionError("Unexpected prompt")):
                    result = self.run_command("--help", command=command)
                self.assertEqual(result[0], 0)
                for option in ("-keystore KEYSTORE", "-storepass STOREPASS", "-new NEW_PASSWORD"):
                    self.assertIn(option, result[2])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(mykeytool.main([]), 0)
        self.assertIn("-storepasswd, --storepasswd", output.getvalue())


if __name__ == "__main__":
    unittest.main()
