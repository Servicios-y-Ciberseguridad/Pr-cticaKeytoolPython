import contextlib
import getpass
import io
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import mykeytool
from keytool.keystore import DN_FIELDS, KeyEntry, load_keystore, save_keystore


class DeleteKeyTests(unittest.TestCase):
    password = "delete-store-password"
    entries = {
        alias: KeyEntry(
            private_key=f"private material for {alias}",
            public_key=f"public material for {alias}",
            dn=dict(zip(DN_FIELDS, ["Ana", "TI", "Empresa", "Madrid", "Madrid", "ES"])),
        )
        for alias in ("remove-me", "keep-me")
    }

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "test.myks"
        save_keystore(self.path, self.password, self.entries)
        self.before = self.path.read_bytes()

    def run_command(self, *options, command="-delete"):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                side_effect=AssertionError("Deleting an entry must not decrypt its key"),
            ),
        ):
            result = mykeytool.main([
                command, "-keystore", str(self.path), *options,
            ])
        combined = output.getvalue() + errors.getvalue()
        for secret in (self.password, "private material", "public material"):
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

    def test_deletes_requested_entry_and_preserves_remaining_entries(self):
        for command in ("-delete", "--delete"):
            with self.subTest(command=command):
                save_keystore(self.path, self.password, self.entries)
                result = self.run_command(
                    "-alias", " remove-me ", "-storepass", self.password,
                    command=command,
                )
                self.assertEqual(result[0], 0, result[2])
                self.assertIn("Exito: alias 'remove-me' eliminado", result[1])
                self.assertEqual(
                    load_keystore(self.path, self.password),
                    {"keep-me": self.entries["keep-me"]},
                )

    def test_deleting_last_entry_leaves_a_valid_empty_keystore(self):
        save_keystore(self.path, self.password, {"remove-me": self.entries["remove-me"]})
        result = self.run_command(
            "-alias", "remove-me", "-storepass", self.password
        )
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(load_keystore(self.path, self.password), {})

    def test_prompts_for_store_password_and_alias_when_omitted(self):
        with (
            patch("getpass.getpass", return_value=self.password) as password_prompt,
            patch("builtins.input", return_value="remove-me") as alias_prompt,
        ):
            result = self.run_command()
        self.assertEqual(result[0], 0, result[2])
        password_prompt.assert_called_once()
        alias_prompt.assert_called_once_with("Enter key alias: ")
        self.assertEqual(
            load_keystore(self.path, self.password),
            {"keep-me": self.entries["keep-me"]},
        )

    def test_missing_alias_is_reported_without_modifying_store(self):
        self.assert_unchanged(
            self.run_command(
                "-alias", "unknown", "-storepass", self.password
            ),
            "No existe el alias 'unknown'",
        )

    def test_blank_alias_is_rejected_without_modifying_store(self):
        self.assert_unchanged(
            self.run_command("-alias", " ", "-storepass", self.password),
            "alias no puede estar vacio",
        )

    def test_wrong_password_is_reported_without_modifying_store(self):
        self.assert_unchanged(
            self.run_command("-alias", "remove-me", "-storepass", "wrong-password"),
            "incorrecta",
        )

    def test_missing_store_is_reported_without_prompting(self):
        self.path.unlink()
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            patch("getpass.getpass", side_effect=AssertionError("Unexpected prompt")),
        ):
            result = mykeytool.main([
                "-delete", "-keystore", str(self.path), "-alias", "remove-me",
            ])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("No existe el KeyStore", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_password_prompt_warning_is_reported(self):
        def warn_without_secure_input(prompt):
            warnings.warn(
                f"No secure terminal while requesting {prompt}",
                getpass.GetPassWarning,
            )

        with patch("getpass.getpass", side_effect=warn_without_secure_input):
            self.assert_unchanged(
                self.run_command("-alias", "remove-me"),
                "no hay un terminal disponible",
            )

    def test_interrupted_alias_prompt_does_not_modify_store(self):
        for interruption in (EOFError, KeyboardInterrupt):
            with self.subTest(interruption=interruption):
                with patch("builtins.input", side_effect=interruption):
                    result = self.run_command("-storepass", self.password)
                self.assert_unchanged(result, "operacion cancelada")


if __name__ == "__main__":
    unittest.main()
