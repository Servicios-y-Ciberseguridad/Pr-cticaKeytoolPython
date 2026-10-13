"""Implementacion modular del simulador de Java Keytool."""

from .storage.keystore import load_keystore_entry

__all__ = ["load_keystore_entry"]