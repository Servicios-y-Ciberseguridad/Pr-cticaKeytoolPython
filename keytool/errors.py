"""Errores de dominio para las operaciones del KeyStore."""


class KeytoolError(Exception):
    """Error esperado que puede comunicarse directamente al usuario."""


class KeystoreNotFoundError(FileNotFoundError, KeytoolError):
    """El archivo KeyStore no existe al intentar abrirlo."""


class KeystoreAuthenticationError(KeytoolError, ValueError):
    """La contraseña del KeyStore es incorrecta o sus datos fueron alterados."""


class InvalidKeystoreError(KeytoolError, ValueError):
    """El formato o contenido descifrado del KeyStore no es válido."""


class DuplicateAliasError(KeytoolError, ValueError):
    """El alias ya está presente en el KeyStore."""


class AliasNotFoundError(KeytoolError, ValueError):
    """El alias solicitado no está presente en el KeyStore."""


class KeyPasswordError(KeytoolError, ValueError):
    """No se pudo descifrar la clave privada con la contraseña proporcionada."""
