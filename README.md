# Práctica Keytool en Python

Este proyecto consiste en una implementación en Python de una herramienta similar a `keytool`, la utilidad de Java para gestionar claves y certificados digitales.

La idea de la práctica es aprender a trabajar con criptografía, generación de claves, y manejo básico de certificados en un entorno CLI.

## Objetivo

Crear un programa Python que permita:

- Generar pares de claves pública/privada.
- Almacenar claves con alias identificativos.
- Generar solicitudes de firma de certificado (CSR) en formato PEM.
- Consultar desde Python la información de una entrada del KeyStore.
- Simular funcionalidades básicas de `keytool` en un entorno de consola.

## Requisitos

- Python 3.10 o superior
- pip
- Entorno virtual recomendado
- En Windows, usa el Python oficial de python.org para crear el entorno virtual

## Instalación

1. Clona o descarga este repositorio.
2. Crea un entorno virtual con el Python oficial de Windows:

```bash
py -3.14 -m venv .venv
```

3. Activa el entorno virtual:

- Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

- Windows (CMD):

```cmd
.venv\Scripts\activate.bat
```

4. Instala las dependencias:

```bash
pip install -r requirements.txt
```

La dependencia principal también puede instalarse directamente con:

```bash
pip install cryptography
```

Si ya tienes un entorno creado con MSYS2 o MinGW, recrealo con el Python oficial de Windows para poder instalar `cryptography` sin errores de compatibilidad.

## Dependencias

Este proyecto usa la librería `cryptography`, que permite generar claves, certificados y manejar operaciones criptográficas modernas de forma segura.

## Estructura del proyecto

```text
Pr-cticaKeytoolPython/
├── mykeytool.py          # CLI y enrutamiento de comandos
├── genkeypair.py         # Generacion RSA y flujo interactivo
├── keystore.py           # Cifrado, lectura y escritura del KeyStore
├── certreq.py            # Comando de solicitudes CSR
├── tests/
│   └── test_mykeytool.py
├── README.md             # Documentación del proyecto
├── requirements.txt      # Dependencias del proyecto
├── .venv/               # Entorno virtual recomendado
├── env/                 # Entorno virtual antiguo (opcional)
└── .gitignore           # Archivos ignorados por Git
```

### Explicación sencilla de la arquitectura

El programa está separado por responsabilidades para que el flujo sea fácil de
seguir y cada archivo tenga una única función:

1. `mykeytool.py` actúa como fachada: interpreta los argumentos, comprueba la
   dependencia criptográfica y decide qué comando ejecutar.
2. `genkeypair.py` recoge los datos, genera el par RSA y prepara la entrada.
3. `certreq.py` recupera una entrada existente, firma el CSR y exporta el PEM.
4. `keystore.py` cifra, valida, lee y escribe el almacén.

El recorrido de `--certreq` se puede explicar en tres pasos:

```text
contraseña + alias → entrada cifrada → CSR firmado → archivo .csr PEM
```

Hay dos contraseñas con objetivos distintos: `storepass` permite descifrar el
almacén completo y `keypass` permite usar la clave privada de un alias. La clave
privada solo se mantiene en memoria el tiempo necesario para firmar y nunca se
escribe en el CSR.

## Uso previsto

Si ejecutas el programa sin parametros, muestra solo los comandos disponibles:

```bash
python mykeytool.py
```

Para ver la ayuda especifica de `genkeypair`, usa:

```bash
python mykeytool.py -genkeypair -h
python mykeytool.py -genkeypair --help
```

La ayuda específica de `certreq` muestra sus opciones compatibles con el estilo de
`keytool`:

```bash
python mykeytool.py -certreq --help
```

El flujo mas simple para generar un par de claves es:

```bash
python mykeytool.py --genkeypair -keyalg RSA
python mykeytool.py --certreq -keystore keystore.myks
```

Tambien admite una sintaxis parecida a `keytool` para `genkeypair`:

```bash
python mykeytool.py -genkeypair -alias mykey -keyalg RSA -keysize 2048 -dname "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES"
```

Para generar un CSR a partir de una entrada existente:

```bash
python mykeytool.py -certreq -keystore keystore.myks -alias mykey -file mykey.csr
```

Si se omiten `-storepass`, `-alias` o `-keypass`, el programa los solicita de
forma interactiva. Al pulsar Enter en la contraseña de la clave se reutiliza la
del KeyStore. `-file` admite las extensiones `.csr` y `.pem`; si se omite, la
salida se llama `<alias>.csr`.

El CSR se firma con SHA-256 y la clave privada RSA del alias. Se exporta como
PKCS#10 en Base64 PEM compatible con `keytool -certreq -rfc`, con las cabeceras
`BEGIN NEW CERTIFICATE REQUEST` y `END NEW CERTIFICATE REQUEST`. El relleno final
`=` o `==` aparece solamente cuando corresponde a la longitud de los datos
binarios. Contiene el DN y la clave pública, pero nunca incluye la clave privada.
La contraseña del KeyStore,
la contraseña de la clave, un alias inexistente y un almacén inexistente o dañado
se notifican como errores controlados, sin mostrar una traza.

Los errores esperados tienen clases específicas derivadas de `KeytoolError`
(`KeystoreAuthenticationError`, `KeyPasswordError`, `DuplicateAliasError`,
`KeystoreNotFoundError`, `InvalidKeystoreError` y `AliasNotFoundError`).
Cuando la autenticación criptográfica falla, el programa indica que la contraseña
puede ser incorrecta o que el almacén pudo ser alterado, ya que ambas causas no se
pueden distinguir de forma fiable.

La contraseña del KeyStore dispone de un único intento por ejecución, tanto en
`genkeypair` como en `certreq`. Si es incorrecta, el programa termina con un error
controlado y es necesario ejecutar de nuevo el comando.

`--genkeypair` y `-genkeypair` aceptan parametros estilo `keytool`, pero tambien completan por consola los que falten. En el flujo interactivo actual se solicitan, segun falten:

- `keyalg`
- `keysize` con valor por defecto `2048`; admite `2048`, `3072`, `4096`, `7680`
  y `15360`, y muestra estas opciones en el prompt
- contrasena del KeyStore
- contrasena de la clave (`RETURN` reutiliza la del KeyStore)
- alias con valor por defecto `mykey`
- DN: `CN`, `OU`, `O`, `L`, `ST` y `C`

En los campos interactivos del DN se puede pulsar `Enter` para dejar el valor vacio. En ese caso, el programa guarda `Unknown` en ese campo. Antes de crear el archivo, siempre muestra un resumen del DN y pide confirmacion final con `yes` o `no`.

Ejemplo de flujo interactivo:

```text
> python mykeytool.py -genkeypair -keyalg RSA
Enter key size (2048, 3072, 4096, 7680, 15360) [2048]:
Enter keystore password:
Re-enter new password:
Enter key alias [mykey]:
Enter key password for <mykey> (RETURN if same as keystore password):
What is your first and last name? [Unknown]:
What is the name of your organizational unit? [Unknown]:
What is the name of your organization? [Unknown]:
What is the name of your City or Locality? [Unknown]:
What is the name of your State or Province? [Unknown]:
What is the two-letter country code for this unit? [Unknown]:
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct? [no/yes]: no
What is your first and last name? [Unknown]: Ana Perez
What is the name of your organizational unit? [Unknown]: Seguridad
What is the name of your organization? [Unknown]: Empresa
What is the name of your City or Locality? [Unknown]: Madrid
What is the name of your State or Province? [Unknown]: Madrid
What is the two-letter country code for this unit? [Unknown]: ES
Is CN=Ana Perez, OU=Seguridad, O=Empresa, L=Madrid, ST=Madrid, C=ES correct? [no/yes]: yes
Exito: par RSA de 2048 bits guardado con alias 'mykey' en 'keystore.myks'.
```

La clave privada se guarda cifrada con `keypass`. Si `python` apunta a un interprete sin `cryptography`, el script intentara reejecutarse automaticamente con `.venv`.

### Formato y recuperación del KeyStore

El archivo binario tiene una versión identificada por su cabecera y esta distribución:

```text
MYKEYSTORE\x01 | sal aleatoria de 16 bytes | nonce de 12 bytes | ciphertext y etiqueta GCM
```

El contenido cifrado es un objeto JSON UTF-8 con las entradas indexadas por alias. La clave de cifrado se deriva de la contraseña del almacén con Scrypt; AES-GCM cifra y autentica el contenido usando la cabecera como dato autenticado. El formato se versiona cambiando la cabecera si en el futuro cambia su estructura o sus parámetros.

Para recuperar una entrada desde otro código Python, `load_keystore_entry` autentica y descifra el almacén y devuelve los datos asociados al alias. La contraseña del almacén no se guarda en el archivo:

```python
from getpass import getpass
from pathlib import Path

from mykeytool import load_keystore_entry

store_password = getpass("Contraseña del KeyStore: ")
entry = load_keystore_entry(Path("keystore.myks"), "mykey", store_password)
print(entry["dn"])
```

El campo `private_key` que devuelve la función sigue cifrado con `keypass`. Para usar la clave privada, se necesita además esa contraseña (o la del almacén si se eligió reutilizarla):

```python
from cryptography.hazmat.primitives import serialization
from getpass import getpass

key_password = getpass("Contraseña de la clave: ")
private_key = serialization.load_pem_private_key(
    entry["private_key"].encode("ascii"),
    password=key_password.encode("utf-8"),
)
```

El cargador informa con `FileNotFoundError` si el almacén no existe y con `ValueError` si el formato, el contenido o la autenticación no son válidos. No uses `-storepass` ni `-keypass` en comandos compartidos: aunque no se guardan en el KeyStore, los argumentos de línea de comandos pueden quedar en el historial o ser visibles para otros procesos. Es más seguro omitirlos y escribir las contraseñas cuando el programa las solicite.

Si quieres forzar manualmente el interprete del entorno virtual, usa:

```powershell
.\.venv\Scripts\python.exe .\mykeytool.py --genkeypair -keyalg RSA
```

## Matriz de pruebas ejecutadas

| Área | Verificación automatizada | Resultado esperado |
|---|---|---|
| `genkeypair` | RSA 2048/3072/4096, DN, alias duplicado y persistencia cifrada | La entrada se crea sin exponer secretos |
| KeyStore | Contraseña correcta/incorrecta, formato inválido, manipulación y archivo inexistente | Acceso autenticado o error controlado |
| `certreq` | CSR PEM, firma SHA-256, sujeto DN y coincidencia de clave pública | CSR válido y firmado por la clave del alias |
| Privacidad | Inspección del PEM y de los mensajes de consola | No aparece ninguna clave privada ni contraseña |
| Errores de CSR | Alias inexistente, contraseña de almacén/clave incorrecta y almacén dañado | Código de salida 1, sin traceback ni archivo parcial |
| CLI | Ayuda general y ayuda específica de ambos comandos | Opciones y sintaxis visibles |

La suite completa se ejecuta con:

```bash
python -m unittest discover -s tests -v
```

## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
