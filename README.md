# Práctica Keytool en Python

Este proyecto consiste en una implementación en Python de una herramienta similar a `keytool`, la utilidad de Java para gestionar claves y certificados digitales.

La idea de la práctica es aprender a trabajar con criptografía, generación de claves, y manejo básico de certificados en un entorno CLI.

## Objetivo

Crear un programa Python que permita:

- Generar pares de claves pública/privada.
- Almacenar claves con alias identificativos.
<<<<<<< HEAD
=======
- Generar solicitudes de firma de certificado (CSR) en formato PEM.
- Firmar certificados X.509 desde solicitudes PKCS#10 en PEM o DER.
>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
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

<<<<<<< HEAD
=======
La dependencia principal también puede instalarse directamente con:

```bash
pip install cryptography
```

>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
Si ya tienes un entorno creado con MSYS2 o MinGW, recrealo con el Python oficial de Windows para poder instalar `cryptography` sin errores de compatibilidad.

## Dependencias

Este proyecto usa la librería `cryptography`, que permite generar claves, certificados y manejar operaciones criptográficas modernas de forma segura.

## Estructura del proyecto

```text
Pr-cticaKeytoolPython/
<<<<<<< HEAD
├── mykeytool.py          # CLI y enrutamiento de comandos
├── genkeypair.py         # Generacion RSA y flujo interactivo
├── keystore.py           # Cifrado, lectura y escritura del KeyStore
├── certreq.py            # Comando de solicitudes CSR
=======
├── mykeytool.py          # Punto de entrada compatible
├── keytool/              # Paquete de la aplicación
│   ├── __init__.py
│   ├── __main__.py       # Permite ejecutar python -m keytool
│   ├── start.py          # CLI y enrutamiento de comandos
│   ├── genkeypair.py     # Generacion RSA y flujo interactivo
│   ├── keystore.py       # Cifrado, lectura y escritura del KeyStore
│   ├── certreq.py        # Comando de solicitudes CSR
│   ├── gencert.py        # Emision X.509 a partir de un CSR
│   ├── changealias.py    # Cambio de alias de una entrada
│   ├── storepasswd.py    # Cambio de contrasena del almacen
│   ├── listing.py        # Listado autenticado de datos publicos
│   └── errors.py         # Errores de dominio
>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
├── tests/
│   └── test_mykeytool.py
├── README.md             # Documentación del proyecto
├── requirements.txt      # Dependencias del proyecto
├── .venv/               # Entorno virtual recomendado
├── env/                 # Entorno virtual antiguo (opcional)
└── .gitignore           # Archivos ignorados por Git
```

<<<<<<< HEAD
=======
### Explicación sencilla de la arquitectura

El código de la aplicación se agrupa en el paquete `keytool/` y las pruebas
permanecen en `tests/`. Cada módulo del paquete tiene una responsabilidad:

1. `keytool/start.py` interpreta argumentos y enruta los comandos.
2. `keytool/genkeypair.py` recoge los datos, genera el par RSA y prepara la entrada.
3. `keytool/certreq.py` recupera una entrada existente, firma el CSR y exporta el PEM.
4. `keytool/changealias.py` valida las entradas y solicita renombrar un alias.
5. `keytool/keystore.py` cifra, valida, lee y escribe el almacén.
6. `keytool/errors.py` define los errores de dominio compartidos.
7. `keytool/listing.py` lista alias y detalles públicos sin descifrar claves privadas.
8. `keytool/storepasswd.py` autentica y cambia la contraseña del almacén.
9. `keytool/gencert.py` valida el CSR y exporta un certificado firmado.

El archivo raíz `mykeytool.py` conserva el comando de ejecución existente. También
puedes iniciar la aplicación mediante `python -m keytool`.

El recorrido de `--certreq` se puede explicar en tres pasos:

```text
contraseña + alias → entrada cifrada → CSR firmado → archivo .csr PEM
```

Hay dos contraseñas con objetivos distintos: `storepass` permite descifrar el
almacén completo y `keypass` permite usar la clave privada de un alias. La clave
privada solo se mantiene en memoria el tiempo necesario para firmar y nunca se
escribe en el CSR.

>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
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

<<<<<<< HEAD
=======
La ayuda específica de `certreq` muestra sus opciones compatibles con el estilo de
`keytool`:

```bash
python mykeytool.py -certreq --help
```

>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
El flujo mas simple para generar un par de claves es:

```bash
python mykeytool.py --genkeypair -keyalg RSA
<<<<<<< HEAD
python mykeytool.py --certreq
```

=======
python mykeytool.py --certreq -keystore keystore.myks
python mykeytool.py --changealias -keystore keystore.myks -alias mykey -destalias nuevaClave
```

`-changealias` también admite `--changealias`. Si se omiten `-storepass`,
`-alias` o `-destalias`, los solicita de forma interactiva; la contraseña se
solicita sin eco. El cambio conserva todos los datos de la entrada, incluida la
clave privada en su forma cifrada y cualquier certificado asociado, sin pedir ni
descifrar la contraseña de la clave privada.

>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
Tambien admite una sintaxis parecida a `keytool` para `genkeypair`:

```bash
python mykeytool.py -genkeypair -alias mykey -keyalg RSA -keysize 2048 -dname "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES"
```

<<<<<<< HEAD
`--genkeypair` y `-genkeypair` aceptan parametros estilo `keytool`, pero tambien completan por consola los que falten. En el flujo interactivo actual se solicitan, segun falten:

- `keyalg`
- `keysize` con valor por defecto `2048`
=======
Cada nueva entrada incluye un certificado X.509 autofirmado en PEM, con el DN
como sujeto y emisor, número de serie aleatorio, firma RSA/SHA-256 y vigencia de
90 días desde su creación. No es un certificado de autoridad certificadora
(`CA=false`) ni proporciona confianza pública por sí mismo. Se guarda dentro
del KeyStore cifrado y `-list` muestra automáticamente su huella SHA-256.
La clave privada sigue cifrada con `keypass`.

Las entradas anteriores sin certificado siguen siendo compatibles; no se
modifican automáticamente. Para probarlo, genera un alias nuevo y consúltalo:

```bash
python -m keytool -genkeypair -alias nuevaClave -keyalg RSA -keysize 2048
python -m keytool -list -alias nuevaClave
python -m keytool -list -alias nuevaClave -v
```

### Emitir un certificado desde un CSR

```powershell
python -m keytool -certreq -alias solicitante -file solicitud.csr
python -m keytool -gencert -keystore keystore.myks -alias emisor -infile solicitud.csr -outfile certificado.der
python -m keytool --gencert -alias emisor -infile solicitud.csr -outfile certificado.pem -rfc -validity 365
python -m keytool -gencert --help
```

Los alias `solicitante` y `emisor` deben existir en sus respectivos almacenes.
El CSR también puede proceder de otra herramienta. Se admiten PKCS#10 en DER,
PEM estándar (`BEGIN CERTIFICATE REQUEST`) y PEM de keytool
(`BEGIN NEW CERTIFICATE REQUEST`). Se verifica la firma de la solicitud antes
de usarla; un CSR alterado o inválido no produce ningún certificado.

Argumentos de `-gencert` / `--gencert`:

| Argumento | Comportamiento |
|---|---|
| `-keystore KEYSTORE` | Almacén del firmante; por defecto `keystore.myks` |
| `-storepass STOREPASS` | Contraseña del almacén; si se omite, se solicita sin eco, con un único intento |
| `-alias ALIAS` | Alias firmante; si se omite, se solicita como en `-certreq` (Enter selecciona `mykey`) |
| `-keypass KEYPASS` | Contraseña de su clave privada; si se omite, se solicita sin eco y Enter reutiliza `storepass` |
| `-infile REQUEST` | CSR de entrada obligatorio |
| `-outfile CERTIFICATE` | Archivo de salida obligatorio, sin restricción de extensión |
| `-rfc` | Exporta PEM/Base64; si se omite, exporta DER binario |
| `-validity DAYS` | Entero positivo; por defecto **90 días** |

Es preferible omitir las contraseñas en la línea de comandos para evitar
exponerlas en el historial o a otros procesos.

El certificado conserva exactamente el sujeto y la clave pública del CSR. El
emisor es el **sujeto del certificado del alias firmante**; para entradas antiguas
sin certificado se usa su DN. Se comprueba que la clave privada, la pública
almacenada y la del certificado emisor correspondan al mismo par. El firmante
debe ser RSA y firma con SHA-256. Se asigna un número de serie aleatorio positivo
de hasta 159 bits. La validez comienza en la hora UTC de ejecución (sin
microsegundos) y termina exactamente `DAYS` días después; se rechazan fechas
fuera del intervalo admitido.

Las extensiones emitidas son:

- `BasicConstraints` crítica: `CA=false`, sin longitud de ruta.
- `KeyUsage` crítica: firma digital; también cifrado de clave para sujetos RSA.
  No permite firmar certificados ni CRL.
- `SubjectKeyIdentifier` y `AuthorityKeyIdentifier`, no críticas, derivados de
  las claves públicas del sujeto y del emisor.

No se copian automáticamente extensiones del CSR, ni siquiera SAN, usos de
clave o solicitudes de `CA=true`. Este perfil básico no sirve por sí solo para
emitir certificados TLS con nombres DNS ni certificados de autoridad.

Por compatibilidad con el flujo académico, se permite firmar con un alias sin
certificado CA o sin permiso `keyCertSign`, pero se muestra una advertencia.
**Una firma matemáticamente válida no equivale a una cadena de confianza
válida.** Los certificados autofirmados creados por `-genkeypair` son `CA=false`
y producirán esta advertencia. El comando no valida la cadena del emisor, su
confianza ni su periodo de validez; tampoco limita la validez emitida a la del
emisor. Para verificar una cadena real se necesita un emisor CA válido y
confiable, con permisos y fechas apropiados.

La salida se escribe de forma atómica y no puede sobrescribir el KeyStore ni el
CSR de entrada. Un fallo previo al reemplazo conserva cualquier archivo de
salida anterior. No se exportan claves privadas ni se modifica ninguna entrada
del almacén. El resultado es un archivo X.509 estándar reutilizable para una
futura importación o exportación: **esta operación no implementa `-exportcert`
ni almacena automáticamente el certificado generado**.

Con un emisor CA apropiado, se puede inspeccionar y verificar usando OpenSSL:

```powershell
openssl x509 -inform DER -in certificado.der -noout -subject -issuer -dates
openssl x509 -inform DER -in certificado.der -out certificado.pem
openssl verify -CAfile emisor-ca.pem certificado.pem
```

### Cambiar la contraseña del KeyStore

```bash
python mykeytool.py -storepasswd -keystore keystore.myks
python -m keytool --storepasswd -keystore keystore.myks
python mykeytool.py -storepasswd --help
```

`-storepasswd` / `--storepasswd` acepta `-keystore KEYSTORE`,
`-storepass STOREPASS` (contraseña actual) y `-new NEW_PASSWORD` (contraseña
nueva). Si se omite `-keystore`, se usa `keystore.myks`. Es preferible omitir las
contraseñas en la línea de comandos para evitar que queden en el historial o
sean visibles para otros procesos: la actual se solicita sin eco y la nueva,
dos veces sin eco para confirmarla. Con `-new`, no se solicita confirmación,
igual que al crear un almacén con `-storepass`.

Solo se permite un intento de autenticación por ejecución. La contraseña
actual se verifica antes de pedir la nueva, que debe tener al menos 8
caracteres, como al crear el almacén, y ser distinta de la contraseña actual.
Si se reutiliza la actual, se muestra un error inmediatamente después de
introducirla, sin pedir confirmación, y el archivo no se modifica.
El comando vuelve a cifrar y autenticar
todas las entradas con sal y nonce aleatorios nuevos y una nueva clave
derivada mediante Scrypt; no cambia el formato del archivo.

Las entradas, certificados y claves privadas cifradas se conservan intactos:
no se solicita ni se cambia ninguna contraseña individual de clave.
**Si una clave usaba la contraseña anterior del almacén, seguirá usando esa
contraseña anterior**, no la nueva.

El archivo se reemplaza de forma atómica solo después de escribir y
sincronizar el contenido completo. Una contraseña actual incorrecta, una
confirmación distinta, una cancelación o un fallo de escritura previo al
reemplazo conserva el archivo original. Un almacén inexistente no se crea.
Los errores se comunican sin mostrar contraseñas ni trazas.

### Consultar las entradas

```bash
python mykeytool.py -list -keystore keystore.myks
python mykeytool.py --list -keystore keystore.myks -alias mykey --verbose
python mykeytool.py -list -v
python mykeytool.py -list --help
```

`-list` / `--list` autentica el almacén antes de mostrar información. Acepta
`-storepass`, pero es preferible omitirlo para introducir la contraseña sin eco.
No solicita `keypass`, no descifra claves privadas ni modifica el archivo.
Sin `-alias`, muestra el número de entradas y todos los alias ordenados por su
texto (distinguiendo mayúsculas); un almacén vacío muestra
`Your keystore contains 0 entries`.
Con `-alias`, muestra únicamente esa entrada, o un error si no existe.
Los alias se representan sin comillas y los DN entre comillas, con escapes para
evitar que saltos de línea o caracteres de control alteren la salida.

La salida sigue el estilo de Java Keytool, pero identifica el formato propio
`MYKEYSTORE (version 1)` y la implementación `Python cryptography`, no PKCS12/SUN:

```text
Keystore type: MYKEYSTORE (version 1)
Keystore provider: Python cryptography

Your keystore contains 1 entry

mykey, creation date unavailable, PrivateKeyEntry,
Certificate fingerprint (SHA-256): unavailable (no certificate)
```

No se almacena una fecha de creación por entrada, por lo que se indica que no
está disponible; no se sustituye por la fecha del archivo ni la del certificado.
Si hay certificado, el listado básico muestra su huella SHA-256 en hexadecimal
mayúsculo separado por dos puntos. No se usa la huella de la clave pública como
si fuera la del certificado. `PrivateKeyEntry` identifica las entradas con clave
privada cifrada que admite actualmente este almacén.

`-v` / `--verbose` añade el DN, el algoritmo RSA y el tamaño en bits de la clave
pública. Si la entrada contiene `certificate` como certificado X.509 en PEM,
también muestra sujeto, emisor, número de serie, vigencia UTC, OID del algoritmo
de firma y huella SHA-256. Si no existe, indica que no está disponible.
Un certificado malformado genera un error incluso en modo básico, ya que no se
puede calcular su huella; una clave pública malformada genera un error en modo
detallado. No hay salida parcial. No se vuelcan entradas, claves privadas, contraseñas, salt, nonce ni
etiquetas de autenticación. Un alias inexistente, contraseña incorrecta o
almacén dañado produce código de salida 1 con un mensaje claro y sin traza.

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
>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
- contrasena del KeyStore
- contrasena de la clave (`RETURN` reutiliza la del KeyStore)
- alias con valor por defecto `mykey`
- DN: `CN`, `OU`, `O`, `L`, `ST` y `C`

En los campos interactivos del DN se puede pulsar `Enter` para dejar el valor vacio. En ese caso, el programa guarda `Unknown` en ese campo. Antes de crear el archivo, siempre muestra un resumen del DN y pide confirmacion final con `yes` o `no`.

Ejemplo de flujo interactivo:

```text
> python mykeytool.py -genkeypair -keyalg RSA
<<<<<<< HEAD
Enter key size [2048]:
=======
Enter key size (2048, 3072, 4096, 7680, 15360) [2048]:
>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
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

<<<<<<< HEAD
La clave privada se guarda cifrada con `keypass`. Si `python` apunta a un interprete sin `cryptography`, el script intentara reejecutarse automaticamente con `.venv`. `--certreq` sigue siendo un marcador para la siguiente fase del proyecto.
=======
La clave privada se guarda cifrada con `keypass`. Si `python` apunta a un interprete sin `cryptography`, el script intentara reejecutarse automaticamente con `.venv`.
>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7

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

<<<<<<< HEAD
=======
## Matriz de pruebas ejecutadas

| Área | Verificación automatizada | Resultado esperado |
|---|---|---|
| `genkeypair` | RSA 2048/3072/4096, DN, alias duplicado y persistencia cifrada | La entrada se crea sin exponer secretos |
| KeyStore | Contraseña correcta/incorrecta, formato inválido, manipulación y archivo inexistente | Acceso autenticado o error controlado |
| `certreq` | CSR PEM, firma SHA-256, sujeto DN y coincidencia de clave pública | CSR válido y firmado por la clave del alias |
| Privacidad | Inspección del PEM y de los mensajes de consola | No aparece ninguna clave privada ni contraseña |
| Errores de CSR | Alias inexistente, contraseña de almacén/clave incorrecta y almacén dañado | Código de salida 1, sin traceback ni archivo parcial |
| CLI | Ayuda general y ayuda específica de ambos comandos | Opciones y sintaxis visibles |
| `list` | Almacén vacío, varios alias, orden estable, filtro, detalles públicos y errores | Listado autenticado, solo lectura y sin secretos |
| `storepasswd` | Cambio correcto, reglas de longitud y confirmación, intento único, claves intactas y fallos de escritura/reemplazo | Contraseña nueva válida, anterior rechazada y archivo original conservado ante errores |
| `gencert` | Firma SHA-256, sujeto, emisor, validez, CSR PEM/DER, extensiones, errores y escritura atómica | X.509 verificable con cryptography y OpenSSL, sin claves privadas ni cambios en el almacén |

La suite completa se ejecuta con:

```bash
python -m unittest discover -s tests -v
```

>>>>>>> ed6d4d7043288449400dd7abecd454423118cff7
## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
