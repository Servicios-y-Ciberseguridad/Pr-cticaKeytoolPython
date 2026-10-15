# Práctica Keytool en Python

Este proyecto consiste en una implementación en Python de una herramienta similar a `keytool`, la utilidad de Java para gestionar claves y certificados digitales.

La idea de la práctica es aprender a trabajar con criptografía, generación de claves, y manejo básico de certificados en un entorno CLI.

## Integrantes

- Yangpeng Ni
- Víctor Iniesta Romera

## Objetivo

Crear un programa Python que permita:

- Generar pares de claves pública/privada.
- Almacenar claves con alias identificativos.
- Generar solicitudes de firma de certificado (CSR) en formato PEM.
- Firmar certificados X.509 desde solicitudes PKCS#10 en PEM o DER.
- Exportar el certificado X.509 público asociado a un alias en DER o PEM.
- Consultar desde Python la información de una entrada del KeyStore.
- Simular funcionalidades básicas de `keytool` en un entorno de consola.

## Requisitos

- Python 3.10 o superior (comprobado con Python 3.14)
- pip
- Git
- Un entorno virtual de Python (recomendado)

## Instalación

Clona el repositorio y entra en el directorio del proyecto:

```bash
git clone https://github.com/Servicios-y-Ciberseguridad/PracticaKeytoolPython.git
cd PracticaKeytoolPython
```

Usa Python 3.10 o superior para crear un entorno virtual:

```bash
python -m venv .venv
```

Activa el entorno:

- Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

- Windows (CMD):

```cmd
.venv\Scripts\activate.bat
```

- macOS/Linux:

```bash
source .venv/bin/activate
```

Instala las dependencias declaradas por el proyecto:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

La dependencia criptográfica también se puede instalar directamente:

```bash
pip install cryptography
```

`requirements.txt` fija `cryptography>=50.0.0`. En Windows, si la instalación
falla desde un entorno MSYS2 o MinGW, crea el entorno virtual con el Python
oficial de python.org.

## Ejecución

Desde la raíz del repositorio, ejecuta la CLI con cualquiera de estas formas:

```bash
python mykeytool.py --help
python -m keytool --help
```

También puedes usar el ejecutable del entorno virtual explícitamente:

```powershell
.\.venv\Scripts\python.exe .\mykeytool.py --help
```

## Estructura del proyecto

```text
Pr-cticaKeytoolPython/
├── mykeytool.py          # Punto de entrada compatible
├── keytool/              # Paquete de la aplicación
│   ├── __init__.py
│   ├── __main__.py       # Permite ejecutar python -m keytool
│   ├── start.py          # CLI y enrutamiento de comandos
│   ├── genkeypair.py     # Generacion RSA y flujo interactivo
│   ├── keystore.py       # Cifrado, lectura y escritura del KeyStore
│   ├── certreq.py        # Comando de solicitudes CSR
│   ├── gencert.py        # Emision X.509 a partir de un CSR
│   ├── exportcert.py     # Exportacion autenticada de certificados publicos
│   ├── changealias.py    # Cambio de alias de una entrada
│   ├── storepasswd.py    # Cambio de contrasena del almacen
│   ├── listing.py        # Listado autenticado de datos publicos
│   └── errors.py         # Errores de dominio
├── tests/
│   ├── test_exportcert.py
│   ├── test_gencert.py
│   ├── test_listing.py
│   ├── test_mykeytool.py
│   └── test_storepasswd.py
├── README.md             # Documentación del proyecto
├── requirements.txt      # Dependencias del proyecto
└── .gitignore           # Archivos ignorados por Git
```

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
10. `keytool/exportcert.py` exporta el certificado asociado a un alias sin acceder
    a la clave privada.

El archivo raíz `mykeytool.py` conserva el comando de ejecución existente. También
puedes iniciar la aplicación mediante `python -m keytool`.

### Decisiones relevantes

- El KeyStore `MYKEYSTORE` es un formato propio versionado; no es un almacén JKS
  ni PKCS12. Protege los datos con AES-GCM y deriva la clave con Scrypt.
- `storepass` protege el almacén y `keypass` protege individualmente la clave
  privada. No se exportan claves privadas.
- Las escrituras de certificados y solicitudes son atómicas para conservar el
  archivo anterior si falla la operación.
- Los certificados autofirmados de `genkeypair` no son autoridades certificadoras
  (`CA=false`). `gencert` firma CSR, pero no valida la confianza de una cadena CA.

El recorrido de `--certreq` se puede explicar en tres pasos:

```text
contraseña + alias → entrada cifrada → CSR firmado → archivo .csr PEM
```

Hay dos contraseñas con objetivos distintos: `storepass` permite descifrar el
almacén completo y `keypass` permite usar la clave privada de un alias. La clave
privada solo se mantiene en memoria el tiempo necesario para firmar y nunca se
escribe en el CSR.

## Uso previsto

### Ayuda de la CLI

```bash
python mykeytool.py --help
python mykeytool.py --genkeypair --help
python mykeytool.py --certreq --help
```

Ejemplo de salida real de la ayuda general:

```text
> python mykeytool.py --help
usage: mykeytool.py [-h] [-genkeypair | -certreq | -changealias | -list |
                    -exportcert | -storepasswd | -gencert] ...
...
options:
  -h, --help            show this help message and exit
  -genkeypair, --genkeypair
                        genera un par de claves RSA y lo guarda en el KeyStore
  -certreq, --certreq   genera una solicitud de firma de certificado (CSR)
...
```

Sin argumentos, `python mykeytool.py` muestra la lista de comandos disponibles.
La ayuda también enumera las opciones generales, por ejemplo `-keyalg`,
`-keysize`, `-infile` y `-outfile`.

`--genkeypair --help` y `--certreq --help` muestran respectivamente las opciones
del par de claves y de la solicitud CSR. Los ejemplos usan la misma interfaz que
`mykeytool.py`; también se puede anteponer `python -m keytool`.

### Generar un par de claves

El comando requiere `-keyalg RSA`. Los demás datos se pueden proporcionar como
argumentos o introducir cuando se soliciten. Por ejemplo:

```bash
python mykeytool.py --genkeypair -keyalg RSA -keysize 2048 -alias demo -dname "CN=Demo, OU=Seguridad, O=Universidad, L=Madrid, ST=Madrid, C=ES"
```

Al omitir `-storepass` y `-keypass`, se solicitan sin eco. Ejemplo del mensaje de
resultado al usar el alias y el almacén de ejemplo:

```text
Exito: par RSA de 2048 bits guardado con alias 'demo' en 'keystore.myks'.
```

### Generar una solicitud CSR

Después de crear el alias `demo`, genera su CSR:

```bash
python mykeytool.py --certreq -keystore keystore.myks -alias demo -file demo.csr
```

Si se omiten las contraseñas, el programa las solicita sin eco. El CSR contiene
el sujeto y la clave pública, nunca la clave privada. Ejemplo del resultado:

```text
Exito: CSR del alias 'demo' guardado en 'demo.csr' en formato PEM compatible con keytool.
```

La siguiente secuencia de consola muestra ambos comandos después de introducir
las contraseñas cuando se solicitan:

```text
> python mykeytool.py --genkeypair -keyalg RSA -keysize 2048 -alias demo -dname "CN=Demo, OU=Seguridad, O=Universidad, L=Madrid, ST=Madrid, C=ES"
Exito: par RSA de 2048 bits guardado con alias 'demo' en 'keystore.myks'.
> python mykeytool.py --certreq -keystore keystore.myks -alias demo -file demo.csr
Exito: CSR del alias 'demo' guardado en 'demo.csr' en formato PEM compatible con keytool.
```

Los mensajes de contraseña se omiten en el bloque: el programa los solicita sin
eco y no los guarda en el historial de comandos.

Cada entrada nueva incluye además un certificado X.509 autofirmado en PEM, con
el DN como sujeto y emisor, firma RSA/SHA-256 y vigencia de 90 días. No es una
autoridad certificadora (`CA=false`). Las entradas antiguas sin certificado
siguen siendo compatibles.

`-changealias` también admite `--changealias`. Si se omiten `-storepass`,
`-alias` o `-destalias`, los solicita de forma interactiva; la contraseña se
solicita sin eco. El cambio conserva los datos de la entrada, incluida la clave
privada cifrada y los certificados asociados.

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
del almacén. El resultado es un archivo X.509 estándar reutilizable.

### Exportar el certificado de un alias

```powershell
python mykeytool.py -exportcert -keystore keystore.myks -alias miClave -file certificado.der
python -m keytool --exportcert -keystore keystore.myks -alias miClave -file certificado.pem -rfc
python mykeytool.py -exportcert --help
```

`-exportcert` / `--exportcert` autentica el KeyStore y exporta únicamente el
certificado X.509 público guardado en el alias. Acepta `-keystore KEYSTORE`,
`-storepass STOREPASS`, `-alias ALIAS`, `-file FILE` y `-rfc`. Si se omite la
contraseña, se solicita sin eco; si se omite el alias, se solicita de forma
interactiva; y si se omite el archivo, se genera `<alias>.cer` con un nombre
seguro. Por defecto se escribe DER binario; `-rfc` escribe PEM/Base64 con las
cabeceras `BEGIN/END CERTIFICATE`. Ambos formatos contienen el mismo certificado.

El comando no carga ni descifra la clave privada, no modifica el KeyStore y
rechaza una salida que apunte al propio almacén, incluso mediante un enlace duro.
La escritura es atómica. Un alias inexistente, un alias sin certificado, una
contraseña incorrecta o un certificado guardado no válido produce un error
claro sin traza.

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
  y `15360`
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

## Historial de contribuciones

Se conserva el historial Git de ambos integrantes. Como ejemplos de commits
representativos:

| Integrante | Commit | Aportación |
|---|---|---|
| Yangpeng Ni | `ed6d4d7` | Implementación de `-gencert` |
| Víctor Iniesta Romera | `f7b8e47` | Cambios de integración del proyecto |

## Matriz de pruebas ejecutadas

Resultados obtenidos el 15 de octubre de 2026 con Python 3.14.7. Los módulos
funcionales se ejecutaron individualmente con `unittest discover`; la prueba
completa se ejecutó además con el comando indicado al final de la tabla.

| Área | Casos cubiertos | Resultado esperado | Resultado obtenido |
|---|---|---|---|
| CLI, `genkeypair` y `certreq` | Ayuda general y específica; generación RSA y CSR en una ejecución temporal | Ayuda con las opciones reales; almacén creado y CSR PEM exportado | Correcto: se ejecutaron las ayudas y la generación produjo almacén y CSR |
| Integración (`test_mykeytool.py`) | Generación RSA, certificados autofirmados, persistencia cifrada, CSR, ayuda, alias duplicado y contraseñas incorrectas | Operaciones correctas y errores controlados sin modificar el almacén ante fallos | Correcto: 50 pruebas, 50 aprobadas tras resolver los conflictos de merge |
| `storepasswd` | Contraseña válida/incorrecta, confirmación, conservación de claves y fallos de escritura | Cambio autenticado; conservar el almacén original ante errores | Correcto: 19 pruebas, 19 aprobadas |
| `list` | Orden, filtro, metadatos públicos, alias ausente y autenticación | Listado estable sin exponer claves; errores controlados | Correcto: 18 pruebas, 18 aprobadas |
| `gencert` | CSR PEM/DER, firma, vigencia, extensiones, entradas incorrectas y escritura atómica | Certificado verificable; no escribir salida parcial ante errores | Correcto: 20 pruebas, 20 aprobadas |
| `exportcert` | DER/PEM, alias, contraseñas, salida atómica y protección del almacén | Exportar solo el certificado; preservar el almacén y la salida previa ante errores | Correcto: 7 pruebas, 7 aprobadas |
| Suite completa | Descubrimiento de todos los módulos de prueba | Todas las pruebas importan y pasan | Correcto: 114 pruebas, 114 aprobadas, sin errores de importación |

La suite completa se ejecuta con:

```bash
python -m unittest discover -s tests -v
```

También se pueden repetir los módulos por separado:

```bash
python -m unittest discover -s tests -p test_mykeytool.py -v
python -m unittest discover -s tests -p test_storepasswd.py -v
python -m unittest discover -s tests -p test_listing.py -v
python -m unittest discover -s tests -p test_gencert.py -v
python -m unittest discover -s tests -p test_exportcert.py -v
```

## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
