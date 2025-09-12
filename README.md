<p align="center">
  <img src="static/images/app_logo.png" alt="easyAuth4IoT logo" width="320">
</p>

# easyAuth4IoT
Gestor de credenciales y contraseñas para IoT con cifrado local (cliente) y del lado del servidor.

## Requisitos

- Python 3.10+
- MongoDB 5.0+ en ejecución (local o remoto) Lo puedes instalar de forma secilla utilizando docker (https://hub.docker.com/_/mongo)
- pip / virtualenv

## Inicio Rápido

1. Crea y activa un entorno virtual (recomendado)
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
   ```

2. Instala dependencias
   ```bash
   pip install -r requirements.txt
   ```

3. Configura `env.txt`
   - Opción A: copia el ejemplo
     ```bash
     cp example_env.txt env.txt
     ```
   - Opción B: crea `env.txt` existente y revisa al menos:
     - `mongo_uri` o (`mongo_host`, `mongo_port`, `mongo_db`)
     - `secret_key` (cadena aleatoria larga)
     - `db_encryption_key` (clave fuerte para cifrado del lado servidor)
     - `ui_primary`, `ui_secondary` (colores hex opcionales)

4. Inicia la base de datos con datos de ejemplo e índices
   ```bash
   python init_db.py
   ```
   Esto crea/asegura índices y agrega usuarios de ejemplo: `admin/admin123`, `staff/staff123`, `user1/user123`, `user2/user123`. RECUERDA ELIMINAR ESTOS USUARIOS EN PRODUCCIÓN.

5. Arranca la aplicación
   ```bash
   python app.py
   ```

6. Puedes cambiar las imagenes de la UI en la carpeta `static/images`. El nombre de los nuevos archivos debe ser el mismo que el de la imagen que reemplazas. Si alguno de los archivos no existe, no se incluye en la UI.

## Configuración (`env.txt`)

El archivo `env.txt` en la raíz del proyecto define la configuración. Claves soportadas (ver `utils/config.py`):

- `server_host`: host de escucha (por defecto `0.0.0.0`)
- `server_port`: puerto (por defecto `5000`)
- `debugMode`: `true/false`

- Conexión a MongoDB (usa solo una opción):
  - `mongo_uri`: URI completa, p. ej. `mongodb://usuario:pass@127.0.0.1:27017/easyAuth4IoT?authSource=admin`
  - ó `mongo_host`, `mongo_port`, `mongo_db`

- UI/Marca:
  - `ui_primary`: color primario hex (p. ej. `#4fe2df`)
  - `ui_secondary`: color secundario hex (p. ej. `#571cd8`)

- Seguridad:
  - `secret_key`: clave secreta de Flask (obligatoria en producción)
  - `db_encryption_key`: clave maestra para cifrado en servidor (obligatoria para cifrado del lado servidor).
    - Puede ser una cadena larga o hex; se deriva a 32 bytes vía HKDF/ SHA‑256.

Cambios en `env.txt` se leen al iniciar el proceso (no hot‑reload).

## Inicialización de Base de Datos (`init_db.py`)

El script `init_db.py`:

- Crea índices en colecciones `users`, `devices`, `device_logins` (incluye índices parciales/únicos y tags).
- Completa tipos en `device_logins` si faltan (`userpass`, `token`, `certificate`).
- Inserta usuarios y dispositivos de ejemplo si no existen.

Ejecuta tantas veces como quieras; es idempotente en inserciones de ejemplo e índices.

## Modelo de Cifrado

- Cifrado en Cliente (local):
  - Desde el menú de usuario abre “Semilla de cifrado local” y carga 12 palabras (BIP‑39) para activar LocalCrypto.
  - Con semilla lista, los datos del Vault y archivos pueden cifrarse en el navegador antes de enviarse.

- Cifrado en Servidor:
  - Si no hay semilla local, el backend cifra automáticamente los elementos del Vault y archivos usando `DB_ENCRYPTION_KEY`.
  - Para búsqueda: los ítems cifrados en servidor se devuelven descifrados por defecto (solo sus campos de metadatos), permitiendo filtro por texto.

## Capturas de pantalla

<p align="center">
  <img src="static/images/app_icon.png" alt="Icono" width="96">
</p>

![Logo](static/images/app_logo.png)
![Demo](static/images/screenshot_demo.png)


## Ejecutar en Producción

- Usa un servidor WSGI (gunicorn/uwsgi) detrás de un reverse proxy (nginx).
- Configura `secret_key` y `db_encryption_key` con valores fuertes.
- Asegura MongoDB con autenticación/SSL si es externo.

## Solución de Problemas

- Mongo no conecta: revisa `mongo_uri` o `mongo_host/mongo_port` en `env.txt` y que MongoDB esté en ejecución.
- Error "DB encryption key not configured": establece `db_encryption_key` en `env.txt` y reinicia.
- Cambios de colores no aplican: reinicia `app.py` para recargar la configuración.

## Usuarios de ejemplo

- Admin: `admin / admin123`
- Staff: `staff / staff123`
- Users: `user1 / user123`, `user2 / user123`

## Licencia

MIT (ver `LICENSE`).
