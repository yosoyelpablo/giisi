"""Configuración del prototipo GIISI (Gestión de Incidentes de Seguridad Informática).

Todos los valores pueden sobreescribirse por variables de entorno. Los valores por
defecto permiten ejecutar el sistema y las pruebas sin configuración adicional.
"""
import os

# Base de datos: PostgreSQL en producción (docker compose), SQLite para desarrollo/pruebas.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./giisi.db")

# Autenticación (RNF 1): JWT firmado, vigencia 8 horas, bcrypt con factor de costo 12.
JWT_SECRET = os.getenv("JWT_SECRET", "cambiar-en-produccion-clave-de-desarrollo")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# Bloqueo de cuenta: 5 intentos fallidos -> 15 minutos (sección Seguridad, E3).
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15

# Clave de la exportación firmada del audit log (HMAC-SHA256). Se custodia FUERA de la base de datos
# (variable de entorno o gestor de secretos), separada de JWT_SECRET: quien solo accede a la base no puede
# firmar una referencia externa válida.
AUDIT_EXPORT_KEY = os.getenv("AUDIT_EXPORT_KEY", "cambiar-en-produccion-clave-de-exportacion")

# Clave compartida que deben presentar las fuentes externas de detección (Wazuh, webhooks).
WEBHOOK_API_KEY = os.getenv("WEBHOOK_API_KEY", "clave-webhook-desarrollo")

# Ventana de deduplicación de alertas (HU-001, criterio 3).
DEDUP_WINDOW_MINUTES = int(os.getenv("DEDUP_WINDOW_MINUTES", "60"))

# Umbral de confianza para la clasificación automática (HU-003, criterio 2).
CLASSIFY_CONFIDENCE_THRESHOLD = float(os.getenv("CLASSIFY_CONFIDENCE_THRESHOLD", "0.6"))

# Contraseña de los usuarios de demostración creados por el seed.
SEED_PASSWORD = os.getenv("SEED_PASSWORD", "Giisi!2026demo")
