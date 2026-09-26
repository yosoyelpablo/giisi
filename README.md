# GIISI — Sistema de gestión de incidentes de seguridad informática para pequeñas empresas

Prototipo tecnológico del **Trabajo final de grado** — Licenciatura en Seguridad Informática, Universidad Siglo 21.
Autor: Pablo Bernal · Tutor: Ing. Esp. Alejandro Pastrán · 2026.

El sistema recibe alertas de fuentes externas de detección (por ejemplo, el SIEM Wazuh), las clasifica automáticamente
según la taxonomía del NIST, calcula su severidad, guía la respuesta mediante **playbooks interactivos** alineados con
las funciones del **NIST CSF 2.0** (NIST SP 800-61 rev. 3) e ISO/IEC 27035, y registra cada acción en un **audit log de
solo agregado con hash encadenado** (integridad verificable).

> La detección de eventos **no** es función del prototipo: la aportan las fuentes externas. El prototipo orquesta el
> triaje, la clasificación, la respuesta y la trazabilidad.

## Producto mínimo viable (MVP)

Flujo completo de extremo a extremo para un incidente de **ransomware**:

`alerta (webhook) → clasificación NIST → severidad → tablero kanban → playbook interactivo → audit log → cierre con lecciones aprendidas`

## Arquitectura

| Componente | Tecnología |
|---|---|
| API REST | Python 3.12 · FastAPI · SQLModel |
| Base de datos | PostgreSQL 16 (SQLite para desarrollo y pruebas) |
| Interfaz web | Streamlit |
| Autenticación / autorización | JWT (8 h) · bcrypt (costo 12) · RBAC por permisos · bloqueo a los 5 intentos |
| Integridad | Audit log append-only con SHA-256 encadenado (`GET /auditoria/verificar`) |
| Despliegue | Docker Compose (db + api + frontend) |

## Ejecución rápida

```bash
docker compose up --build
```

- Interfaz web: http://localhost:8501  (KPI: tiempo de triaje y tiempo de respuesta medidos desde la recepción de la alerta; la latencia evento→alerta es de la fuente externa y se informa solo como contexto)
- API y documentación OpenAPI: http://localhost:8000/docs

Usuarios de demostración (contraseña `Giisi!2026demo`, configurable con `SEED_PASSWORD`):

| Usuario | Rol | Puede |
|---|---|---|
| operador@giisi.local | operador | registrar incidentes, ejecutar playbooks, lecciones |
| coordinador@giisi.local | coordinador de respuesta | lo anterior + asignar, cambiar severidad, **cerrar** |
| gerente@giisi.local | gerente | solo lectura (tablero e indicadores) |
| admin@giisi.local | administrador | todo + verificar la integridad del audit log |

### Simular una alerta de Wazuh

```bash
python scripts/simular_alerta.py ransomware     # también: acceso | filtracion | phishing
```

## Ejecución local sin Docker

```bash
python -m venv .venv && .venv/Scripts/activate      # Linux/macOS: source .venv/bin/activate
pip install -r backend/requirements.txt -r frontend/requirements.txt
cd backend && uvicorn app.main:app --reload         # API en :8000 (SQLite giisi.db)
cd frontend && streamlit run app.py                 # interfaz en :8501
```

## Pruebas automatizadas

```bash
cd backend && pytest -q
```

Cubren el flujo MVP completo, la deduplicación de alertas, la clasificación y severidad, las transiciones de estado,
el RBAC, el bloqueo de cuenta y la **detección de manipulación del audit log**.

## Estructura del repositorio

```
backend/app/
  main.py        aplicación FastAPI y ciclo de vida (crea tablas + seed)
  models.py      entidades del DER (rol, usuario, incidente, alerta, playbook, accion_respuesta, ...)
  auth.py        bcrypt, JWT, bloqueo de cuenta, RBAC (require(permiso))
  audit.py       audit log con hash encadenado + verificación de la cadena
  rules.py       motor de reglas: clasificación NIST y severidad
  services.py    lógica de negocio: ingesta, ciclo de vida, playbooks, cierre, métricas
  routers.py     endpoints REST
  seed.py        roles, usuarios demo, taxonomía, activos y playbooks
backend/tests/   pruebas pytest
frontend/app.py  interfaz Streamlit (panel, detalle, alta manual, playbooks, integridad)
scripts/         simulador de alertas
docker-compose.yml
```

## Alcance y trabajo futuro

Fuera del alcance del prototipo (ver TFG, Entrega 2): detección de eventos, integración con firewall/EDR, análisis
forense automatizado, operación multiorganización. Etapas siguientes: notificaciones por correo, clasificación asistida
por un modelo de lenguaje local para los casos «a revisar» (el audit log nunca es escrito por el modelo) y migración de
la interfaz a React.

## Licencia

MIT — el stack completo es de código abierto y no genera costos de licenciamiento.
