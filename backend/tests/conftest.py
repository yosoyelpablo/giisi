"""Configuración de pruebas: base SQLite en memoria y bcrypt rápido."""
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["BCRYPT_ROUNDS"] = "4"
os.environ["WEBHOOK_API_KEY"] = "clave-test"
import tempfile
os.environ["AUDIT_EXPORT_DIR"] = tempfile.mkdtemp(prefix="giisi-ref-")

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session
from app.main import app
from app.database import engine
from app.seed import seed
from app import config

ALERTA_RANSOMWARE = {
    "origen": "wazuh", "id_alerta_origen": "1716283245.12345", "timestamp": "2026-09-20T14:02:11Z",
    "regla": {"id": 100210, "nivel": 12, "descripcion": "Actividad compatible con ransomware"},
    "activo": {"nombre": "SRV-FILES-01", "direccion_ip": "192.168.10.15"},
    "categoria_sugerida": "codigo_malicioso",
    "detalle": "Cifrado masivo de archivos detectado en un recurso compartido",
}


@pytest.fixture(scope="session")
def client():
    SQLModel.metadata.drop_all(engine); SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        seed(s)
    with TestClient(app) as c:
        yield c


def token(client, email):
    r = client.post("/auth/login", json={"email": email, "password": config.SEED_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def operador(client): return token(client, "operador@giisi.local")
@pytest.fixture(scope="session")
def coordinador(client): return token(client, "coordinador@giisi.local")
@pytest.fixture(scope="session")
def gerente(client): return token(client, "gerente@giisi.local")
@pytest.fixture(scope="session")
def admin(client): return token(client, "admin@giisi.local")
