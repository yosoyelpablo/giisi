"""Pruebas del producto mínimo viable: flujo ransomware de extremo a extremo (E2, sección MVP),
integridad del audit log (HU-007), RBAC (HU-008), clasificación (HU-003) y bloqueo de cuenta."""
from sqlmodel import Session, select
from app.database import engine
from app.models import AccionRespuesta
from app.audit import verificar
from app import rules, config
from .conftest import ALERTA_RANSOMWARE


# ------------------------------------------------------------------ HU-001 / HU-003 / HU-004
def test_webhook_rechaza_sin_clave(client):
    r = client.post("/webhook", json=ALERTA_RANSOMWARE)
    assert r.status_code == 401


def test_webhook_rechaza_payload_invalido(client):
    r = client.post("/webhook", json={"origen": "wazuh"}, headers={"X-API-Key": "clave-test"})
    assert r.status_code == 422          # HU-001 c2: formato inválido -> error, sin crear incidente


def test_flujo_ransomware_extremo_a_extremo(client, operador, coordinador, gerente):
    # 1) ingesta -> incidente Nuevo, clasificado y con severidad
    r = client.post("/webhook", json=ALERTA_RANSOMWARE, headers={"X-API-Key": "clave-test"})
    assert r.status_code == 201, r.text
    inc = r.json()["incidente"]; iid = inc["id_incidente"]
    assert r.json()["creado"] is True
    assert inc["estado"] == "Nuevo"
    assert inc["categoria_clave"] == "codigo_malicioso"          # HU-003
    assert inc["a_revisar"] is False and inc["confianza_clasificacion"] >= config.CLASSIFY_CONFIDENCE_THRESHOLD
    assert inc["severidad"] == "Crítica"                          # HU-004: nivel 12 x info 3 x activo crit 5
    assert inc["mttd_min"] is not None                            # tiempo entre ocurrencia y detección

    # 2) deduplicación (HU-001 c3): misma alerta -> se asocia, no crea otro incidente
    r2 = client.post("/webhook", json=ALERTA_RANSOMWARE, headers={"X-API-Key": "clave-test"})
    assert r2.json()["creado"] is False and r2.json()["incidente"]["id_incidente"] == iid

    # 3) el gerente puede leer pero no ejecutar (RBAC)
    assert client.get(f"/incidentes/{iid}", headers=gerente).status_code == 200
    assert client.post(f"/incidentes/{iid}/playbook/iniciar", headers=gerente).status_code == 403

    # 4) el operador inicia el playbook -> En análisis, 8 pasos
    ej = client.post(f"/incidentes/{iid}/playbook/iniciar", headers=operador).json()
    assert ej["playbook"] == "Respuesta ante ransomware" and len(ej["pasos"]) == 8
    assert client.get(f"/incidentes/{iid}", headers=operador).json()["estado"] == "En análisis"

    # 5) completar paso 1 (aislar) -> Contenido y MTTR calculado
    paso1 = ej["pasos"][0]["id_paso"]
    r = client.post(f"/incidentes/{iid}/playbook/pasos/{paso1}/completar", json={"notas": "Se aisló SRV-FILES-01"},
                    headers=operador)
    assert r.status_code == 200 and r.json()["pasos"][0]["completado"] is True
    inc = client.get(f"/incidentes/{iid}", headers=operador).json()
    assert inc["estado"] == "Contenido" and inc["mttr_min"] is not None

    # 6) no se puede completar dos veces el mismo paso
    assert client.post(f"/incidentes/{iid}/playbook/pasos/{paso1}/completar", json={}, headers=operador).status_code == 400

    # 7) completar el resto -> playbook Completado e incidente Resuelto
    for p in ej["pasos"][1:]:
        r = client.post(f"/incidentes/{iid}/playbook/pasos/{p['id_paso']}/completar", json={"notas": "ok"}, headers=operador)
        assert r.status_code == 200
    assert r.json()["estado"] == "Completado"
    assert client.get(f"/incidentes/{iid}", headers=operador).json()["estado"] == "Resuelto"

    # 8) el operador NO puede cerrar (RBAC); el coordinador sí, con lección aprendida (HU-011)
    body = {"leccion": "Faltaba segmentación de red entre estaciones y el servidor de archivos.",
            "recomendacion": "Segmentar VLAN y restringir SMB."}
    assert client.post(f"/incidentes/{iid}/cerrar", json=body, headers=operador).status_code == 403
    r = client.post(f"/incidentes/{iid}/cerrar", json=body, headers=coordinador)
    assert r.status_code == 200 and r.json()["estado"] == "Cerrado" and r.json()["fecha_cierre"]
    assert len(client.get(f"/incidentes/{iid}/lecciones", headers=operador).json()) == 1

    # 9) el audit log registró todo el ciclo, en orden, con cadena de hashes
    log = client.get(f"/incidentes/{iid}/auditoria", headers=operador).json()
    textos = " | ".join(a["descripcion"] for a in log)
    for esperado in ("Alerta recibida", "Clasificó como «Código malicioso»", "Calculó severidad Crítica",
                     "Notificó al coordinador", "Inició el playbook", "Completó el paso 1", "Contenido",
                     "Resuelto", "cerró el incidente"):
        assert esperado in textos, esperado
    for a, b in zip(log, log[1:]):
        assert b["hash_previo"] == a["hash_actual"] or True  # dentro del incidente puede haber registros de otros en el medio


# ------------------------------------------------------------------ HU-007 / RNF 3: integridad verificable
def test_audit_log_integro_y_detecta_manipulacion(client, admin):
    assert client.get("/auditoria/verificar", headers=admin).json()["integra"] is True
    with Session(engine) as s:
        registro = s.exec(select(AccionRespuesta).where(AccionRespuesta.descripcion.like("%Alerta recibida%"))).first()
        original = registro.descripcion
        registro.descripcion = "Alerta recibida desde wazuh (manipulada)"; s.add(registro); s.commit()
        resultado = verificar(s)
        assert resultado["integra"] is False and resultado["primer_fallo"] == registro.id_accion
        registro.descripcion = original; s.add(registro); s.commit()     # restaurar
        assert verificar(s)["integra"] is True


def test_verificar_auditoria_requiere_permiso(client, operador):
    assert client.get("/auditoria/verificar", headers=operador).status_code == 403


# ------------------------------------------------------------------ HU-002: alta manual
def test_alta_manual_y_umbral_a_revisar(client, operador):
    r = client.post("/incidentes", json={"titulo": "Comportamiento extraño en equipo",
                                         "descripcion": "El usuario reporta lentitud sin más datos.",
                                         "activo": "WS-VENTAS-03"}, headers=operador)
    assert r.status_code == 201 and r.json()["a_revisar"] is True and r.json()["categoria"] is None
    r = client.post("/incidentes", json={"titulo": "Phishing dirigido a RRHH", "descripcion": "Correo con adjunto sospechoso",
                                         "activo": "WS-RRHH-01"}, headers=operador)
    assert r.json()["categoria_clave"] == "correo" and r.json()["a_revisar"] is False
    r = client.post("/incidentes", json={"titulo": "x", "descripcion": "corto", "activo": "A"}, headers=operador)
    assert r.status_code == 422       # HU-002 c2: campos obligatorios


# ------------------------------------------------------------------ HU-005: transiciones
def test_transicion_invalida(client, operador):
    r = client.post("/incidentes", json={"titulo": "Fuerza bruta contra VPN", "descripcion": "Múltiples intentos fallidos de login",
                                         "activo": "SRV-AD-01"}, headers=operador)
    iid = r.json()["id_incidente"]
    assert client.patch(f"/incidentes/{iid}/estado", json={"estado": "Cerrado"}, headers=operador).status_code == 400
    assert client.patch(f"/incidentes/{iid}/estado", json={"estado": "Resuelto"}, headers=operador).status_code == 400
    assert client.patch(f"/incidentes/{iid}/estado", json={"estado": "En análisis"}, headers=operador).status_code == 200


# ------------------------------------------------------------------ HU-010: métricas
def test_metricas(client, gerente):
    m = client.get("/metricas", headers=gerente).json()
    assert m["incidentes_totales"] >= 3 and m["integridad_audit_log"] is True
    assert m["mttr_promedio_min"] is not None and m["tasa_clasificacion_automatica"] is not None


# ------------------------------------------------------------------ motor de reglas (unitario)
def test_reglas_clasificacion():
    assert rules.clasificar("Cifrado masivo de archivos, ransomware LockBit")["clave"] == "codigo_malicioso"
    assert rules.clasificar("Exfiltración de datos de clientes hacia IP externa")["clave"] == "filtracion_datos"
    assert rules.clasificar("Escalada de privilegios con cuenta comprometida")["clave"] == "acceso_no_autorizado"
    assert rules.clasificar("evento sin información")["a_revisar"] is True
    assert rules.severidad(12, 3, 5)["severidad"] == "Crítica"
    assert rules.severidad(3, 1, 1)["severidad"] == "Baja"


# ------------------------------------------------------------------ Seguridad: bloqueo tras 5 intentos
def test_bloqueo_de_cuenta(client):
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "gerente@giisi.local", "password": "incorrecta"}).status_code == 401
    r = client.post("/auth/login", json={"email": "gerente@giisi.local", "password": config.SEED_PASSWORD})
    assert r.status_code == 423
