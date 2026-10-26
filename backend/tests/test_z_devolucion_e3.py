"""Pruebas de la devolución de la Entrega 3:
(1) triaje completo hasta la confirmación humana de la clasificación, y
(2) límite de la cadena de hashes y referencia externa firmada (exportación)."""
import copy
from sqlmodel import Session, select
from app.database import engine
from app.models import AccionRespuesta
from app.audit import verificar, _calcular_hash
from .conftest import ALERTA_RANSOMWARE


def _alerta(id_origen, **cambios):
    a = copy.deepcopy(ALERTA_RANSOMWARE); a["id_alerta_origen"] = id_origen; a.update(cambios)
    return a


def _ingestar(client, alerta):
    r = client.post("/webhook", json=alerta, headers={"X-API-Key": "clave-test"})
    assert r.status_code == 201, r.text
    return r.json()["incidente"]["id_incidente"]


# ------------------------------------------------------------------ (1) triaje completo
def test_confirmacion_humana_mide_el_triaje_completo(client, operador):
    inc = _ingestar(client, _alerta("e3-confirmar-1"))
    antes = client.get(f"/incidentes/{inc}", headers=operador).json()
    assert antes["tiempo_triaje_seg"] is not None and antes["tiempo_triaje_completo_seg"] is None
    r = client.post(f"/incidentes/{inc}/clasificacion/confirmar", json={}, headers=operador)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["categoria_clave"] == "codigo_malicioso" and d["fecha_confirmacion"] is not None
    assert d["tiempo_triaje_completo_seg"] >= d["tiempo_triaje_seg"]     # la revisión humana se suma al automático
    log = client.get(f"/incidentes/{inc}/auditoria", headers=operador).json()
    assert any("Triaje confirmado por una persona" in a["descripcion"] for a in log)
    assert client.post(f"/incidentes/{inc}/clasificacion/confirmar", json={}, headers=operador).status_code == 400


def test_el_operador_puede_corregir_la_propuesta(client, operador):
    inc = _ingestar(client, _alerta("e3-corregir-1"))             # el motor propone «Código malicioso», Crítica
    r = client.post(f"/incidentes/{inc}/clasificacion/confirmar",
                    json={"categoria_clave": "filtracion_datos", "severidad": "Alta"}, headers=operador)
    assert r.status_code == 200 and r.json()["categoria_clave"] == "filtracion_datos" and r.json()["severidad"] == "Alta"
    log = client.get(f"/incidentes/{inc}/auditoria", headers=operador).json()
    assert any("corrigió" in a["descripcion"] for a in log)


def test_el_gerente_no_confirma_clasificaciones(client, gerente):
    inc = _ingestar(client, _alerta("e3-gerente-1"))
    assert client.post(f"/incidentes/{inc}/clasificacion/confirmar", json={}, headers=gerente).status_code == 403


def test_metricas_informan_el_triaje_completo(client, gerente):
    m = client.get("/metricas", headers=gerente).json()
    assert m["tiempo_triaje_completo_promedio_seg"] is not None


# ------------------------------------------------------------------ (2) límite de la cadena y referencia externa
def test_exportacion_sin_cambios_coincide(client, admin):
    exp = client.get("/auditoria/exportar", headers=admin).json()
    assert exp["algoritmo"] == "HMAC-SHA256" and len(exp["firma"]) == 64
    _ingestar(client, _alerta("e3-export-1"))                      # la cadena sigue creciendo después de exportar
    r = client.post("/auditoria/verificar-exportacion", json=exp, headers=admin).json()
    assert r["coincide"] is True, r


def test_reconstruir_toda_la_cadena_engana_a_la_verificacion_interna_pero_no_a_la_exportacion(client, admin):
    exp = client.get("/auditoria/exportar", headers=admin).json()
    with Session(engine) as s:
        registros = s.exec(select(AccionRespuesta).order_by(AccionRespuesta.id_accion)).all()
        originales = [(r.descripcion, r.hash_previo, r.hash_actual) for r in registros]
        # Atacante con acceso de escritura a la base: altera un registro y RECALCULA toda la cadena.
        registros[1].descripcion = "Registro alterado por un atacante con acceso a la base"
        previo = "0" * 64
        for r in registros:
            r.hash_previo = previo
            r.hash_actual = _calcular_hash(previo, r.id_incidente, r.id_usuario, r.id_paso, r.actor, r.descripcion, r.timestamp)
            previo = r.hash_actual; s.add(r)
        s.commit()
        assert verificar(s)["integra"] is True                      # el límite: la cadena reconstruida es coherente
        r = client.post("/auditoria/verificar-exportacion", json=exp, headers=admin).json()
        assert r["coincide"] is False and "ya no coincide" in r["motivo"]   # la referencia externa lo detecta
        for reg, (desc, hp, ha) in zip(registros, originales):         # restaurar
            reg.descripcion, reg.hash_previo, reg.hash_actual = desc, hp, ha; s.add(reg)
        s.commit()
        assert verificar(s)["integra"] is True


def test_una_exportacion_alterada_no_tiene_firma_valida(client, admin):
    exp = client.get("/auditoria/exportar", headers=admin).json()
    exp["referencia"]["hash_cabeza"] = "f" * 64
    r = client.post("/auditoria/verificar-exportacion", json=exp, headers=admin).json()
    assert r["coincide"] is False and "firma" in r["motivo"]


def test_exportar_requiere_permiso(client, operador):
    assert client.get("/auditoria/exportar", headers=operador).status_code == 403
