"""Carga un estado de DEMOSTRACIÓN en una base vacía (para capturas de pantalla y el video demostrativo).

Los tiempos que resultan de este script NO son mediciones: las confirmaciones las hace el propio
script en forma inmediata. Las mediciones del triaje están en scripts/resultados/ (medir_triaje.py).

Estado que deja:
  INC-001 ransomware            triaje confirmado · playbook iniciado · pasos 1 y 2 completos → «Contenido»
  INC-002 acceso no autorizado  triaje confirmado · playbook iniciado → «En análisis»
  INC-003 filtración de datos   SIN confirmar → «Nuevo» (muestra el formulario de triaje)
  INC-004 phishing              triaje confirmado → «Nuevo»
  INC-005 fuerza bruta          triaje confirmado · resuelto y cerrado con lección aprendida → «Cerrado»
  + una referencia externa firmada del audit log en exportaciones/

Uso:  python scripts/poblar_demo.py      (API levantada y base recién creada)
"""
import datetime, json, os, uuid
from pathlib import Path
import requests

API = os.getenv("API_URL", "http://127.0.0.1:8000")
KEY = os.getenv("WEBHOOK_API_KEY", "clave-webhook-desarrollo")
PW = os.getenv("SEED_PASSWORD", "Giisi!2026demo")


def login(email):
    r = requests.post(f"{API}/auth/login", json={"email": email, "password": PW}, timeout=10); r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def alerta(rid, nivel, desc, activo, ip, detalle, sugerida=None):
    a = {"origen": "wazuh", "id_alerta_origen": f"demo-{uuid.uuid4()}",
         "timestamp": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=42)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "regla": {"id": rid, "nivel": nivel, "descripcion": desc}, "activo": {"nombre": activo, "direccion_ip": ip}, "detalle": detalle}
    if sugerida: a["categoria_sugerida"] = sugerida
    r = requests.post(f"{API}/webhook", json=a, headers={"X-API-Key": KEY}, timeout=10); r.raise_for_status()
    return r.json()["incidente"]["id_incidente"]


def ok(r):
    if r.status_code >= 400: raise SystemExit(f"{r.status_code} {r.text}")
    return r.json()


op, co, ad = login("operador@giisi.local"), login("coordinador@giisi.local"), login("admin@giisi.local")
i1 = alerta(100210, 12, "Actividad compatible con ransomware", "SRV-FILES-01", "192.168.10.15",
            "Cifrado masivo de archivos detectado en un recurso compartido", "codigo_malicioso")
i2 = alerta(5710, 10, "Escalada de privilegios con cuenta comprometida", "SRV-AD-01", "192.168.10.10",
            "Login exitoso inusual seguido de uso de sudo fuera de horario", "acceso_no_autorizado")
i3 = alerta(87105, 11, "Exfiltración de datos hacia IP externa", "WS-RRHH-01", "192.168.20.11",
            "Transferencia inusual de 4 GB de datos de clientes hacia un host desconocido", "filtracion_datos")
i4 = alerta(31151, 7, "Correo malicioso con adjunto sospechoso", "WS-VENTAS-03", "192.168.20.33",
            "Phishing dirigido: adjunto con macro detectado por el antivirus", "correo")
i5 = alerta(5551, 10, "Intentos fallidos de inicio de sesión en serie", "SRV-WEB-01", "192.168.10.20",
            "Múltiples intentos fallidos de autenticación: posible fuerza bruta sobre el portal interno")
for i in (i1, i2, i4, i5):
    ok(requests.post(f"{API}/incidentes/{i}/clasificacion/confirmar", json={}, headers=op, timeout=10))
# ransomware: playbook con contención
ej = ok(requests.post(f"{API}/incidentes/{i1}/playbook/iniciar", headers=op, timeout=10))
pasos = sorted(ej["pasos"], key=lambda p: p["orden"])
ok(requests.post(f"{API}/incidentes/{i1}/playbook/pasos/{pasos[0]['id_paso']}/completar",
                 json={"notas": "Se aisló SRV-FILES-01 de la red (puerto del switch deshabilitado)."}, headers=op, timeout=10))
ok(requests.post(f"{API}/incidentes/{i1}/playbook/pasos/{pasos[1]['id_paso']}/completar",
                 json={"notas": "Imagen de disco y volcado de memoria guardados en el repositorio forense."}, headers=op, timeout=10))
# acceso no autorizado: playbook iniciado
ok(requests.post(f"{API}/incidentes/{i2}/playbook/iniciar", headers=op, timeout=10))
# fuerza bruta: ciclo completo y cierre
for estado in ("En análisis", "Resuelto"):
    ok(requests.patch(f"{API}/incidentes/{i5}/estado", json={"estado": estado}, headers=op, timeout=10))
ok(requests.post(f"{API}/incidentes/{i5}/cerrar", json={
    "leccion": "Los intentos provenían de una única IP externa; se bloqueó en el firewall y se activó el bloqueo de cuenta.",
    "recomendacion": "Exigir segundo factor en el portal interno."}, headers=co, timeout=10))
# referencia externa firmada
exp = ok(requests.get(f"{API}/auditoria/exportar", headers=ad, timeout=10))
dest = Path(__file__).parent.parent / "exportaciones"; dest.mkdir(exist_ok=True)
f = dest / f"referencia_{exp['referencia']['ultimo_id']}_demo.json"; f.write_text(json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"Demostración cargada: incidentes {i1}-{i5}; referencia firmada en {f}")
