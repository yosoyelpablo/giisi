"""Simula una alerta de Wazuh (u otra fuente de detección) enviándola al webhook del prototipo.

Uso:  python scripts/simular_alerta.py [ransomware|acceso|filtracion|phishing]
"""
import sys, json, uuid, datetime, requests, os

API = os.getenv("API_URL", "http://localhost:8000")
KEY = os.getenv("WEBHOOK_API_KEY", "clave-webhook-desarrollo")

ESCENARIOS = {
    "ransomware": (100210, 12, "Actividad compatible con ransomware", "SRV-FILES-01", "192.168.10.15",
                   "codigo_malicioso", "Cifrado masivo de archivos detectado en un recurso compartido"),
    "acceso": (5710, 10, "Escalada de privilegios con cuenta comprometida", "SRV-AD-01", "192.168.10.10",
               "acceso_no_autorizado", "Login exitoso inusual seguido de uso de sudo fuera de horario"),
    "filtracion": (87105, 11, "Exfiltración de datos hacia IP externa", "WS-RRHH-01", "192.168.20.11",
                   "filtracion_datos", "Transferencia inusual de 4 GB de datos de clientes hacia un host desconocido"),
    "phishing": (31151, 7, "Correo malicioso con adjunto sospechoso", "WS-VENTAS-03", "192.168.20.33",
                 "correo", "Phishing dirigido: adjunto con macro detectado por el antivirus"),
}

esc = sys.argv[1] if len(sys.argv) > 1 else "ransomware"
rid, nivel, desc, activo, ip, cat, detalle = ESCENARIOS[esc]
alerta = {
    "origen": "wazuh", "id_alerta_origen": str(uuid.uuid4()),
    "timestamp": (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=42)).isoformat() + "Z",
    "regla": {"id": rid, "nivel": nivel, "descripcion": desc},
    "activo": {"nombre": activo, "direccion_ip": ip},
    "categoria_sugerida": cat, "detalle": detalle,
}
r = requests.post(f"{API}/webhook", json=alerta, headers={"X-API-Key": KEY}, timeout=10)
print(r.status_code, json.dumps(r.json(), ensure_ascii=False, indent=2))
