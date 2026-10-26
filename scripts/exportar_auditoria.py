"""Referencia externa firmada del audit log (devolución de la Entrega 3).

  python scripts/exportar_auditoria.py              emite la referencia y la guarda en exportaciones/
  python scripts/exportar_auditoria.py verificar F  compara la cadena actual con la referencia del archivo F

El sistema emite la referencia al cerrar cada incidente (backend: AUDIT_EXPORT_DIR). En producción, además,
se emitiría a diario en forma programada y se subiría a un bucket con bloqueo de objetos en modo de cumplimiento, que impide
modificarla o borrarla durante el período de retención, incluso con credenciales de administrador:
  aws s3api put-object --bucket <respaldos> --key auditoria/<archivo>.json --body <archivo>.json \\
      --object-lock-mode COMPLIANCE --object-lock-retain-until-date <fecha>
"""
import json, os, sys, datetime
from pathlib import Path
import requests

API = os.getenv("API_URL", "http://127.0.0.1:8000")   # 127.0.0.1 evita la demora de ~2 s de Windows al resolver «localhost» por IPv6
ADMIN = os.getenv("ADMIN_EMAIL", "admin@giisi.local")
CLAVE = os.getenv("SEED_PASSWORD", "Giisi!2026demo")
DESTINO = Path(__file__).parent.parent / "exportaciones"

r = requests.post(f"{API}/auth/login", json={"email": ADMIN, "password": CLAVE}, timeout=10); r.raise_for_status()
h = {"Authorization": f"Bearer {r.json()['access_token']}"}

if len(sys.argv) > 2 and sys.argv[1] == "verificar":
    exp = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    print(json.dumps(requests.post(f"{API}/auditoria/verificar-exportacion", json=exp, headers=h, timeout=10).json(),
                     ensure_ascii=False, indent=2))
else:
    exp = requests.get(f"{API}/auditoria/exportar", headers=h, timeout=10); exp.raise_for_status(); exp = exp.json()
    DESTINO.mkdir(exist_ok=True)
    f = DESTINO / f"referencia_{exp['referencia']['ultimo_id']}_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
    f.write_text(json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Referencia firmada guardada en {f}\n{json.dumps(exp, ensure_ascii=False, indent=2)}")
