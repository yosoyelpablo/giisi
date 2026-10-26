"""Medición del triaje completo en condiciones equivalentes (devolución de la Entrega 3).

Compara dos procedimientos sobre los MISMOS seis escenarios y mide, en ambos, desde la
recepción de la alerta (T0) hasta que una persona CONFIRMA la categoría y la severidad:

  prototipo  la alerta entra por el webhook; el motor de reglas propone categoría y severidad;
             el operador revisa la propuesta y la confirma o la corrige (POST .../clasificacion/confirmar).
             El tiempo lo calcula el servidor: confirmación − recepción.
  manual     el operador recibe la misma alerta, sin propuesta, y la clasifica con la guía de la
             organización (taxonomía NIST, matriz de severidad e inventario de activos).
             El tiempo se mide desde que se muestra la alerta hasta que confirma.

Orden recomendado: primero «prototipo» y después «manual». Como el operador ya vio los
escenarios, el aprendizaje favorece al procedimiento manual: la comparación es conservadora.
Cada modo presenta los escenarios en un orden distinto (semilla fija) para reducir la memoria del orden.

Uso:
  python scripts/medir_triaje.py prototipo      (con la API levantada: docker compose up)
  python scripts/medir_triaje.py manual
  python scripts/medir_triaje.py resumen        (compara los dos CSV más recientes)
"""
import csv, datetime, json, os, random, statistics, sys, time, uuid
from pathlib import Path

API = os.getenv("API_URL", "http://127.0.0.1:8000")   # 127.0.0.1 evita la demora de ~2 s de Windows al resolver «localhost» por IPv6
KEY = os.getenv("WEBHOOK_API_KEY", "clave-webhook-desarrollo")
USUARIO = os.getenv("OPERADOR_EMAIL", "operador@giisi.local")
CLAVE = os.getenv("SEED_PASSWORD", "Giisi!2026demo")
SALIDA = Path(__file__).parent / "resultados"

# id, regla, nivel, descripción, activo, ip, categoría sugerida por la fuente (o None), detalle, categoría esperada, severidad esperada
ESCENARIOS = [
    ("E1", 100210, 12, "Actividad compatible con ransomware", "SRV-FILES-01", "192.168.10.15", "codigo_malicioso",
     "Cifrado masivo de archivos detectado en un recurso compartido", "codigo_malicioso", "Crítica"),
    ("E2", 5710, 10, "Escalada de privilegios con cuenta comprometida", "SRV-AD-01", "192.168.10.10", "acceso_no_autorizado",
     "Login exitoso inusual seguido de uso de sudo fuera de horario", "acceso_no_autorizado", "Crítica"),
    ("E3", 87105, 11, "Exfiltración de datos hacia IP externa", "WS-RRHH-01", "192.168.20.11", "filtracion_datos",
     "Transferencia inusual de 4 GB de datos de clientes hacia un host desconocido", "filtracion_datos", "Alta"),
    ("E4", 31151, 7, "Correo malicioso con adjunto sospechoso", "WS-VENTAS-03", "192.168.20.33", "correo",
     "Phishing dirigido: adjunto con macro detectado por el antivirus", "correo", "Media"),
    ("E5", 5551, 10, "Intentos fallidos de inicio de sesión en serie", "SRV-WEB-01", "192.168.10.20", None,
     "Múltiples intentos fallidos de autenticación: posible fuerza bruta sobre el portal interno", "desgaste", "Alta"),
    ("E6", 81200, 5, "Dispositivo USB no autorizado conectado", "WS-RRHH-01", "192.168.20.11", None,
     "Se conectó un medio extraíble no registrado en una estación de Recursos Humanos", "medios_externos", "Media"),
]

# Guía de la organización para el procedimiento manual (los mismos criterios que aplica el motor de reglas)
CATEGORIAS = [("codigo_malicioso", "Código malicioso", 3), ("acceso_no_autorizado", "Acceso no autorizado", 3),
              ("filtracion_datos", "Filtración de datos", 3), ("correo", "Correo electrónico", 2),
              ("desgaste", "Ataque de desgaste (fuerza bruta, denegación de servicio)", 2), ("web", "Aplicación web", 2),
              ("suplantacion", "Suplantación de identidad", 2), ("uso_indebido", "Uso indebido", 1),
              ("medios_externos", "Medios externos o removibles", 2), ("perdida_robo", "Pérdida o robo de equipamiento", 2)]
ACTIVOS = {"SRV-FILES-01": 5, "SRV-AD-01": 5, "SRV-WEB-01": 4, "WS-VENTAS-03": 2, "WS-RRHH-01": 3}
SEVERIDADES = {"b": "Baja", "m": "Media", "a": "Alta", "c": "Crítica"}

GUIA = """
──────────────── GUÍA DE TRIAJE DE LA ORGANIZACIÓN ────────────────
Categorías (taxonomía NIST):
{cats}
Severidad = funcional × información × recuperabilidad
  funcional:        nivel de la alerta ≥ 12 → 3 · ≥ 7 → 2 · resto → 1
  información:      el número entre corchetes de la categoría
  recuperabilidad:  criticidad del activo ≥ 4 → 3 · = 3 → 2 · ≤ 2 → 1
  inventario:       {activos}
  puntaje ≥ 18 Crítica · ≥ 9 Alta · ≥ 4 Media · resto Baja
────────────────────────────────────────────────────────────────────"""


def alerta_de(e):
    _, rid, nivel, desc, activo, ip, sug, detalle, *_ = e
    a = {"origen": "wazuh", "id_alerta_origen": f"medicion-{uuid.uuid4()}",
         "timestamp": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=42)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "regla": {"id": rid, "nivel": nivel, "descripcion": desc}, "activo": {"nombre": activo, "direccion_ip": ip},
         "detalle": detalle}
    if sug: a["categoria_sugerida"] = sug
    return a


def pedir(texto, validos):
    while True:
        v = input(texto).strip().lower()
        if v in validos: return v
        print(f"   valores válidos: {', '.join(sorted(validos))}")


def elegir_categoria():
    n = pedir("   Categoría (número 1-10): ", {str(i) for i in range(1, 11)})
    return CATEGORIAS[int(n) - 1][0]


def guardar(modo, filas):
    SALIDA.mkdir(exist_ok=True)
    f = SALIDA / f"triaje_{modo}_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"
    with open(f, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas[0].keys())); w.writeheader(); w.writerows(filas)
    print(f"\nResultados guardados en {f}")
    resumen_de(modo, filas)


def resumen_de(modo, filas):
    t = [float(x["segundos"]) for x in filas]
    ok_c = sum(1 for x in filas if str(x["categoria_correcta"]) in ("True", "1")); ok_s = sum(1 for x in filas if str(x["severidad_correcta"]) in ("True", "1"))
    print(f"{modo:10s} n={len(t)} · media {statistics.mean(t):.1f} s · mediana {statistics.median(t):.1f} s · "
          f"mín {min(t):.1f} s · máx {max(t):.1f} s · categoría correcta {ok_c}/{len(t)} · severidad correcta {ok_s}/{len(t)}")


def modo_prototipo():
    import requests
    r = requests.post(f"{API}/auth/login", json={"email": USUARIO, "password": CLAVE}, timeout=10); r.raise_for_status()
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    orden = ESCENARIOS[:]; random.Random(11).shuffle(orden); filas = []
    print("MODO PROTOTIPO — se envía cada alerta al webhook y se muestra la propuesta del sistema.")
    for e in orden:
        input(f"\n[{e[0]}] Presione Enter para recibir la próxima alerta…")
        r = requests.post(f"{API}/webhook", json=alerta_de(e), headers={"X-API-Key": KEY}, timeout=10); r.raise_for_status()
        inc = r.json()["incidente"]
        print(json.dumps(alerta_de(e) | {"id_alerta_origen": "…"}, ensure_ascii=False, indent=2))
        print(f"   PROPUESTA DEL SISTEMA → categoría: {inc['categoria'] or 'a revisar'} · severidad: {inc['severidad']} "
              f"· confianza {inc['confianza_clasificacion']}")
        print(GUIA.format(cats="\n".join(f"  {i}. {n} [{imp}]" for i, (_, n, imp) in enumerate(CATEGORIAS, 1)),
                          activos=", ".join(f"{k} {v}" for k, v in ACTIVOS.items())))
        acc = pedir("   ¿Confirma la propuesta? (s = confirmar / n = corregir): ", {"s", "n"})
        cuerpo = {}
        if acc == "n" or inc["categoria"] is None:
            cuerpo = {"categoria_clave": elegir_categoria(),
                      "severidad": SEVERIDADES[pedir("   Severidad (b/m/a/c): ", set(SEVERIDADES))]}
        r = requests.post(f"{API}/incidentes/{inc['id_incidente']}/clasificacion/confirmar", json=cuerpo, headers=h, timeout=10)
        r.raise_for_status(); d = r.json()
        filas.append({"modo": "prototipo", "escenario": e[0], "categoria": d["categoria_clave"], "categoria_correcta": d["categoria_clave"] == e[8],
                      "severidad": d["severidad"], "severidad_correcta": d["severidad"] == e[9], "corrigio_propuesta": acc == "n",
                      "segundos": d["tiempo_triaje_completo_seg"], "incidente": d["id_incidente"]})
        print(f"   → confirmado: {d['tiempo_triaje_completo_seg']:.1f} s desde la recepción (medido por el servidor)")
    guardar("prototipo", filas)


def modo_manual():
    orden = ESCENARIOS[:]; random.Random(29).shuffle(orden); filas = []
    print("MODO MANUAL — la misma alerta, sin propuesta: clasifique con la guía de la organización.")
    for e in orden:
        input(f"\n[{e[0]}] Presione Enter para recibir la próxima alerta…")
        t0 = time.perf_counter()
        print(json.dumps(alerta_de(e) | {"id_alerta_origen": "…"}, ensure_ascii=False, indent=2))
        print(GUIA.format(cats="\n".join(f"  {i}. {n} [{imp}]" for i, (_, n, imp) in enumerate(CATEGORIAS, 1)),
                          activos=", ".join(f"{k} {v}" for k, v in ACTIVOS.items())))
        cat = elegir_categoria()
        sev = SEVERIDADES[pedir("   Severidad (b/m/a/c): ", set(SEVERIDADES))]
        pedir("   ¿Confirma la clasificación? (s): ", {"s"})
        seg = round(time.perf_counter() - t0, 1)
        filas.append({"modo": "manual", "escenario": e[0], "categoria": cat, "categoria_correcta": cat == e[8], "severidad": sev,
                      "severidad_correcta": sev == e[9], "corrigio_propuesta": "", "segundos": seg, "incidente": ""})
        print(f"   → confirmado: {seg:.1f} s desde la recepción")
    guardar("manual", filas)


def modo_resumen():
    for modo in ("prototipo", "manual"):
        archivos = sorted(SALIDA.glob(f"triaje_{modo}_*.csv"))
        if not archivos:
            print(f"Sin mediciones de «{modo}»"); continue
        with open(archivos[-1], encoding="utf-8") as fh:
            resumen_de(modo, list(csv.DictReader(fh)))


if __name__ == "__main__":
    {"prototipo": modo_prototipo, "manual": modo_manual, "resumen": modo_resumen}[sys.argv[1] if len(sys.argv) > 1 else "resumen"]()
