"""Medición del tiempo de respuesta en condiciones equivalentes (complementa la medición del triaje).

Compara dos procedimientos sobre los MISMOS tres escenarios —los que tienen playbook: ransomware,
acceso no autorizado y filtración de datos— y mide, en ambos, desde la recepción de la alerta (T0)
hasta el INICIO DE LA CONTENCIÓN: el registro del primer paso del playbook, que es el de contención.

  prototipo  la alerta entra por el webhook; el operador confirma o corrige la propuesta de triaje,
             inicia el playbook que el sistema asigna según la categoría y completa el paso de
             contención con una nota. El tiempo lo calcula el servidor: contención − recepción.
  manual     el operador recibe la misma alerta, sin propuesta, la clasifica con la guía de la
             organización, elige el procedimiento en el manual de la organización (los mismos tres
             playbooks, como documento) y registra a mano la acción de contención. El tiempo se mide
             desde que se muestra la alerta hasta el Enter de esa nota.

Ambos modos usan la consola, la misma alerta, la misma guía de triaje y el mismo contenido de los
playbooks, que en los dos aparece después del triaje: la diferencia medida es la asistencia del
sistema (propuesta, playbook asignado y registro). Se guarda además el corte del triaje (seg_triaje).
El operador atiende cada alerta apenas la recibe: no se mide la espera hasta la atención ni la
ejecución real de la acción, solo su registro.

Consigna (igual en los dos modos, fijada antes de medir): leer la alerta y verificar la categoría y
la severidad con la guía antes de responder; la nota describe en una línea la acción realizada.
Regla de descarte: un escenario con seg_triaje menor a 5 s se informa como «confirmado sin leer» y
no se usa; si la corrida se corta, se conservan las filas ya guardadas y se informa, sin repetir
los escenarios ya vistos.

Orden: primero «prototipo» y después «manual» (conservador respecto del aprendizaje). Cada modo
presenta los escenarios en un orden distinto.

Uso (con la API levantada, en la consola directa, sin redirigir la salida):
  python scripts/medir_respuesta.py prototipo
  python scripts/medir_respuesta.py manual
  python scripts/medir_respuesta.py resumen      (compara los dos CSV más recientes, por escenario)
"""
import csv, datetime, json, random, statistics, sys, time

from medir_triaje import (API, KEY, USUARIO, CLAVE, SALIDA, ESCENARIOS, CATEGORIAS, ACTIVOS, SEVERIDADES, GUIA,
                          alerta_de, pedir, elegir_categoria)

sys.stdout.reconfigure(encoding="utf-8")
CON_PLAYBOOK = [e for e in ESCENARIOS if e[0] in ("E1", "E2", "E3")]   # una alerta por playbook disponible
CAMPOS = ["modo", "escenario", "categoria", "categoria_correcta", "severidad", "severidad_correcta", "seg_triaje",
          "playbook", "primer_paso", "contencion_correcta", "segundos", "incidente", "notas"]


def guia():
    return GUIA.format(cats="\n".join(f"  {i}. {n} [{imp}]" for i, (_, n, imp) in enumerate(CATEGORIAS, 1)),
                       activos=", ".join(f"{k} {v}" for k, v in ACTIVOS.items()))


def sesion():
    import requests
    r = requests.post(f"{API}/auth/login", json={"email": USUARIO, "password": CLAVE}, timeout=10); r.raise_for_status()
    return requests, {"Authorization": f"Bearer {r.json()['access_token']}"}


def manual_de_procedimientos(playbooks):
    lineas = ["──────────────── MANUAL DE PROCEDIMIENTOS DE LA ORGANIZACIÓN ────────────────"]
    for i, pb in enumerate(playbooks, 1):
        lineas.append(f"  {i}. {pb['nombre']} (categoría: {pb['categoria']})")
        lineas += [f"       paso {p['orden']}. {p['descripcion']} [{p['funcion_csf']} · {p['rol_responsable']}]" for p in pb["pasos"]]
    lineas.append("──────────────────────────────────────────────────────────────────────────────")
    return "\n".join(lineas)


def segundos(desde, hasta):
    return round((datetime.datetime.fromisoformat(hasta) - datetime.datetime.fromisoformat(desde)).total_seconds(), 1)


class Registro:
    """CSV que se escribe fila por fila: si la corrida se corta, lo medido ya quedó guardado."""
    def __init__(self, modo):
        SALIDA.mkdir(exist_ok=True)
        self.archivo = SALIDA / f"respuesta_{modo}_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"
        self.fh = open(self.archivo, "w", newline="", encoding="utf-8-sig")
        self.w = csv.DictWriter(self.fh, fieldnames=CAMPOS); self.w.writeheader(); self.fh.flush(); self.filas = []

    def agregar(self, fila):
        self.w.writerow(fila); self.fh.flush(); self.filas.append(fila)

    def cerrar(self, modo, total):
        self.fh.close()
        print(f"\nResultados guardados en {self.archivo} ({len(self.filas)} de {total} escenarios)")
        if self.filas: resumen_de(modo, self.filas)


def resumen_de(modo, filas):
    t = [float(x["segundos"]) for x in filas if str(x["segundos"]) != ""]
    ok = lambda campo: sum(1 for x in filas if str(x[campo]) in ("True", "1"))
    if t:
        print(f"{modo:10s} n={len(t)} · media {statistics.mean(t):.1f} s · mediana {statistics.median(t):.1f} s · "
              f"mín {min(t):.1f} s · máx {max(t):.1f} s · categoría correcta {ok('categoria_correcta')}/{len(filas)} · "
              f"severidad correcta {ok('severidad_correcta')}/{len(filas)} · contención correcta {ok('contencion_correcta')}/{len(filas)}")
    return {x["escenario"]: x for x in filas}


def modo_prototipo():
    requests, h = sesion()
    orden = CON_PLAYBOOK[:]; random.Random(13).shuffle(orden); reg = Registro("prototipo"); ids = []
    print("MODO PROTOTIPO — la alerta entra al sistema; confirme el triaje, inicie el playbook y complete la contención.")
    try:
        for e in orden:
            input(f"\n[{e[0]}] Presione Enter para recibir la próxima alerta…")
            r = requests.post(f"{API}/webhook", json=alerta_de(e), headers={"X-API-Key": KEY}, timeout=10); r.raise_for_status()
            inc = r.json()["incidente"]; iid = inc["id_incidente"]; ids.append(iid)
            print(json.dumps(alerta_de(e) | {"id_alerta_origen": "…"}, ensure_ascii=False, indent=2))
            print(f"   PROPUESTA DEL SISTEMA → categoría: {inc['categoria'] or 'a revisar'} · severidad: {inc['severidad']} "
                  f"· confianza {inc['confianza_clasificacion']}")
            print(guia())
            acc = pedir("   ¿Confirma la propuesta? (s = confirmar / n = corregir): ", {"s", "n"})
            cuerpo = {}
            if acc == "n" or inc["categoria"] is None:
                cuerpo = {"categoria_clave": elegir_categoria(),
                          "severidad": SEVERIDADES[pedir("   Severidad (b/m/a/c): ", set(SEVERIDADES))]}
            r = requests.post(f"{API}/incidentes/{iid}/clasificacion/confirmar", json=cuerpo, headers=h, timeout=10)
            r.raise_for_status(); d = r.json()
            fila = {"modo": "prototipo", "escenario": e[0], "categoria": d["categoria_clave"], "categoria_correcta": d["categoria_clave"] == e[8],
                    "severidad": d["severidad"], "severidad_correcta": d["severidad"] == e[9], "seg_triaje": d["tiempo_triaje_completo_seg"],
                    "playbook": "", "primer_paso": "", "contencion_correcta": False, "segundos": "", "incidente": iid, "notas": ""}
            input("   Presione Enter para iniciar el playbook asignado…")
            r = requests.post(f"{API}/incidentes/{iid}/playbook/iniciar", headers=h, timeout=10)
            if r.status_code == 404:   # categoría corregida a una sin playbook: se registra y se sigue
                print(f"   El sistema no tiene playbook para esa categoría: escenario registrado sin contención.")
                reg.agregar(fila | {"playbook": "(sin playbook)"}); continue
            r.raise_for_status(); ej = r.json()
            print(f"\n   PLAYBOOK ASIGNADO POR EL SISTEMA: {ej['playbook']}")
            for p in ej["pasos"]:
                print(f"     paso {p['orden']}. {p['descripcion']} [{p['funcion_csf']} · {p['rol_responsable']}]")
            primero, notas = None, []
            while True:   # hasta que el sistema registre el inicio de la contención
                n = int(pedir("   Paso que ejecuta ahora (número): ", {str(p["orden"]) for p in ej["pasos"] if not p["completado"]}))
                primero = primero or n
                notas.append(input("   Nota de lo realizado: ").strip())
                paso = next(p for p in ej["pasos"] if p["orden"] == n)
                r = requests.post(f"{API}/incidentes/{iid}/playbook/pasos/{paso['id_paso']}/completar", json={"notas": notas[-1]},
                                  headers=h, timeout=10); r.raise_for_status(); ej = r.json()
                fin = requests.get(f"{API}/incidentes/{iid}", headers=h, timeout=10).json()
                if fin["fecha_contencion"]: break
                print("   (registrado; la contención todavía no se inició)")
            seg = segundos(fin["fecha_recepcion"], fin["fecha_contencion"])
            reg.agregar(fila | {"playbook": ej["playbook"], "primer_paso": primero, "segundos": seg, "notas": " | ".join(notas),
                                "contencion_correcta": d["categoria_clave"] == e[8] and primero == 1})
            print(f"   → contención iniciada: {seg:.1f} s desde la recepción (medido por el servidor) · estado {fin['estado']}")
    except (KeyboardInterrupt, EOFError, requests.RequestException) as ex:
        print(f"\nCorrida interrumpida ({type(ex).__name__}): se conservan los escenarios ya guardados.")
    finally:
        reg.cerrar("prototipo", len(orden))
        if ids:   # evidencia del servidor: el audit log de cada incidente medido
            try:
                aud = {i: requests.get(f"{API}/incidentes/{i}/auditoria", headers=h, timeout=10).json() for i in ids}
                f = reg.archivo.with_name(reg.archivo.stem + "_auditoria.json")
                f.write_text(json.dumps(aud, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
                print(f"Audit log de los incidentes medidos: {f}")
            except requests.RequestException:
                print("No se pudo exportar el audit log: la base conserva los incidentes medidos.")


def modo_manual():
    requests, h = sesion()
    playbooks = requests.get(f"{API}/playbooks", headers=h, timeout=10).json()   # el mismo contenido, como documento
    orden = CON_PLAYBOOK[:]; random.Random(31).shuffle(orden); reg = Registro("manual")
    print("MODO MANUAL — la misma alerta, sin sistema: clasifique con la guía, elija el procedimiento del manual "
          "y registre la acción de contención.")
    try:
        for e in orden:
            input(f"\n[{e[0]}] Presione Enter para recibir la próxima alerta…")
            t0 = time.perf_counter()
            print(json.dumps(alerta_de(e) | {"id_alerta_origen": "…"}, ensure_ascii=False, indent=2))
            print(guia())
            cat = elegir_categoria()
            sev = SEVERIDADES[pedir("   Severidad (b/m/a/c): ", set(SEVERIDADES))]
            seg_triaje = round(time.perf_counter() - t0, 1)
            print(manual_de_procedimientos(playbooks))   # como en el prototipo: el procedimiento aparece después del triaje
            npb = int(pedir(f"   Procedimiento que aplica (número 1-{len(playbooks)}): ", {str(i) for i in range(1, len(playbooks) + 1)}))
            pb = playbooks[npb - 1]; primero, notas = None, []
            while True:   # el mismo punto final que el prototipo: registrar el paso de contención
                n = int(pedir("   Paso que ejecuta ahora (número): ", {str(p["orden"]) for p in pb["pasos"]}))
                primero = primero or n
                notas.append(input("   Registro manual de la acción realizada: ").strip())
                if n == 1: break
                print("   (registrado; la contención todavía no se inició)")
            seg = round(time.perf_counter() - t0, 1)
            nombre_cat = next(nom for clave, nom, _ in CATEGORIAS if clave == e[8])
            reg.agregar({"modo": "manual", "escenario": e[0], "categoria": cat, "categoria_correcta": cat == e[8], "severidad": sev,
                         "severidad_correcta": sev == e[9], "seg_triaje": seg_triaje, "playbook": pb["nombre"], "primer_paso": primero,
                         "contencion_correcta": pb["categoria"] == nombre_cat and primero == 1, "segundos": seg, "incidente": "",
                         "notas": " | ".join(notas)})
            print(f"   → contención iniciada: {seg:.1f} s desde la recepción")
    except (KeyboardInterrupt, EOFError) as ex:
        print(f"\nCorrida interrumpida ({type(ex).__name__}): se conservan los escenarios ya guardados.")
    finally:
        reg.cerrar("manual", len(orden))


def modo_resumen():
    por = {}
    for modo in ("prototipo", "manual"):
        archivos = sorted(SALIDA.glob(f"respuesta_{modo}_*.csv"))
        if not archivos:
            print(f"Sin mediciones de «{modo}»"); continue
        with open(archivos[-1], encoding="utf-8-sig") as fh:
            por[modo] = resumen_de(modo, list(csv.DictReader(fh)))
    if len(por) == 2:   # con tres pares, el resultado se informa por escenario (descriptivo, sin inferencia)
        print("\nescenario   manual (triaje)      prototipo (triaje)")
        for esc in sorted(set(por["manual"]) | set(por["prototipo"])):
            m, p = por["manual"].get(esc, {}), por["prototipo"].get(esc, {})
            print(f"{esc:10s}  {m.get('segundos', '—'):>6} s ({m.get('seg_triaje', '—'):>5} s)   "
                  f"{p.get('segundos', '—'):>6} s ({p.get('seg_triaje', '—'):>5} s)")


if __name__ == "__main__":
    {"prototipo": modo_prototipo, "manual": modo_manual, "resumen": modo_resumen}[sys.argv[1] if len(sys.argv) > 1 else "resumen"]()
