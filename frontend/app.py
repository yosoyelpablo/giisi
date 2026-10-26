"""GIISI — interfaz web del prototipo (Streamlit).

Implementa las pantallas diseñadas en la Entrega 2: panel principal (KPI + kanban),
detalle de incidente (información, línea de tiempo, playbook y audit log) y ejecución
de playbook. Se comunica con la API mediante HTTP con el token JWT del usuario.
"""
import json
import os
import requests
import streamlit as st

API = os.getenv("API_URL", "http://127.0.0.1:8000")   # 127.0.0.1: evita la demora de Windows con «localhost» (IPv6)
SEV_COLOR = {"Crítica": "#c0392b", "Alta": "#e07b28", "Media": "#e6b800", "Baja": "#3f8f4f", None: "#7b8494"}
ESTADOS = ["Nuevo", "En análisis", "Contenido", "Resuelto", "Cerrado"]
CSF_COLOR = {"Responder": "#c0522a", "Detectar": "#2f4a86", "Recuperar": "#7a4fa0"}

st.set_page_config(page_title="GIISI · Gestión de incidentes", page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------- API helpers
def api(method, path, **kw):
    headers = kw.pop("headers", {})
    if "token" in st.session_state:
        headers["Authorization"] = f"Bearer {st.session_state.token}"
    r = requests.request(method, f"{API}{path}", headers=headers, timeout=15, **kw)
    if r.status_code == 401 and "token" in st.session_state:
        st.session_state.clear(); st.rerun()
    return r


def error(r):
    try:
        st.error(r.json().get("detail", r.text))
    except Exception:
        st.error(r.text)


def num(x, d=0):
    """Número con coma decimal (convención del documento)."""
    return f"{x:.{d}f}".replace(".", ",")


def badge(texto, color):
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:6px;font-size:0.8em;font-weight:600">{texto}</span>'


# ---------------------------------------------------------------- login (HU-008)
def pantalla_login():
    st.markdown("## 🛡️ GIISI · Gestión de incidentes de seguridad informática")
    st.caption("Prototipo alineado con NIST SP 800-61 rev. 3 (CSF 2.0) e ISO/IEC 27035 — Universidad Siglo 21")
    with st.form("login"):
        email = st.text_input("Correo electrónico", value="operador@giisi.local")
        password = st.text_input("Contraseña", type="password")
        if st.form_submit_button("Ingresar", type="primary"):
            r = api("POST", "/auth/login", json={"email": email, "password": password})
            if r.status_code == 200:
                d = r.json()
                st.session_state.update(token=d["access_token"], rol=d["rol"], nombre=d["nombre"], permisos=d["permisos"])
                st.rerun()
            else:
                error(r)
    st.info("Usuarios de demostración: operador@ · coordinador@ · gerente@ · admin@giisi.local (misma contraseña del seed).")


# ---------------------------------------------------------------- panel principal (HU-005, HU-010)
def pantalla_panel():
    st.markdown("## Panel principal")
    m = api("GET", "/metricas").json()
    c1, c2, c3, c4 = st.columns(4)
    tc = m.get("tiempo_triaje_completo_promedio_seg")
    c1.metric("Triaje completo", f"{num(tc, 0)} s" if tc is not None else "—",
              help="Desde la recepción de la alerta hasta que una persona confirma la clasificación y la severidad")
    c2.metric("Tiempo de respuesta", f"{num(m['mttr_promedio_min'], 0)} min" if m["mttr_promedio_min"] is not None else "—",
              help="Desde la recepción de la alerta hasta la contención (lo mejora el prototipo)")
    c3.metric("Incidentes abiertos", m["incidentes_abiertos"])
    c4.metric("Clasificación automática", f"{num(m['tasa_clasificacion_automatica'], 0)} %" if m["tasa_clasificacion_automatica"] is not None else "—")
    st.caption(("✅ Audit log íntegro" if m["integridad_audit_log"] else "⚠️ Audit log con inconsistencias")
               + (f" · propuesta automática del motor de reglas: {num(m['tiempo_triaje_promedio_seg'], 2)} s" if m["tiempo_triaje_promedio_seg"] is not None else "")
               + f" · {m['incidentes_totales']} incidentes en total"
               + (f" · latencia de la fuente externa (evento → alerta): {num(m['latencia_alerta_promedio_min'], 0)} min, fuera del alcance del prototipo" if m["latencia_alerta_promedio_min"] is not None else ""))
    st.markdown("### Tablero de incidentes (kanban)")
    incs = api("GET", "/incidentes").json()
    cols = st.columns(len(ESTADOS))
    for col, estado in zip(cols, ESTADOS):
        with col:
            st.markdown(f"**{estado}**")
            for i in [x for x in incs if x["estado"] == estado]:
                with st.container(border=True):
                    st.markdown(f"INC-{i['id_incidente']:03d} {badge(i['severidad'] or 'Sin severidad', SEV_COLOR[i['severidad']])}",
                                unsafe_allow_html=True)
                    st.markdown(f"**{i['titulo']}**")
                    st.caption(f"{i['categoria'] or '⚠️ a revisar'} · {i['activo'] or '—'}")
                    if st.button("Abrir", key=f"abrir{i['id_incidente']}"):
                        st.session_state.incidente = i["id_incidente"]; st.session_state.vista = "Detalle"; st.rerun()


# ---------------------------------------------------------------- detalle (HU-006, HU-007, HU-011)
def pantalla_detalle():
    incs = api("GET", "/incidentes").json()
    if not incs:
        st.info("No hay incidentes registrados."); return
    ids = [i["id_incidente"] for i in incs]
    actual = st.session_state.get("incidente", ids[0])
    sel = st.selectbox("Incidente", ids, index=ids.index(actual) if actual in ids else 0,
                       format_func=lambda x: f"INC-{x:03d} · " + next(i["titulo"] for i in incs if i["id_incidente"] == x))
    st.session_state.incidente = sel
    inc = api("GET", f"/incidentes/{sel}").json()

    st.markdown(f"## INC-{inc['id_incidente']:03d} · {inc['titulo']} &nbsp; "
                f"{badge(inc['severidad'] or 'Sin severidad', SEV_COLOR[inc['severidad']])} "
                f"{badge(inc['estado'], '#2f4a86')}", unsafe_allow_html=True)
    st.caption(f"Categoría NIST: {inc['categoria'] or '⚠️ a revisar'} · Activo: {inc['activo']} · "
               f"Asignado: {inc['asignado'] or '—'} · Origen: {inc['origen']}")

    izq, der = st.columns([1, 1])
    with izq:
        st.markdown("#### Información")
        st.write(inc["descripcion"] or "—")
        st.write(f"**Recepción de la alerta (T0):** {inc['fecha_recepcion'][:16].replace('T', ' ')} UTC")
        st.write(f"**Latencia de la fuente externa (evento → alerta):** {num(inc['latencia_alerta_min'], 0)} min — contexto, fuera del prototipo" if inc["latencia_alerta_min"] is not None else "**Latencia de la fuente externa:** —")
        st.write(f"**Propuesta automática (clasificación y severidad):** {num(inc['tiempo_triaje_seg'], 2)} s desde T0" if inc["tiempo_triaje_seg"] is not None else "**Propuesta automática:** —")
        st.write(f"**Triaje completo (hasta la confirmación humana):** {num(inc['tiempo_triaje_completo_seg'], 0)} s" if inc.get("tiempo_triaje_completo_seg") is not None else "**Triaje completo:** — (clasificación sin confirmar)")
        st.write(f"**Tiempo de respuesta:** {num(inc['mttr_min'], 0)} min" if inc["mttr_min"] is not None else "**Tiempo de respuesta:** — (sin contención aún)")
        if inc["confianza_clasificacion"] is not None:
            st.write(f"**Confianza de clasificación:** {num(inc['confianza_clasificacion'], 2)}")

        st.markdown("#### Registro de acciones (audit log · integridad verificable)")
        log = api("GET", f"/incidentes/{sel}/auditoria").json()
        for a in log:
            st.markdown(f"`{a['timestamp'][11:19]}` **{a['actor']}** — {a['descripcion']}  "
                        f"<span style='color:#7b8494;font-family:monospace;font-size:0.75em'>{a['hash_actual'][:12]}…</span>",
                        unsafe_allow_html=True)

    with der:
        st.markdown("#### Triaje")
        puede_clasificar = "incidentes:clasificar" in st.session_state.permisos or "*" in st.session_state.permisos
        if inc.get("fecha_confirmacion"):
            st.success(f"Clasificación confirmada: {inc['categoria']} · severidad {inc['severidad']} "
                       f"({num(inc['tiempo_triaje_completo_seg'], 0)} s desde la recepción)")
        elif puede_clasificar and inc["estado"] != "Cerrado":
            st.caption("Revise la propuesta del motor de reglas y confírmela o corríjala.")
            cats = api("GET", "/categorias").json()
            claves = [c["clave"] for c in cats]
            c_sel = st.selectbox("Categoría NIST", claves, format_func=lambda k: next(c["nombre"] for c in cats if c["clave"] == k),
                                 index=claves.index(inc["categoria_clave"]) if inc["categoria_clave"] in claves else 0, key=f"cat{sel}")
            s_sel = st.selectbox("Severidad", ["Baja", "Media", "Alta", "Crítica"],
                                 index=["Baja", "Media", "Alta", "Crítica"].index(inc["severidad"]) if inc["severidad"] else 1, key=f"sev{sel}")
            if st.button("✔ Confirmar clasificación", type="primary"):
                r = api("POST", f"/incidentes/{sel}/clasificacion/confirmar", json={"categoria_clave": c_sel, "severidad": s_sel})
                st.rerun() if r.status_code == 200 else error(r)
        else:
            st.info("Clasificación pendiente de confirmación por el operador.")
        st.markdown("#### Playbook")
        ej = api("GET", f"/incidentes/{sel}/playbook").json()
        puede_ejecutar = "playbook:ejecutar" in st.session_state.permisos or "*" in st.session_state.permisos
        if ej is None:
            if inc["estado"] == "Cerrado":
                st.info("Incidente cerrado.")
            elif inc["categoria"] is None:
                st.warning("El incidente está «a revisar»: no tiene categoría, por lo que no hay playbook asociado.")
            elif puede_ejecutar and st.button("▶ Iniciar playbook", type="primary"):
                r = api("POST", f"/incidentes/{sel}/playbook/iniciar")
                (st.rerun() if r.status_code == 200 else error(r))
        else:
            hechos = sum(p["completado"] for p in ej["pasos"])
            st.progress(hechos / len(ej["pasos"]), text=f"{ej['playbook']} — {hechos}/{len(ej['pasos'])} pasos · {ej['estado']}")
            for p in ej["pasos"]:
                with st.container(border=True):
                    c1, c2 = st.columns([5, 1])
                    c1.markdown(f"{'✅' if p['completado'] else '⬜'} **Paso {p['orden']}.** {p['descripcion']}  "
                                f"{badge(p['funcion_csf'], CSF_COLOR.get(p['funcion_csf'], '#555'))}", unsafe_allow_html=True)
                    c1.caption(f"Responsable: {p['rol_responsable']}" + (f" · completado por {p['completado_por']}" if p["completado"] else ""))
                    if p["completado"] and p["notas"]:
                        c1.caption(f"Notas: {p['notas']}")
                    if not p["completado"] and puede_ejecutar and ej["estado"] == "En curso":
                        notas = c1.text_input("Notas", key=f"n{p['id_paso']}", label_visibility="collapsed", placeholder="Notas del paso")
                        if c2.button("Completar", key=f"c{p['id_paso']}"):
                            r = api("POST", f"/incidentes/{sel}/playbook/pasos/{p['id_paso']}/completar", json={"notas": notas})
                            (st.rerun() if r.status_code == 200 else error(r))

        if inc["estado"] == "Resuelto" and ("incidentes:cerrar" in st.session_state.permisos or "*" in st.session_state.permisos):
            st.markdown("#### Cierre con lecciones aprendidas")
            with st.form("cerrar"):
                leccion = st.text_area("Lección aprendida")
                reco = st.text_input("Recomendación")
                if st.form_submit_button("Cerrar incidente", type="primary"):
                    r = api("POST", f"/incidentes/{sel}/cerrar", json={"leccion": leccion, "recomendacion": reco})
                    (st.rerun() if r.status_code == 200 else error(r))
        if inc["estado"] == "Cerrado":
            for l in api("GET", f"/incidentes/{sel}/lecciones").json():
                st.success(f"**Lección aprendida:** {l['descripcion']}" + (f"\n\n**Recomendación:** {l['recomendacion']}" if l["recomendacion"] else ""))


# ---------------------------------------------------------------- alta manual (HU-002)
def pantalla_alta():
    st.markdown("## Registrar incidente manualmente")
    with st.form("alta"):
        titulo = st.text_input("Título")
        descripcion = st.text_area("Descripción")
        activo = st.text_input("Activo afectado", placeholder="SRV-FILES-01")
        if st.form_submit_button("Registrar", type="primary"):
            r = api("POST", "/incidentes", json={"titulo": titulo, "descripcion": descripcion, "activo": activo})
            if r.status_code == 201:
                st.success(f"Incidente INC-{r.json()['id_incidente']:03d} creado · clasificación: "
                           f"{r.json()['categoria'] or 'a revisar'} · severidad {r.json()['severidad']}")
            else:
                error(r)


# ---------------------------------------------------------------- playbooks + integridad
def pantalla_playbooks():
    st.markdown("## Playbooks disponibles")
    for pb in api("GET", "/playbooks").json():
        with st.expander(f"{pb['nombre']} · {pb['categoria']} · {len(pb['pasos'])} pasos"):
            for p in pb["pasos"]:
                st.markdown(f"**{p['orden']}.** {p['descripcion']} {badge(p['funcion_csf'], CSF_COLOR.get(p['funcion_csf'], '#555'))} "
                            f"<span style='color:#7b8494'>· {p['rol_responsable']}</span>", unsafe_allow_html=True)


def pantalla_integridad():
    st.markdown("## Verificación de integridad del audit log")
    st.write("Recorre toda la cadena de hashes y recalcula cada registro. Cualquier modificación o eliminación se detecta.")
    if st.button("Verificar ahora", type="primary"):
        r = api("GET", "/auditoria/verificar")
        if r.status_code == 200:
            d = r.json()
            (st.success if d["integra"] else st.error)(f"{'✅ Cadena íntegra' if d['integra'] else '⚠️ Cadena rota'} · "
                                                        f"{d['registros']} registros" + (f" · último hash {d['ultimo_hash'][:16]}…" if d["integra"] else f" · primer fallo en el registro {d['primer_fallo']}: {d['motivo']}"))
        else:
            error(r)

    st.markdown("### Referencia externa firmada")
    st.write("La cadena de hashes detecta alteraciones, pero quien tenga acceso de escritura a la base podría recalcularla "
             "entera. Por eso se exporta periódicamente el estado de la cadena firmado (HMAC-SHA256, con una clave que no está "
             "en la base) y se guarda en un almacenamiento inmutable. Comparar la cadena actual con una exportación anterior "
             "detecta una reconstrucción.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Exportar referencia firmada"):
            r = api("GET", "/auditoria/exportar")
            if r.status_code == 200:
                st.session_state.exportacion = r.json()
            else:
                error(r)
        if st.session_state.get("exportacion"):
            exp = st.session_state.exportacion
            st.json(exp)
            st.download_button("Descargar exportación (JSON)", json.dumps(exp, ensure_ascii=False, indent=2),
                               file_name=f"giisi_referencia_{exp['referencia']['ultimo_id']}.json", mime="application/json")
    with c2:
        archivo = st.file_uploader("Verificar contra una exportación anterior", type="json")
        if archivo is not None and st.button("Verificar contra la exportación", type="primary"):
            r = api("POST", "/auditoria/verificar-exportacion", json=json.loads(archivo.getvalue()))
            if r.status_code == 200:
                d = r.json(); (st.success if d["coincide"] else st.error)(d["motivo"])
            else:
                error(r)


# ---------------------------------------------------------------- navegación
if "token" not in st.session_state:
    pantalla_login()
else:
    with st.sidebar:
        st.markdown("### 🛡️ GIISI")
        st.caption(f"{st.session_state.nombre} · {st.session_state.rol}")
        vistas = ["Panel", "Detalle", "Registrar incidente", "Playbooks"]
        if "*" in st.session_state.permisos:
            vistas.append("Integridad")
        vista = st.radio("Sección", vistas, index=vistas.index(st.session_state.get("vista", "Panel")), label_visibility="collapsed")
        st.session_state.vista = vista
        if st.button("Cerrar sesión"):
            st.session_state.clear(); st.rerun()
    {"Panel": pantalla_panel, "Detalle": pantalla_detalle, "Registrar incidente": pantalla_alta,
     "Playbooks": pantalla_playbooks, "Integridad": pantalla_integridad}[vista]()
