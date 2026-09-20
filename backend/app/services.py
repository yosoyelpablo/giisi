"""Lógica de negocio del prototipo: ingesta, clasificación, ciclo de vida, playbooks, cierre y métricas."""
import json
from datetime import datetime, timedelta
from .util import utcnow
from typing import Optional
from fastapi import HTTPException
from sqlmodel import Session, select
from . import config, rules
from .audit import registrar, verificar
from .models import (Incidente, Alerta, CategoriaNist, Activo, Usuario, Playbook, PasoPlaybook,
                     EjecucionPlaybook, PasoEjecutado, LeccionAprendida, TRANSICIONES, SEVERIDADES)
from .schemas import AlertaIn, IncidenteManualIn, IncidenteOut, EjecucionOut, PasoOut, MetricasOut


# ---------------------------------------------------------------- utilidades
def _minutos(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
    if a is None or b is None:
        return None
    return round(max(0.0, (b - a).total_seconds() / 60.0), 1)


def _activo_por_nombre(session: Session, nombre: str, ip: Optional[str] = None) -> Activo:
    activo = session.exec(select(Activo).where(Activo.nombre == nombre)).first()
    if activo is None:  # activo desconocido: se registra con criticidad media
        activo = Activo(nombre=nombre, tipo="Desconocido", criticidad=3, direccion_ip=ip)
        session.add(activo); session.commit(); session.refresh(activo)
    return activo


def a_out(session: Session, inc: Incidente) -> IncidenteOut:
    cat = session.get(CategoriaNist, inc.id_categoria) if inc.id_categoria else None
    act = session.get(Activo, inc.id_activo) if inc.id_activo else None
    usr = session.get(Usuario, inc.id_usuario_asig) if inc.id_usuario_asig else None
    return IncidenteOut(
        id_incidente=inc.id_incidente, titulo=inc.titulo, descripcion=inc.descripcion, estado=inc.estado,
        severidad=inc.severidad, categoria=cat.nombre if cat else None, categoria_clave=cat.clave if cat else None,
        activo=act.nombre if act else None, asignado=usr.nombre if usr else None,
        fecha_ocurrencia=inc.fecha_ocurrencia, fecha_deteccion=inc.fecha_deteccion,
        fecha_contencion=inc.fecha_contencion, fecha_cierre=inc.fecha_cierre,
        mttd_min=inc.mttd_min, mttr_min=inc.mttr_min, confianza_clasificacion=inc.confianza_clasificacion,
        a_revisar=inc.a_revisar, origen=inc.origen)


# ---------------------------------------------------------------- clasificación + severidad
def clasificar_y_priorizar(session: Session, inc: Incidente, texto: str, nivel: int,
                           categoria_sugerida: Optional[str], actor: str = "motor de reglas") -> None:
    res = rules.clasificar(texto, categoria_sugerida)
    inc.confianza_clasificacion = res["confianza"]; inc.a_revisar = res["a_revisar"]
    cat = session.exec(select(CategoriaNist).where(CategoriaNist.clave == res["clave"])).first() if res["clave"] else None
    if cat and not res["a_revisar"]:
        inc.id_categoria = cat.id_categoria
        registrar(session, f"Clasificó como «{cat.nombre}» (confianza {res['confianza']:.2f}; reglas: "
                  f"{', '.join(res['reglas_aplicadas'])})", actor=actor, id_incidente=inc.id_incidente)
    else:
        registrar(session, f"Clasificación por debajo del umbral (confianza {res['confianza']:.2f}); "
                  f"marcado «a revisar» para clasificación manual", actor=actor, id_incidente=inc.id_incidente)
    activo = session.get(Activo, inc.id_activo) if inc.id_activo else None
    sev = rules.severidad(nivel, cat.impacto_informacion if cat else 2, activo.criticidad if activo else 3)
    inc.severidad = sev["severidad"]
    registrar(session, f"Calculó severidad {sev['severidad']} (funcional {sev['funcional']} × información "
              f"{sev['informacion']} × recuperabilidad {sev['recuperabilidad']} = {sev['puntaje']})",
              actor=actor, id_incidente=inc.id_incidente)
    if sev["severidad"] in ("Alta", "Crítica"):
        registrar(session, f"Notificó al coordinador de respuesta (severidad {sev['severidad']})",
                  actor="sistema", id_incidente=inc.id_incidente)
    session.add(inc); session.commit(); session.refresh(inc)


# ---------------------------------------------------------------- ingesta (HU-001)
def ingestar_alerta(session: Session, alerta: AlertaIn) -> tuple[Incidente, bool]:
    """Crea (o asocia a) un incidente a partir de una alerta. Devuelve (incidente, creado)."""
    if alerta.id_alerta_origen:
        limite = utcnow() - timedelta(minutes=config.DEDUP_WINDOW_MINUTES)
        previa = session.exec(select(Alerta).where(Alerta.origen == alerta.origen,
                                                    Alerta.id_alerta_origen == alerta.id_alerta_origen,
                                                    Alerta.fecha_recepcion >= limite)).first()
        if previa:
            inc = session.get(Incidente, previa.id_incidente)
            session.add(Alerta(origen=alerta.origen, id_alerta_origen=alerta.id_alerta_origen,
                               payload_json=alerta.model_dump_json(), id_incidente=inc.id_incidente))
            session.commit()
            registrar(session, f"Alerta duplicada de {alerta.origen} asociada al incidente existente",
                      actor="sistema", id_incidente=inc.id_incidente)
            return inc, False
    activo = _activo_por_nombre(session, alerta.activo.nombre, alerta.activo.direccion_ip)
    inc = Incidente(titulo=f"{alerta.regla.descripcion} en {activo.nombre}", descripcion=alerta.detalle,
                    id_activo=activo.id_activo, fecha_ocurrencia=alerta.timestamp.replace(tzinfo=None),
                    origen="webhook")
    inc.mttd_min = _minutos(inc.fecha_ocurrencia, inc.fecha_deteccion)
    session.add(inc); session.commit(); session.refresh(inc)
    session.add(Alerta(origen=alerta.origen, id_alerta_origen=alerta.id_alerta_origen,
                       payload_json=alerta.model_dump_json(), id_incidente=inc.id_incidente))
    session.commit()
    registrar(session, f"Alerta recibida desde {alerta.origen} (regla {alerta.regla.id}, nivel {alerta.regla.nivel}); "
              f"incidente creado en estado «Nuevo»", actor="sistema", id_incidente=inc.id_incidente)
    texto = " ".join([alerta.regla.descripcion, alerta.detalle, alerta.categoria_sugerida or ""])
    clasificar_y_priorizar(session, inc, texto, alerta.regla.nivel, alerta.categoria_sugerida)
    return inc, True


# ---------------------------------------------------------------- alta manual (HU-002)
def crear_manual(session: Session, datos: IncidenteManualIn, usuario) -> Incidente:
    activo = _activo_por_nombre(session, datos.activo)
    inc = Incidente(titulo=datos.titulo, descripcion=datos.descripcion, id_activo=activo.id_activo,
                    fecha_ocurrencia=datos.fecha_ocurrencia, origen="manual")
    inc.mttd_min = _minutos(inc.fecha_ocurrencia, inc.fecha_deteccion)
    session.add(inc); session.commit(); session.refresh(inc)
    registrar(session, "Incidente registrado manualmente en estado «Nuevo»", actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    clasificar_y_priorizar(session, inc, f"{datos.titulo} {datos.descripcion}", 8, None)
    return inc


# ---------------------------------------------------------------- ciclo de vida (HU-005)
def cambiar_estado(session: Session, inc: Incidente, nuevo: str, usuario) -> Incidente:
    if nuevo not in TRANSICIONES.get(inc.estado, []):
        raise HTTPException(400, f"Transición no permitida: «{inc.estado}» → «{nuevo}»")
    if nuevo == "Cerrado":
        raise HTTPException(400, "El cierre se realiza con el registro de lecciones aprendidas (POST /cerrar)")
    anterior, inc.estado = inc.estado, nuevo
    if nuevo == "Contenido" and inc.fecha_contencion is None:
        inc.fecha_contencion = utcnow()
        inc.mttr_min = _minutos(inc.fecha_deteccion, inc.fecha_contencion)
    session.add(inc); session.commit(); session.refresh(inc)
    registrar(session, f"Cambió el estado de «{anterior}» a «{nuevo}»", actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    return inc


def asignar(session: Session, inc: Incidente, id_usuario: int, usuario) -> Incidente:
    destino = session.get(Usuario, id_usuario)
    if not destino:
        raise HTTPException(404, "Usuario no encontrado")
    inc.id_usuario_asig = id_usuario; session.add(inc); session.commit(); session.refresh(inc)
    registrar(session, f"Asignó el incidente a {destino.nombre}", actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    return inc


def cambiar_severidad(session: Session, inc: Incidente, sev: str, usuario) -> Incidente:
    if sev not in SEVERIDADES:
        raise HTTPException(400, f"Severidad inválida; valores: {SEVERIDADES}")
    anterior, inc.severidad = inc.severidad, sev
    session.add(inc); session.commit(); session.refresh(inc)
    registrar(session, f"Modificó la severidad de {anterior} a {sev}", actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    return inc


# ---------------------------------------------------------------- playbooks (HU-006)
def iniciar_playbook(session: Session, inc: Incidente, usuario) -> EjecucionPlaybook:
    if not inc.id_categoria:
        raise HTTPException(400, "El incidente no tiene categoría; clasifíquelo antes de iniciar un playbook")
    activa = session.exec(select(EjecucionPlaybook).where(EjecucionPlaybook.id_incidente == inc.id_incidente,
                                                          EjecucionPlaybook.estado == "En curso")).first()
    if activa:
        return activa
    pb = session.exec(select(Playbook).where(Playbook.id_categoria == inc.id_categoria)).first()
    if not pb:
        raise HTTPException(404, "No existe un playbook para la categoría del incidente")
    ej = EjecucionPlaybook(id_incidente=inc.id_incidente, id_playbook=pb.id_playbook)
    session.add(ej); session.commit(); session.refresh(ej)
    for paso in session.exec(select(PasoPlaybook).where(PasoPlaybook.id_playbook == pb.id_playbook)):
        session.add(PasoEjecutado(id_ejecucion=ej.id_ejecucion, id_paso=paso.id_paso))
    session.commit()
    if inc.estado == "Nuevo":
        cambiar_estado(session, inc, "En análisis", usuario)
    registrar(session, f"Inició el playbook «{pb.nombre}»", actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    return ej


def ejecucion_out(session: Session, ej: EjecucionPlaybook) -> EjecucionOut:
    pb = session.get(Playbook, ej.id_playbook)
    pasos = []
    for pe in session.exec(select(PasoEjecutado).where(PasoEjecutado.id_ejecucion == ej.id_ejecucion)):
        p = session.get(PasoPlaybook, pe.id_paso)
        u = session.get(Usuario, pe.id_usuario) if pe.id_usuario else None
        pasos.append(PasoOut(id_paso=p.id_paso, orden=p.orden, descripcion=p.descripcion, funcion_csf=p.funcion_csf,
                             rol_responsable=p.rol_responsable, completado=pe.completado, notas=pe.notas,
                             completado_por=u.nombre if u else None, timestamp=pe.timestamp))
    pasos.sort(key=lambda x: x.orden)
    return EjecucionOut(id_ejecucion=ej.id_ejecucion, playbook=pb.nombre, estado=ej.estado,
                        fecha_inicio=ej.fecha_inicio, fecha_fin=ej.fecha_fin, pasos=pasos)


def completar_paso(session: Session, inc: Incidente, id_paso: int, notas: str, usuario) -> EjecucionOut:
    ej = session.exec(select(EjecucionPlaybook).where(EjecucionPlaybook.id_incidente == inc.id_incidente,
                                                      EjecucionPlaybook.estado == "En curso")).first()
    if not ej:
        raise HTTPException(400, "No hay un playbook en curso para este incidente")
    pe = session.exec(select(PasoEjecutado).where(PasoEjecutado.id_ejecucion == ej.id_ejecucion,
                                                   PasoEjecutado.id_paso == id_paso)).first()
    if not pe:
        raise HTTPException(404, "El paso no pertenece al playbook en curso")
    if pe.completado:
        raise HTTPException(400, "El paso ya fue completado")
    paso = session.get(PasoPlaybook, id_paso)
    pe.completado, pe.notas, pe.id_usuario, pe.timestamp = True, notas, usuario.id_usuario, utcnow()
    session.add(pe); session.commit()
    registrar(session, f"Completó el paso {paso.orden} «{paso.descripcion}» [{paso.funcion_csf}]"
              + (f" — notas: {notas}" if notas else ""), actor=usuario.email,
              id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario, id_paso=id_paso)
    # primer paso de contención completado -> el incidente pasa a «Contenido»
    if paso.orden == 1 and inc.estado == "En análisis":
        cambiar_estado(session, inc, "Contenido", usuario)
    restantes = session.exec(select(PasoEjecutado).where(PasoEjecutado.id_ejecucion == ej.id_ejecucion,
                                                          PasoEjecutado.completado == False)).all()  # noqa: E712
    if not restantes:
        ej.estado, ej.fecha_fin = "Completado", utcnow(); session.add(ej); session.commit()
        registrar(session, "Completó todos los pasos del playbook", actor=usuario.email,
                  id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
        if inc.estado in ("En análisis", "Contenido"):
            cambiar_estado(session, inc, "Resuelto", usuario)
    session.refresh(ej)
    return ejecucion_out(session, ej)


# ---------------------------------------------------------------- cierre (HU-011)
def cerrar(session: Session, inc: Incidente, leccion: str, recomendacion: str, usuario) -> Incidente:
    if inc.estado != "Resuelto":
        raise HTTPException(400, "Solo se cierra un incidente en estado «Resuelto»")
    session.add(LeccionAprendida(id_incidente=inc.id_incidente, descripcion=leccion, recomendacion=recomendacion))
    inc.estado, inc.fecha_cierre = "Cerrado", utcnow()
    session.add(inc); session.commit(); session.refresh(inc)
    registrar(session, f"Registró lecciones aprendidas y cerró el incidente: {leccion[:120]}",
              actor=usuario.email, id_incidente=inc.id_incidente, id_usuario=usuario.id_usuario)
    return inc


# ---------------------------------------------------------------- métricas (HU-010)
def metricas(session: Session) -> MetricasOut:
    incs = session.exec(select(Incidente)).all()
    por_estado = {}; por_sev = {}
    for i in incs:
        por_estado[i.estado] = por_estado.get(i.estado, 0) + 1
        if i.severidad: por_sev[i.severidad] = por_sev.get(i.severidad, 0) + 1
    mttd = [i.mttd_min for i in incs if i.mttd_min is not None]
    mttr = [i.mttr_min for i in incs if i.mttr_min is not None]
    clasif = [i for i in incs if i.confianza_clasificacion is not None]
    tasa = round(100.0 * sum(1 for i in clasif if not i.a_revisar) / len(clasif), 1) if clasif else None
    return MetricasOut(
        incidentes_totales=len(incs), incidentes_abiertos=sum(1 for i in incs if i.estado != "Cerrado"),
        por_estado=por_estado, por_severidad=por_sev,
        mttd_promedio_min=round(sum(mttd) / len(mttd), 1) if mttd else None,
        mttr_promedio_min=round(sum(mttr) / len(mttr), 1) if mttr else None,
        tasa_clasificacion_automatica=tasa, integridad_audit_log=verificar(session)["integra"])
