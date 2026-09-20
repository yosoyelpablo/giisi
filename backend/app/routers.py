"""Endpoints REST del prototipo. Cada operación verifica autenticación y permiso (RBAC)."""
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlmodel import Session, select
from . import config, services
from .audit import verificar
from .auth import authenticate, create_token, require, get_current_user, CurrentUser
from .database import get_session
from .models import Rol, Usuario, Incidente, Playbook, PasoPlaybook, CategoriaNist, AccionRespuesta, EjecucionPlaybook, LeccionAprendida
from .schemas import (LoginIn, TokenOut, AlertaIn, IncidenteManualIn, IncidenteOut, CambioEstadoIn, AsignarIn,
                      SeveridadIn, CompletarPasoIn, CerrarIn, EjecucionOut, AccionOut, MetricasOut)

router = APIRouter()


# ---------------------------------------------------------------- autenticación (HU-008)
@router.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(datos: LoginIn, session: Session = Depends(get_session)):
    user = authenticate(session, datos.email, datos.password)
    rol = session.get(Rol, user.id_rol)
    return TokenOut(access_token=create_token(user, rol), rol=rol.nombre, nombre=user.nombre,
                    permisos=rol.permisos.split(","))


@router.get("/auth/me", tags=["auth"])
def me(user: CurrentUser = Depends(get_current_user)):
    return {"id_usuario": user.id_usuario, "email": user.email, "nombre": user.nombre, "rol": user.rol,
            "permisos": user.permisos}


# ---------------------------------------------------------------- webhook (HU-001)
@router.post("/webhook", status_code=status.HTTP_201_CREATED, tags=["ingesta"])
def webhook(alerta: AlertaIn, x_api_key: str = Header(default=""), session: Session = Depends(get_session)):
    if x_api_key != config.WEBHOOK_API_KEY:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Clave de fuente inválida")
    inc, creado = services.ingestar_alerta(session, alerta)
    return {"creado": creado, "incidente": services.a_out(session, inc)}


# ---------------------------------------------------------------- incidentes
def _inc(session: Session, id_incidente: int) -> Incidente:
    inc = session.get(Incidente, id_incidente)
    if not inc:
        raise HTTPException(404, "Incidente no encontrado")
    return inc


@router.get("/incidentes", response_model=list[IncidenteOut], tags=["incidentes"])
def listar(session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    return [services.a_out(session, i) for i in session.exec(select(Incidente).order_by(Incidente.id_incidente.desc()))]


@router.post("/incidentes", response_model=IncidenteOut, status_code=201, tags=["incidentes"])
def crear(datos: IncidenteManualIn, session: Session = Depends(get_session), user=Depends(require("incidentes:crear"))):
    return services.a_out(session, services.crear_manual(session, datos, user))


@router.get("/incidentes/{id_incidente}", response_model=IncidenteOut, tags=["incidentes"])
def detalle(id_incidente: int, session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    return services.a_out(session, _inc(session, id_incidente))


@router.patch("/incidentes/{id_incidente}/estado", response_model=IncidenteOut, tags=["incidentes"])
def estado(id_incidente: int, datos: CambioEstadoIn, session: Session = Depends(get_session),
           user=Depends(require("playbook:ejecutar"))):
    return services.a_out(session, services.cambiar_estado(session, _inc(session, id_incidente), datos.estado, user))


@router.patch("/incidentes/{id_incidente}/asignar", response_model=IncidenteOut, tags=["incidentes"])
def asignar(id_incidente: int, datos: AsignarIn, session: Session = Depends(get_session),
            user=Depends(require("incidentes:asignar"))):
    return services.a_out(session, services.asignar(session, _inc(session, id_incidente), datos.id_usuario, user))


@router.patch("/incidentes/{id_incidente}/severidad", response_model=IncidenteOut, tags=["incidentes"])
def severidad(id_incidente: int, datos: SeveridadIn, session: Session = Depends(get_session),
              user=Depends(require("incidentes:severidad"))):
    return services.a_out(session, services.cambiar_severidad(session, _inc(session, id_incidente), datos.severidad, user))


@router.post("/incidentes/{id_incidente}/cerrar", response_model=IncidenteOut, tags=["incidentes"])
def cerrar(id_incidente: int, datos: CerrarIn, session: Session = Depends(get_session),
           user=Depends(require("incidentes:cerrar"))):
    return services.a_out(session, services.cerrar(session, _inc(session, id_incidente), datos.leccion, datos.recomendacion, user))


@router.get("/incidentes/{id_incidente}/lecciones", tags=["incidentes"])
def lecciones(id_incidente: int, session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    return session.exec(select(LeccionAprendida).where(LeccionAprendida.id_incidente == id_incidente)).all()


# ---------------------------------------------------------------- playbooks (HU-006)
@router.get("/playbooks", tags=["playbooks"])
def playbooks(session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    out = []
    for pb in session.exec(select(Playbook)):
        cat = session.get(CategoriaNist, pb.id_categoria)
        pasos = session.exec(select(PasoPlaybook).where(PasoPlaybook.id_playbook == pb.id_playbook).order_by(PasoPlaybook.orden)).all()
        out.append({"id_playbook": pb.id_playbook, "nombre": pb.nombre, "categoria": cat.nombre,
                    "pasos": [{"orden": p.orden, "descripcion": p.descripcion, "funcion_csf": p.funcion_csf,
                               "rol_responsable": p.rol_responsable} for p in pasos]})
    return out


@router.post("/incidentes/{id_incidente}/playbook/iniciar", response_model=EjecucionOut, tags=["playbooks"])
def iniciar(id_incidente: int, session: Session = Depends(get_session), user=Depends(require("playbook:ejecutar"))):
    ej = services.iniciar_playbook(session, _inc(session, id_incidente), user)
    return services.ejecucion_out(session, ej)


@router.get("/incidentes/{id_incidente}/playbook", response_model=EjecucionOut | None, tags=["playbooks"])
def ejecucion(id_incidente: int, session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    ej = session.exec(select(EjecucionPlaybook).where(EjecucionPlaybook.id_incidente == id_incidente)
                      .order_by(EjecucionPlaybook.id_ejecucion.desc())).first()
    return services.ejecucion_out(session, ej) if ej else None


@router.post("/incidentes/{id_incidente}/playbook/pasos/{id_paso}/completar", response_model=EjecucionOut, tags=["playbooks"])
def completar(id_incidente: int, id_paso: int, datos: CompletarPasoIn, session: Session = Depends(get_session),
              user=Depends(require("playbook:ejecutar"))):
    return services.completar_paso(session, _inc(session, id_incidente), id_paso, datos.notas, user)


# ---------------------------------------------------------------- audit log (HU-007)
@router.get("/incidentes/{id_incidente}/auditoria", response_model=list[AccionOut], tags=["auditoria"])
def auditoria(id_incidente: int, session: Session = Depends(get_session), user=Depends(require("incidentes:leer"))):
    return session.exec(select(AccionRespuesta).where(AccionRespuesta.id_incidente == id_incidente)
                        .order_by(AccionRespuesta.id_accion)).all()


@router.get("/auditoria/verificar", tags=["auditoria"])
def verificar_cadena(session: Session = Depends(get_session), user=Depends(require("auditoria:verificar"))):
    return verificar(session)


# ---------------------------------------------------------------- métricas (HU-010)
@router.get("/metricas", response_model=MetricasOut, tags=["metricas"])
def metricas(session: Session = Depends(get_session), user=Depends(require("metricas:leer"))):
    return services.metricas(session)


@router.get("/usuarios", tags=["auth"])
def usuarios(session: Session = Depends(get_session), user=Depends(require("incidentes:asignar"))):
    return [{"id_usuario": u.id_usuario, "nombre": u.nombre, "email": u.email,
             "rol": session.get(Rol, u.id_rol).nombre} for u in session.exec(select(Usuario))]
