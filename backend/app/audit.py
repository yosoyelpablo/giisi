"""Audit log de solo agregado con integridad verificable — RNF 2 y RNF 3 (HU-007).

Cada registro guarda el hash del registro anterior (hash_previo) y su propio hash
(hash_actual = SHA-256 de los campos del registro concatenados con hash_previo).
Cualquier modificación o eliminación rompe la cadena y es detectable con verificar().
El registro NUNCA es escrito por el modelo de lenguaje ni por procesos no auditados.
"""
import hashlib
from datetime import datetime
from .util import utcnow
from typing import Optional
from sqlmodel import Session, select
from .models import AccionRespuesta

GENESIS = "0" * 64


def _calcular_hash(hash_previo: str, id_incidente, id_usuario, id_paso, actor: str,
                   descripcion: str, timestamp: datetime) -> str:
    material = "|".join([
        hash_previo, str(id_incidente or ""), str(id_usuario or ""), str(id_paso or ""),
        actor, descripcion, timestamp.isoformat(timespec="microseconds"),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def ultimo_hash(session: Session) -> str:
    ultimo = session.exec(select(AccionRespuesta).order_by(AccionRespuesta.id_accion.desc())).first()
    return ultimo.hash_actual if ultimo else GENESIS


def registrar(session: Session, descripcion: str, *, actor: str = "sistema",
              id_incidente: Optional[int] = None, id_usuario: Optional[int] = None,
              id_paso: Optional[int] = None) -> AccionRespuesta:
    """Agrega un registro al audit log encadenándolo al anterior. Solo agregado."""
    ts = utcnow()
    previo = ultimo_hash(session)
    accion = AccionRespuesta(
        id_incidente=id_incidente, id_usuario=id_usuario, id_paso=id_paso, actor=actor,
        descripcion=descripcion, timestamp=ts, hash_previo=previo,
        hash_actual=_calcular_hash(previo, id_incidente, id_usuario, id_paso, actor, descripcion, ts),
    )
    session.add(accion); session.commit(); session.refresh(accion)
    return accion


def verificar(session: Session) -> dict:
    """Recorre toda la cadena y recalcula cada hash. Devuelve el resultado de la verificación."""
    registros = session.exec(select(AccionRespuesta).order_by(AccionRespuesta.id_accion)).all()
    esperado_previo = GENESIS
    for r in registros:
        if r.hash_previo != esperado_previo:
            return {"integra": False, "registros": len(registros), "primer_fallo": r.id_accion,
                    "motivo": "hash_previo no coincide con el registro anterior (registro eliminado o insertado)"}
        recalculado = _calcular_hash(r.hash_previo, r.id_incidente, r.id_usuario, r.id_paso,
                                     r.actor, r.descripcion, r.timestamp)
        if recalculado != r.hash_actual:
            return {"integra": False, "registros": len(registros), "primer_fallo": r.id_accion,
                    "motivo": "hash_actual no coincide con el contenido (registro modificado)"}
        esperado_previo = r.hash_actual
    return {"integra": True, "registros": len(registros), "ultimo_hash": esperado_previo}
