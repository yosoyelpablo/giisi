"""Audit log de solo agregado con integridad verificable — RNF 2 y RNF 3 (HU-007).

Cada registro guarda el hash del registro anterior (hash_previo) y su propio hash
(hash_actual = SHA-256 de los campos del registro concatenados con hash_previo).
Cualquier modificación o eliminación rompe la cadena y es detectable con verificar().
El registro NUNCA es escrito por el modelo de lenguaje ni por procesos no auditados.

Límite (devolución E3): la cadena por sí sola NO garantiza la integridad frente a quien tenga
acceso de escritura a la base y pueda recalcular TODOS los hashes desde el registro alterado:
el resultado vuelve a ser una cadena internamente coherente. Por eso el sistema emite una
referencia externa: exportar_firmado() produce el estado de la cadena (cantidad de registros,
último id y hash de cabeza) firmado con HMAC-SHA256 con una clave que se custodia fuera de la
base, y esa exportación se guarda en un almacenamiento inmutable (por ejemplo, Amazon S3 con
bloqueo de objetos). verificar_contra_exportacion() compara la cadena actual con una referencia
firmada anterior: una reconstrucción de la cadena cambia el hash de cabeza y queda detectada.
"""
import hmac
import json
import hashlib
from datetime import datetime
from pathlib import Path
from .util import utcnow
from typing import Optional
from sqlmodel import Session, select
from . import config
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


# ---------------------------------------------------------------- referencia externa firmada (devolución E3)
def _canonico(referencia: dict) -> bytes:
    return json.dumps(referencia, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _firmar(referencia: dict) -> str:
    return hmac.new(config.AUDIT_EXPORT_KEY.encode("utf-8"), _canonico(referencia), hashlib.sha256).hexdigest()


def exportar_firmado(session: Session) -> dict:
    """Emite la referencia externa del estado actual de la cadena, firmada con HMAC-SHA256.

    La exportación se guarda fuera del sistema, en un almacenamiento inmutable (en producción,
    un bucket con bloqueo de objetos en modo de cumplimiento); scripts/exportar_auditoria.py la genera.
    """
    v = verificar(session)
    if not v["integra"]:
        raise ValueError("No se exporta una referencia de una cadena que ya no es íntegra")
    ultimo = session.exec(select(AccionRespuesta).order_by(AccionRespuesta.id_accion.desc())).first()
    referencia = {"sistema": "GIISI", "version": 1, "fecha_emision": utcnow().isoformat(timespec="seconds"),
                  "registros": v["registros"], "ultimo_id": ultimo.id_accion if ultimo else 0,
                  "hash_cabeza": v["ultimo_hash"]}
    return {"referencia": referencia, "firma": _firmar(referencia), "algoritmo": "HMAC-SHA256"}


def guardar_referencia(session: Session) -> Path:
    """Emite la referencia firmada y la guarda en AUDIT_EXPORT_DIR (se invoca al cerrar cada incidente)."""
    exp = exportar_firmado(session)
    destino = Path(config.AUDIT_EXPORT_DIR); destino.mkdir(parents=True, exist_ok=True)
    f = destino / f"referencia_{exp['referencia']['ultimo_id']}_{utcnow():%Y%m%d_%H%M%S}.json"
    f.write_text(json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8")
    return f


def verificar_contra_exportacion(session: Session, exportacion: dict) -> dict:
    """Compara la cadena actual con una referencia firmada emitida antes.

    1) La firma debe ser válida: la referencia no fue alterada ni fabricada sin la clave.
    2) El registro ultimo_id debe seguir existiendo con el mismo hash: si alguien modificó un
       registro anterior y recalculó toda la cadena, el hash de ese registro cambió.
    3) La cantidad de registros hasta ultimo_id debe coincidir: detecta eliminaciones.
    4) La cadena completa debe ser internamente coherente (verificar()).
    """
    ref, firma = exportacion.get("referencia", {}), exportacion.get("firma", "")
    if not hmac.compare_digest(_firmar(ref), firma):
        return {"coincide": False, "motivo": "La firma de la referencia no es válida: la exportación fue alterada o no la emitió el sistema"}
    reg = session.get(AccionRespuesta, ref.get("ultimo_id")) if ref.get("ultimo_id") else None
    if ref.get("ultimo_id") and (reg is None or reg.hash_actual != ref.get("hash_cabeza")):
        return {"coincide": False, "motivo": f"El registro {ref.get('ultimo_id')} ya no coincide con la referencia externa: "
                                             "la cadena fue modificada y recalculada, o truncada"}
    hasta = session.exec(select(AccionRespuesta).where(AccionRespuesta.id_accion <= (ref.get("ultimo_id") or 0))).all()
    if len(hasta) != ref.get("registros"):
        return {"coincide": False, "motivo": f"La referencia registra {ref.get('registros')} registros hasta el {ref.get('ultimo_id')} "
                                             f"y hoy hay {len(hasta)}: se eliminaron o insertaron registros"}
    v = verificar(session)
    if not v["integra"]:
        return {"coincide": False, "motivo": f"La cadena actual no es íntegra: {v['motivo']} (registro {v['primer_fallo']})"}
    return {"coincide": True, "motivo": f"La cadena actual contiene sin cambios los {ref.get('registros')} registros de la referencia "
                                        f"emitida el {ref.get('fecha_emision')} y es íntegra ({v['registros']} registros en total)"}
