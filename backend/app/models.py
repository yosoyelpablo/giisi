"""Modelo de datos del prototipo — implementa el DER de la Entrega 2 (Figura 4).

Entidades: rol, usuario, categoria_nist, activo, incidente, alerta, playbook,
paso_playbook, ejecucion_playbook, paso_ejecutado, accion_respuesta (audit log) y
leccion_aprendida.
"""
from datetime import datetime
from .util import utcnow
from typing import Optional
from sqlmodel import SQLModel, Field

# ---- Estados del ciclo de vida del incidente (HU-005) ----
ESTADOS = ["Nuevo", "En análisis", "Contenido", "Resuelto", "Cerrado"]
TRANSICIONES = {
    "Nuevo": ["En análisis"],
    "En análisis": ["Contenido", "Resuelto"],
    "Contenido": ["Resuelto"],
    "Resuelto": ["Cerrado"],
    "Cerrado": [],
}
SEVERIDADES = ["Baja", "Media", "Alta", "Crítica"]
FUNCIONES_CSF = ["Gobernar", "Identificar", "Proteger", "Detectar", "Responder", "Recuperar"]


class Rol(SQLModel, table=True):
    __tablename__ = "rol"
    id_rol: Optional[int] = Field(default=None, primary_key=True)
    nombre: str = Field(index=True, unique=True)
    permisos: str  # lista separada por comas, p. ej. "incidentes:leer,incidentes:crear"


class Usuario(SQLModel, table=True):
    __tablename__ = "usuario"
    id_usuario: Optional[int] = Field(default=None, primary_key=True)
    nombre: str
    email: str = Field(index=True, unique=True)
    hash_contrasena: str
    id_rol: int = Field(foreign_key="rol.id_rol")
    activo: bool = True
    intentos_fallidos: int = 0
    bloqueado_hasta: Optional[datetime] = None


class CategoriaNist(SQLModel, table=True):
    __tablename__ = "categoria_nist"
    id_categoria: Optional[int] = Field(default=None, primary_key=True)
    clave: str = Field(index=True, unique=True)   # p. ej. codigo_malicioso
    nombre: str
    descripcion: str = ""
    impacto_informacion: int = 2                   # 1-3, aporte de la categoría a la severidad


class Activo(SQLModel, table=True):
    __tablename__ = "activo"
    id_activo: Optional[int] = Field(default=None, primary_key=True)
    nombre: str = Field(index=True, unique=True)
    tipo: str
    criticidad: int = 3                            # 1 (baja) a 5 (muy alta)
    direccion_ip: Optional[str] = None


class Incidente(SQLModel, table=True):
    __tablename__ = "incidente"
    id_incidente: Optional[int] = Field(default=None, primary_key=True)
    titulo: str
    descripcion: str = ""
    id_categoria: Optional[int] = Field(default=None, foreign_key="categoria_nist.id_categoria")
    id_activo: Optional[int] = Field(default=None, foreign_key="activo.id_activo")
    severidad: Optional[str] = None
    estado: str = "Nuevo"
    id_usuario_asig: Optional[int] = Field(default=None, foreign_key="usuario.id_usuario")
    fecha_ocurrencia: Optional[datetime] = None    # momento del evento según la fuente externa
    fecha_recepcion: datetime = Field(default_factory=utcnow)   # T0 del prototipo: recepción de la alerta
    fecha_contencion: Optional[datetime] = None
    fecha_cierre: Optional[datetime] = None
    latencia_alerta_min: Optional[float] = None    # evento -> recepción: latencia de la fuente externa (contexto, no es meta)
    tiempo_triaje_seg: Optional[float] = None      # recepción -> clasificación + severidad AUTOMÁTICAS (sin revisión humana)
    fecha_confirmacion: Optional[datetime] = None  # instante en que una persona confirma (o corrige) la clasificación
    tiempo_triaje_completo_seg: Optional[float] = None  # recepción -> confirmación humana: triaje completo (devolución E3)
    mttr_min: Optional[float] = None               # recepción -> contención (lo mejora el prototipo)
    confianza_clasificacion: Optional[float] = None
    a_revisar: bool = False                         # clasificación por debajo del umbral (HU-003)
    origen: str = "manual"                          # manual | webhook


class Alerta(SQLModel, table=True):
    __tablename__ = "alerta"
    id_alerta: Optional[int] = Field(default=None, primary_key=True)
    origen: str
    id_alerta_origen: Optional[str] = Field(default=None, index=True)
    payload_json: str
    fecha_recepcion: datetime = Field(default_factory=utcnow)
    id_incidente: int = Field(foreign_key="incidente.id_incidente")


class Playbook(SQLModel, table=True):
    __tablename__ = "playbook"
    id_playbook: Optional[int] = Field(default=None, primary_key=True)
    nombre: str
    descripcion: str = ""
    id_categoria: int = Field(foreign_key="categoria_nist.id_categoria")


class PasoPlaybook(SQLModel, table=True):
    __tablename__ = "paso_playbook"
    id_paso: Optional[int] = Field(default=None, primary_key=True)
    id_playbook: int = Field(foreign_key="playbook.id_playbook")
    orden: int
    descripcion: str
    funcion_csf: str                                # Responder (incluye el análisis) | Recuperar — la detección es externa
    rol_responsable: str = "operador"


class EjecucionPlaybook(SQLModel, table=True):
    __tablename__ = "ejecucion_playbook"
    id_ejecucion: Optional[int] = Field(default=None, primary_key=True)
    id_incidente: int = Field(foreign_key="incidente.id_incidente")
    id_playbook: int = Field(foreign_key="playbook.id_playbook")
    fecha_inicio: datetime = Field(default_factory=utcnow)
    fecha_fin: Optional[datetime] = None
    estado: str = "En curso"                        # En curso | Completado


class PasoEjecutado(SQLModel, table=True):
    __tablename__ = "paso_ejecutado"
    id: Optional[int] = Field(default=None, primary_key=True)
    id_ejecucion: int = Field(foreign_key="ejecucion_playbook.id_ejecucion")
    id_paso: int = Field(foreign_key="paso_playbook.id_paso")
    completado: bool = False
    notas: str = ""
    id_usuario: Optional[int] = Field(default=None, foreign_key="usuario.id_usuario")
    timestamp: Optional[datetime] = None


class AccionRespuesta(SQLModel, table=True):
    """Audit log de solo agregado con hash encadenado (RNF 2 y RNF 3)."""
    __tablename__ = "accion_respuesta"
    id_accion: Optional[int] = Field(default=None, primary_key=True)
    id_incidente: Optional[int] = Field(default=None, foreign_key="incidente.id_incidente")
    id_usuario: Optional[int] = Field(default=None, foreign_key="usuario.id_usuario")
    id_paso: Optional[int] = Field(default=None, foreign_key="paso_playbook.id_paso")
    actor: str = "sistema"                          # nombre legible del usuario o proceso
    descripcion: str
    timestamp: datetime = Field(default_factory=utcnow)
    hash_previo: str
    hash_actual: str = Field(index=True)


class LeccionAprendida(SQLModel, table=True):
    __tablename__ = "leccion_aprendida"
    id_leccion: Optional[int] = Field(default=None, primary_key=True)
    id_incidente: int = Field(foreign_key="incidente.id_incidente")
    descripcion: str
    recomendacion: str = ""
    fecha: datetime = Field(default_factory=utcnow)
