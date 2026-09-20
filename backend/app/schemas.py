"""Esquemas de entrada/salida de la API."""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field, EmailStr


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    rol: str
    nombre: str
    permisos: list[str]


# ---- Alerta del webhook (Anexo 2, E3) ----
class ReglaAlerta(BaseModel):
    id: int
    nivel: int = Field(ge=0, le=15)
    descripcion: str


class ActivoAlerta(BaseModel):
    nombre: str
    direccion_ip: Optional[str] = None


class AlertaIn(BaseModel):
    origen: str
    id_alerta_origen: Optional[str] = None
    timestamp: datetime
    regla: ReglaAlerta
    activo: ActivoAlerta
    categoria_sugerida: Optional[str] = None
    detalle: str = ""


class IncidenteManualIn(BaseModel):
    titulo: str = Field(min_length=5)
    descripcion: str = Field(min_length=10)
    activo: str
    fecha_ocurrencia: Optional[datetime] = None


class CambioEstadoIn(BaseModel):
    estado: str


class AsignarIn(BaseModel):
    id_usuario: int


class SeveridadIn(BaseModel):
    severidad: str


class CompletarPasoIn(BaseModel):
    notas: str = ""


class CerrarIn(BaseModel):
    leccion: str = Field(min_length=10)
    recomendacion: str = ""


class IncidenteOut(BaseModel):
    id_incidente: int
    titulo: str
    descripcion: str
    estado: str
    severidad: Optional[str]
    categoria: Optional[str]
    categoria_clave: Optional[str]
    activo: Optional[str]
    asignado: Optional[str]
    fecha_ocurrencia: Optional[datetime]
    fecha_deteccion: datetime
    fecha_contencion: Optional[datetime]
    fecha_cierre: Optional[datetime]
    mttd_min: Optional[float]
    mttr_min: Optional[float]
    confianza_clasificacion: Optional[float]
    a_revisar: bool
    origen: str


class PasoOut(BaseModel):
    id_paso: int
    orden: int
    descripcion: str
    funcion_csf: str
    rol_responsable: str
    completado: bool = False
    notas: str = ""
    completado_por: Optional[str] = None
    timestamp: Optional[datetime] = None


class EjecucionOut(BaseModel):
    id_ejecucion: int
    playbook: str
    estado: str
    fecha_inicio: datetime
    fecha_fin: Optional[datetime]
    pasos: list[PasoOut]


class AccionOut(BaseModel):
    id_accion: int
    id_incidente: Optional[int]
    actor: str
    descripcion: str
    timestamp: datetime
    hash_previo: str
    hash_actual: str


class MetricasOut(BaseModel):
    incidentes_totales: int
    incidentes_abiertos: int
    por_estado: dict[str, int]
    por_severidad: dict[str, int]
    mttd_promedio_min: Optional[float]
    mttr_promedio_min: Optional[float]
    tasa_clasificacion_automatica: Optional[float]
    integridad_audit_log: bool
