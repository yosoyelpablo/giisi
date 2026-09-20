"""Datos iniciales: roles (RBAC), usuarios de demostración, taxonomía NIST, activos y playbooks."""
from sqlmodel import Session, select
from . import config
from .auth import hash_password
from .models import Rol, Usuario, CategoriaNist, Activo, Playbook, PasoPlaybook

# Permisos por rol — Tabla 8 (E3). El administrador tiene comodín "*".
ROLES = {
    "operador": "incidentes:leer,incidentes:crear,playbook:ejecutar,lecciones:crear,metricas:leer",
    "coordinador": "incidentes:leer,incidentes:crear,incidentes:asignar,incidentes:severidad,incidentes:cerrar,"
                   "playbook:ejecutar,playbook:editar,lecciones:crear,metricas:leer",
    "gerente": "incidentes:leer,metricas:leer",
    "administrador": "*",
}

USUARIOS = [
    ("Juan Pérez", "operador@giisi.local", "operador"),
    ("María Gómez", "coordinador@giisi.local", "coordinador"),
    ("Carlos Ruiz", "gerente@giisi.local", "gerente"),
    ("Admin GIISI", "admin@giisi.local", "administrador"),
]

# Taxonomía NIST (E1, marco teórico) — clave, nombre, impacto sobre la información (1-3)
CATEGORIAS = [
    ("codigo_malicioso", "Código malicioso", 3, "Ransomware, malware, troyanos"),
    ("acceso_no_autorizado", "Acceso no autorizado", 3, "Uso de credenciales o escalada de privilegios sin autorización"),
    ("filtracion_datos", "Filtración de datos", 3, "Exfiltración o fuga de información sensible"),
    ("correo", "Correo electrónico", 2, "Phishing y correo malicioso"),
    ("desgaste", "Ataque de desgaste", 2, "Fuerza bruta y denegación de servicio"),
    ("web", "Aplicación web", 2, "Inyección de código, XSS y ataques a aplicaciones web"),
    ("suplantacion", "Suplantación de identidad", 2, "Spoofing y ataques de intermediario"),
    ("uso_indebido", "Uso indebido", 1, "Violación de la política de uso aceptable"),
    ("medios_externos", "Medios externos o removibles", 2, "Dispositivos USB y medios extraíbles"),
    ("perdida_robo", "Pérdida o robo de equipamiento", 2, "Equipos con información sensible extraviados o robados"),
]

ACTIVOS = [
    ("SRV-FILES-01", "Servidor de archivos", 5, "192.168.10.15"),
    ("SRV-AD-01", "Controlador de dominio", 5, "192.168.10.10"),
    ("SRV-WEB-01", "Servidor web interno", 4, "192.168.10.20"),
    ("WS-VENTAS-03", "Estación de trabajo", 2, "192.168.20.33"),
    ("WS-RRHH-01", "Estación de trabajo", 3, "192.168.20.11"),
]

# Playbooks (E2, HU-006 y Anexo 1 de E3) — pasos con función CSF 2.0 y rol responsable
PLAYBOOKS = {
    "codigo_malicioso": ("Respuesta ante ransomware", [
        ("Aislar el activo afectado de la red", "Responder", "operador"),
        ("Preservar la evidencia (imagen de disco y volcado de memoria)", "Responder", "operador"),
        ("Identificar la variante y el vector de entrada", "Detectar", "coordinador"),
        ("Notificar a la gerencia y evaluar las obligaciones de notificación externa", "Responder", "coordinador"),
        ("Erradicar el software malicioso y cerrar el vector de entrada", "Responder", "operador"),
        ("Restaurar los servicios desde un respaldo verificado", "Recuperar", "operador"),
        ("Verificar el restablecimiento y monitorear la recurrencia", "Recuperar", "coordinador"),
        ("Registrar las lecciones aprendidas y cerrar el incidente", "Recuperar", "coordinador"),
    ]),
    "acceso_no_autorizado": ("Respuesta ante acceso no autorizado", [
        ("Deshabilitar la cuenta comprometida y revocar sus sesiones", "Responder", "operador"),
        ("Identificar el alcance del acceso y los recursos consultados", "Detectar", "coordinador"),
        ("Restablecer credenciales y exigir segundo factor", "Responder", "operador"),
        ("Verificar la ausencia de persistencia en los sistemas afectados", "Recuperar", "coordinador"),
        ("Registrar las lecciones aprendidas y cerrar el incidente", "Recuperar", "coordinador"),
    ]),
    "filtracion_datos": ("Respuesta ante filtración de datos", [
        ("Bloquear el canal de exfiltración identificado", "Responder", "operador"),
        ("Determinar el tipo y el volumen de la información afectada", "Detectar", "coordinador"),
        ("Notificar a la gerencia y evaluar obligaciones legales de notificación", "Responder", "coordinador"),
        ("Remediar la causa raíz y reforzar los controles", "Recuperar", "operador"),
        ("Registrar las lecciones aprendidas y cerrar el incidente", "Recuperar", "coordinador"),
    ]),
}


def seed(session: Session) -> None:
    if session.exec(select(Rol)).first():
        return  # ya inicializado
    roles = {}
    for nombre, permisos in ROLES.items():
        r = Rol(nombre=nombre, permisos=permisos); session.add(r); roles[nombre] = r
    session.commit()
    for nombre, email, rol in USUARIOS:
        session.add(Usuario(nombre=nombre, email=email, hash_contrasena=hash_password(config.SEED_PASSWORD),
                            id_rol=roles[rol].id_rol))
    cats = {}
    for clave, nombre, impacto, desc in CATEGORIAS:
        c = CategoriaNist(clave=clave, nombre=nombre, impacto_informacion=impacto, descripcion=desc)
        session.add(c); cats[clave] = c
    for nombre, tipo, crit, ip in ACTIVOS:
        session.add(Activo(nombre=nombre, tipo=tipo, criticidad=crit, direccion_ip=ip))
    session.commit()
    for clave, (nombre, pasos) in PLAYBOOKS.items():
        pb = Playbook(nombre=nombre, id_categoria=cats[clave].id_categoria); session.add(pb); session.commit()
        for i, (desc, csf, rol) in enumerate(pasos, start=1):
            session.add(PasoPlaybook(id_playbook=pb.id_playbook, orden=i, descripcion=desc, funcion_csf=csf, rol_responsable=rol))
    session.commit()
