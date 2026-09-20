"""Motor de reglas: clasificación por taxonomía NIST (HU-003) y cálculo de severidad (HU-004).

La clasificación es determinista y explicable: cada categoría tiene palabras clave con
peso; la confianza es la proporción del peso acumulado sobre el máximo de la categoría
ganadora. Si no supera el umbral, el incidente queda marcado «a revisar» (HU-003, c2).
La severidad combina impacto funcional, impacto sobre la información y recuperabilidad,
según el esquema de priorización del NIST SP 800-61.
"""
import unicodedata
from typing import Optional
from . import config

# clave_categoria -> lista de (palabra clave, peso)
REGLAS = {
    "codigo_malicioso": [("ransomware", 1.0), ("cifrado masivo", 0.9), ("malware", 0.8), ("troyano", 0.8),
                         ("virus", 0.6), ("encrypt", 0.7), ("wannacry", 1.0), ("lockbit", 1.0), ("crypto", 0.4)],
    "acceso_no_autorizado": [("acceso no autorizado", 1.0), ("unauthorized", 0.9), ("login exitoso inusual", 0.8),
                             ("escalada de privilegios", 0.9), ("privilege", 0.7), ("cuenta comprometida", 0.9),
                             ("vpn", 0.3), ("sudo", 0.4)],
    "filtracion_datos": [("exfiltracion", 1.0), ("exfiltration", 1.0), ("filtracion", 1.0), ("fuga de datos", 1.0),
                         ("transferencia inusual", 0.7), ("datos de clientes", 0.6), ("dlp", 0.8)],
    "correo": [("phishing", 1.0), ("spear", 0.6), ("correo malicioso", 0.9), ("adjunto sospechoso", 0.8),
               ("suplantacion de remitente", 0.7)],
    "desgaste": [("fuerza bruta", 1.0), ("brute force", 1.0), ("denegacion de servicio", 1.0), ("ddos", 1.0),
                 ("dos", 0.5), ("intentos fallidos", 0.7), ("multiple failed", 0.7)],
    "web": [("inyeccion sql", 1.0), ("sql injection", 1.0), ("xss", 1.0), ("cross-site", 0.9),
            ("aplicacion web", 0.5), ("web attack", 0.9)],
    "suplantacion": [("spoofing", 1.0), ("suplantacion", 0.9), ("identidad falsa", 0.8), ("man in the middle", 0.9)],
    "uso_indebido": [("uso indebido", 1.0), ("politica de uso", 0.8), ("software no autorizado", 0.8),
                     ("acceso a contenido", 0.5)],
    "medios_externos": [("usb", 1.0), ("medio extraible", 1.0), ("removable", 1.0), ("dispositivo externo", 0.8)],
    "perdida_robo": [("robo", 1.0), ("perdida de equipo", 1.0), ("notebook extraviada", 1.0), ("stolen", 1.0)],
}


def _normalizar(texto: str) -> str:
    texto = unicodedata.normalize("NFKD", texto or "").encode("ascii", "ignore").decode().lower()
    return texto


def clasificar(texto: str, categoria_sugerida: Optional[str] = None) -> dict:
    """Devuelve {'clave', 'confianza', 'a_revisar', 'reglas_aplicadas'}."""
    t = _normalizar(texto)
    mejor, mejor_peso, mejor_reglas = None, 0.0, []
    for clave, reglas in REGLAS.items():
        peso = 0.0; aplicadas = []
        for palabra, w in reglas:
            if palabra in t:
                peso += w; aplicadas.append(palabra)
        if categoria_sugerida and categoria_sugerida == clave:
            peso += 0.5; aplicadas.append("categoria_sugerida")
        if peso > mejor_peso:
            mejor, mejor_peso, mejor_reglas = clave, peso, aplicadas
    if mejor is None:
        return {"clave": None, "confianza": 0.0, "a_revisar": True, "reglas_aplicadas": []}
    confianza = min(1.0, mejor_peso / 1.5)
    return {"clave": mejor, "confianza": round(confianza, 2),
            "a_revisar": confianza < config.CLASSIFY_CONFIDENCE_THRESHOLD, "reglas_aplicadas": mejor_reglas}


def severidad(nivel_alerta: int, impacto_informacion: int, criticidad_activo: int) -> dict:
    """Combina impacto funcional (nivel de la alerta 0-15), impacto sobre la información
    (1-3, según categoría) y recuperabilidad (criticidad del activo 1-5) en un nivel de severidad."""
    funcional = 3 if nivel_alerta >= 12 else 2 if nivel_alerta >= 7 else 1
    recuperabilidad = 3 if criticidad_activo >= 4 else 2 if criticidad_activo >= 3 else 1
    puntaje = funcional * impacto_informacion * recuperabilidad          # 1 .. 27
    nivel = "Crítica" if puntaje >= 18 else "Alta" if puntaje >= 9 else "Media" if puntaje >= 4 else "Baja"
    return {"severidad": nivel, "puntaje": puntaje, "funcional": funcional,
            "informacion": impacto_informacion, "recuperabilidad": recuperabilidad}
