"""GIISI — Sistema de gestión de incidentes de seguridad informática para pequeñas empresas.

Prototipo del Trabajo final de grado (Universidad Siglo 21). API REST construida con FastAPI.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session
from .database import engine, init_db
from .routers import router
from .seed import seed


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(engine) as session:
        seed(session)
    yield


app = FastAPI(
    title="GIISI — Gestión Integral de Incidentes de Seguridad Informática",
    description="Prototipo alineado con NIST SP 800-61 rev. 3 (CSF 2.0) e ISO/IEC 27035. "
                "Recibe alertas de fuentes externas de detección, las clasifica, calcula su severidad, "
                "guía la respuesta con playbooks y registra cada acción en un audit log de integridad verificable.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(router)


@app.get("/", tags=["sistema"])
def raiz():
    return {"sistema": "GIISI", "version": app.version, "documentacion": "/docs"}


@app.get("/salud", tags=["sistema"])
def salud():
    return {"estado": "ok"}
