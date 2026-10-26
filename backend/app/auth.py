"""Autenticación y autorización — RNF 1 y sección Seguridad (E3).

- Contraseñas almacenadas exclusivamente como hash bcrypt (factor de costo 12).
- Sesión mediante JWT firmado (HS256) con vigencia de 8 horas.
- Bloqueo de cuenta tras 5 intentos fallidos durante 15 minutos.
- Control de acceso basado en roles (RBAC): cada operación exige un permiso.
"""
from datetime import datetime, timedelta
from .util import utcnow
from typing import Optional
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select
from . import config
from .database import get_session
from .models import Rol, Usuario

_bearer = HTTPBearer(auto_error=False)


# ---------- contraseñas ----------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def password_policy_ok(plain: str) -> bool:
    """Mínimo 12 caracteres, mayúscula, minúscula, número y carácter especial."""
    return (len(plain) >= 12 and any(c.isupper() for c in plain) and any(c.islower() for c in plain)
            and any(c.isdigit() for c in plain) and any(not c.isalnum() for c in plain))


# ---------- tokens ----------
def create_token(user: Usuario, rol: Rol) -> str:
    payload = {
        "sub": str(user.id_usuario),
        "email": user.email,
        "rol": rol.nombre,
        "permisos": rol.permisos.split(","),
        "exp": utcnow() + timedelta(hours=config.JWT_EXPIRE_HOURS),
        "iat": utcnow(),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión expirada")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")


# ---------- login con bloqueo ----------
def authenticate(session: Session, email: str, password: str) -> Usuario:
    user = session.exec(select(Usuario).where(Usuario.email == email)).first()
    if not user or not user.activo:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")
    if user.bloqueado_hasta and user.bloqueado_hasta > utcnow():
        raise HTTPException(status.HTTP_423_LOCKED, "Cuenta bloqueada temporalmente por intentos fallidos")
    if not verify_password(password, user.hash_contrasena):
        user.intentos_fallidos += 1
        if user.intentos_fallidos >= config.LOGIN_MAX_ATTEMPTS:
            user.bloqueado_hasta = utcnow() + timedelta(minutes=config.LOGIN_LOCK_MINUTES)
            user.intentos_fallidos = 0
            session.add(user); session.commit()
            from .audit import registrar
            registrar(session, f"Bloqueó la cuenta {user.email} durante {config.LOGIN_LOCK_MINUTES} minutos tras "
                      f"{config.LOGIN_MAX_ATTEMPTS} intentos fallidos de inicio de sesión", id_usuario=user.id_usuario)
        session.add(user); session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")
    user.intentos_fallidos = 0; user.bloqueado_hasta = None
    session.add(user); session.commit(); session.refresh(user)
    return user


# ---------- dependencias FastAPI ----------
class CurrentUser:
    def __init__(self, id_usuario: int, email: str, rol: str, permisos: list[str], nombre: str):
        self.id_usuario, self.email, self.rol, self.permisos, self.nombre = id_usuario, email, rol, permisos, nombre

    def puede(self, permiso: str) -> bool:
        return "*" in self.permisos or permiso in self.permisos


def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
                     session: Session = Depends(get_session)) -> CurrentUser:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Autenticación requerida")
    data = decode_token(creds.credentials)
    user = session.get(Usuario, int(data["sub"]))
    if not user or not user.activo:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario inactivo")
    return CurrentUser(user.id_usuario, user.email, data["rol"], data["permisos"], user.nombre)


def require(permiso: str):
    """Dependencia que exige un permiso concreto (RBAC). Registra los intentos denegados."""
    def _dep(user: CurrentUser = Depends(get_current_user), session: Session = Depends(get_session)):
        if not user.puede(permiso):
            from .audit import registrar
            registrar(session, f"Acceso denegado: '{permiso}' solicitado por {user.email} (rol {user.rol})",
                      actor=user.email, id_usuario=user.id_usuario)
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"El rol '{user.rol}' no tiene el permiso '{permiso}'")
        return user
    return _dep
