import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection
from backend.database import get_db
from backend.core.auth import hash_password, verify_password, create_token, get_current_user, require_admin
from backend.schemas import UserCreate, LoginRequest, TokenResponse, UserOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: UserCreate, conn: Connection = Depends(get_db)):
    existing = conn.execute("SELECT id FROM users WHERE email = %s", (body.email,)).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    # First user bootstraps as admin; all subsequent users become analysts
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    role = "admin" if count == 0 else "analyst"

    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, email, hashed_password, role) VALUES (%s, %s, %s, %s)",
        (user_id, body.email, hash_password(body.password), role),
    )
    conn.commit()
    logger.info(f"[auth] registered {body.email} as {role}")
    return UserOut(id=user_id, email=body.email, role=role)


@router.post("/users", response_model=UserOut, status_code=201)
def admin_create_user(
    body: UserCreate,
    conn: Connection = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Admin endpoint to create users with explicit roles (analyst / admin / read_only)."""
    existing = conn.execute("SELECT id FROM users WHERE email = %s", (body.email,)).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_id = str(uuid.uuid4())
    role = body.role or "analyst"
    conn.execute(
        "INSERT INTO users (id, email, hashed_password, role) VALUES (%s, %s, %s, %s)",
        (user_id, body.email, hash_password(body.password), role),
    )
    conn.commit()
    logger.info(f"[auth] admin created {body.email} as {role}")
    return UserOut(id=user_id, email=body.email, role=role)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, conn: Connection = Depends(get_db)):
    row = conn.execute(
        "SELECT id, email, hashed_password, role FROM users WHERE email = %s",
        (body.email,),
    ).fetchone()
    if not row or not verify_password(body.password, row[2]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user_id=row[0], email=row[1], role=row[3])
    logger.info(f"[auth] login {body.email}")
    return TokenResponse(access_token=token, token_type="bearer")


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(get_current_user)):
    return UserOut(id=user["id"], email=user["email"], role=user["role"])
