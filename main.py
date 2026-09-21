import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from auth import create_access_token, create_otp, decode_access_token, hash_otp, hash_password, send_otp_email, smtp_is_configured, verify_password
from database import close_db, connect_db, get_pool
from sockets import sio_app

ADMIN_EMAILS = {
    email.strip().lower()
    for email in os.getenv("ADMIN_EMAILS", "").split(",")
    if email.strip()
}

@asynccontextmanager
async def lifespan(_: FastAPI):
    await connect_db()
    try:
        yield
    finally:
        await close_db()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://chitchat-frontend-alpha.vercel.app","http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000",  "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "Chat App Running"}

class EmailRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class VerifyOtpRequest(EmailRequest):
    code: str = Field(min_length=6, max_length=6)
    display_name: str | None = Field(default=None, min_length=2, max_length=80)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    confirm_password: str | None = Field(default=None, min_length=8, max_length=128)


class RegisterRequest(EmailRequest):
    display_name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class LoginRequest(EmailRequest):
    password: str = Field(min_length=8, max_length=128)


async def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        return decode_access_token(authorization.removeprefix("Bearer ").strip())
    except (ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def admin_user(user: dict = Depends(current_user)) -> dict:
    if user.get("email", "").lower() not in ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.post("/api/auth/request-otp")
async def request_otp(request: EmailRequest) -> dict:
    email = request.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    code = create_otp()
    pool = get_pool()
    async with pool.acquire() as connection:
        await connection.execute("DELETE FROM otp_codes WHERE email = $1", email)
        await connection.execute(
            """
            INSERT INTO otp_codes (email, code_hash, expires_at)
            VALUES ($1, $2, $3)
            """,
            email,
            hash_otp(email, code),
            datetime.now(timezone.utc) + timedelta(seconds=300),
        )

    if smtp_is_configured():
        try:
            await send_otp_email(email, code)
        
        except Exception as error:
            print("EMAIL ERROR:", error)

            return {
                "message": "OTP generated",
                "dev_code": code
            }
        except RuntimeError as error:
            print("SMTP ERROR:", error)

            return {
                "message": "OTP generated",
                "dev_code": code
            }
            # raise HTTPException(status_code=503, detail=str(error))
        return {"message": "OTP sent"}

    if os.getenv("ENVIRONMENT", "development") != "production":
        print(f"Development OTP for {email}: {code}")
        return {"message": "OTP generated", "dev_code": code}
    raise HTTPException(status_code=503, detail="SMTP credentials are not configured")


@app.post("/api/auth/register")
async def register(request: RegisterRequest) -> dict:
    email = request.email.strip().lower()
    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    pool = get_pool()
    async with pool.acquire() as connection:
        existing = await connection.fetchrow("SELECT id, password_hash FROM users WHERE email = $1", email)
        if existing is not None and existing["password_hash"]:
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        if existing is None:
            user = await connection.fetchrow(
                """
                INSERT INTO users (email, display_name, password_hash)
                VALUES ($1, $2, $3)
                RETURNING id, email, display_name
                """,
                email,
                request.display_name.strip(),
                hash_password(request.password),
            )
        else:
            user = await connection.fetchrow(
                """
                UPDATE users SET display_name = $2, password_hash = $3
                WHERE id = $1
                RETURNING id, email, display_name
                """,
                existing["id"],
                request.display_name.strip(),
                hash_password(request.password),
            )
    user_data = dict(user)
    return {"token": create_access_token(user_data), "user": user_data}


@app.post("/api/auth/login")
async def login(request: LoginRequest) -> dict:
    email = request.email.strip().lower()
    pool = get_pool()
    async with pool.acquire() as connection:
        user = await connection.fetchrow(
            "SELECT id, email, display_name, password_hash FROM users WHERE email = $1",
            email,
        )
    if user is None or not user["password_hash"] or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user_data = {"id": user["id"], "email": user["email"], "display_name": user["display_name"]}
    return {"token": create_access_token(user_data), "user": user_data}


@app.post("/api/auth/verify-otp")
async def verify_otp(request: VerifyOtpRequest) -> dict:
    email = request.email.strip().lower()
    if request.password and request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    pool = get_pool()
    async with pool.acquire() as connection:
        otp = await connection.fetchrow(
            """
            SELECT id FROM otp_codes
            WHERE email = $1 AND code_hash = $2 AND used = FALSE
              AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1
            """,
            email,
            hash_otp(email, request.code),
        )
        if otp is None:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        user = await connection.fetchrow("SELECT id, email, display_name, password_hash FROM users WHERE email = $1", email)
        if user is not None and request.password and user["password_hash"]:
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        if user is None:
            if not request.display_name or not request.password:
                raise HTTPException(status_code=400, detail="Name and password are required for registration")
            user = await connection.fetchrow(
                """
                INSERT INTO users (email, display_name, password_hash)
                VALUES ($1, $2, $3)
                RETURNING id, email, display_name, password_hash
                """,
                email,
                request.display_name.strip(),
                hash_password(request.password),
            )
        elif request.password and not user["password_hash"]:
            user = await connection.fetchrow(
                """
                UPDATE users SET display_name = COALESCE($2, display_name), password_hash = $3
                WHERE id = $1
                RETURNING id, email, display_name, password_hash
                """,
                user["id"],
                request.display_name.strip() if request.display_name else None,
                hash_password(request.password),
            )
        await connection.execute("UPDATE otp_codes SET used = TRUE WHERE id = $1", otp["id"])

    user_data = dict(user)
    return {"token": create_access_token(user_data), "user": user_data}


@app.get("/api/auth/me")
async def me(user: dict = Depends(current_user)) -> dict:
    return {"user": user}


@app.get("/api/users")
async def users(user: dict = Depends(current_user)) -> list[dict]:
    pool = get_pool()
    async with pool.acquire() as connection:
        rows = await connection.fetch(
            """
            SELECT id, email, display_name, about, last_seen_at
            FROM users
            WHERE id <> $1
            ORDER BY display_name, email
            """,
            int(user["sub"]),
        )
    return [dict(row) for row in rows]


@app.get("/api/messages")
async def message_history(user: dict = Depends(current_user)) -> list[dict]:
    pool = get_pool()
    async with pool.acquire() as connection:
        rows = await connection.fetch(
            """
                SELECT messages.id, users.display_name, messages.body, messages.created_at,
                         messages.user_id, messages.recipient_id,
                         messages.delivered_at, messages.seen_at
                FROM messages JOIN users ON users.id = messages.user_id
                WHERE messages.recipient_id IS NULL
                    OR messages.user_id = $1 OR messages.recipient_id = $1
            ORDER BY messages.created_at DESC LIMIT 100
                """, int(user["sub"])
        )
    return [
        {
            "id": row["id"],
            "sid": row["display_name"],
            "message": row["body"],
            "sender_id": row["user_id"],
            "recipient_id": row["recipient_id"],
            "delivered_at": row["delivered_at"].isoformat() if row["delivered_at"] else None,
            "seen_at": row["seen_at"].isoformat() if row["seen_at"] else None,
            "created_at": row["created_at"].isoformat(),
            "type": "chat",
        }
        for row in reversed(rows)
    ]


@app.get("/api/admin/database")
async def database_snapshot(_: dict = Depends(admin_user)) -> dict:
    pool = get_pool()
    async with pool.acquire() as connection:
        table_rows = await connection.fetch(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """
        )
        tables = []
        for table_row in table_rows:
            table_name = table_row["table_name"]
            columns = await connection.fetch(
                """
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = $1
                ORDER BY ordinal_position
                """,
                table_name,
            )
            if table_name == "users":
                rows = await connection.fetch(
                    "SELECT id, email, display_name, created_at FROM users ORDER BY id"
                )
            elif table_name == "otp_codes":
                rows = await connection.fetch(
                    """
                    SELECT id, email, expires_at, used, created_at,
                           (expires_at > NOW() AND NOT used) AS is_active
                    FROM otp_codes ORDER BY created_at DESC
                    """
                )
            elif table_name == "messages":
                rows = await connection.fetch(
                    """
                    SELECT messages.id, sender.display_name AS sender,
                           recipient.display_name AS recipient, messages.body,
                           messages.created_at
                    FROM messages
                    JOIN users AS sender ON sender.id = messages.user_id
                    LEFT JOIN users AS recipient ON recipient.id = messages.recipient_id
                    ORDER BY messages.created_at DESC
                    """
                )
            else:
                rows = []
            tables.append({
                "name": table_name,
                "columns": [dict(column) for column in columns],
                "rows": [dict(row) for row in rows],
            })
    return {"tables": tables}

app.mount("/", app=sio_app)

if __name__ == "__main__":
    uvicorn.run('main:app', reload=True)
    