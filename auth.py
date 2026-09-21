import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
from asyncio import to_thread
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage


def load_local_environment() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_local_environment()

TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-this-development-secret").encode()
OTP_TTL_SECONDS = 300


def create_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16_384,
        r=8,
        p=1,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=16_384,
            r=8,
            p=1,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def hash_otp(email: str, code: str) -> str:
    return hmac.new(TOKEN_SECRET, f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def smtp_is_configured() -> bool:
    return all(
        os.getenv(name)
        for name in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM")
    )


async def send_otp_email(email: str, code: str) -> None:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", username or "")
    if not host or not sender:
        raise RuntimeError("SMTP credentials are not configured")

    message = EmailMessage()
    message["Subject"] = "Your chat verification code"
    message["From"] = sender
    message["To"] = email
    message.set_content(f"Your chat verification code is {code}. It expires in 5 minutes.")

    def send_message() -> None:
        try:
            print(f"SMTP_HOST={host}")
            print(f"SMTP_PORT={port}")
            print(f"SMTP_USERNAME={username}")
            print(f"SMTP_PASSWORD={password}")
            print(f"SMTP_FROM={sender}")
            print(f"SMTP_TO={email}")
            print(f"SMTP_CONTENT={message.get_content()}")
            print(f"SMTP_SERVER={host}:{port}")
            print(f"SMTP_MESSAGE={message}")
            
            with smtplib.SMTP(host, port) as connection:
                print("Connected to SMTP")
                connection.starttls()
                print("Started TLS")
                if username and password:
                    connection.login(username, password)
                    print("Logged in")
                connection.send_message(message)
                print("Email sent successfully")
        except Exception as error:
            print("SMTP ERROR:", repr(error))
            raise RuntimeError(f"SMTP delivery failed: {error}") from error
        except smtplib.SMTPAuthenticationError as error:
            raise RuntimeError("SMTP authentication failed; check the email and app password") from error
        except smtplib.SMTPRecipientsRefused as error:
            raise RuntimeError("The recipient email address was refused by the SMTP server") from error
        except (OSError, smtplib.SMTPException) as error:
            print("SMTP ERROR:", repr(error))
            raise RuntimeError(f"SMTP delivery failed: {error}") from error

    await to_thread(send_message)


def create_access_token(user: dict) -> str:
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "display_name": user["display_name"],
        "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    signature = hmac.new(TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def decode_access_token(token: str) -> dict:
    encoded, signature = token.split(".", 1)
    expected = hmac.new(TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid token")
    payload = json.loads(base64.urlsafe_b64decode(encoded).decode())
    if payload["exp"] < int(datetime.now(timezone.utc).timestamp()):
        raise ValueError("Expired token")
    return payload
