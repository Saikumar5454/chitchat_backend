import os

import asyncpg

# DATABASE_URL = os.getenv(
#     "DATABASE_URL",
#     "postgresql://postgres:postgres@localhost:5432/chatapp",
# )




pool: asyncpg.Pool | None = None


async def connect_db() -> None:
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
    async with pool.acquire() as connection:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(254) UNIQUE NOT NULL,
                display_name VARCHAR(80) NOT NULL,
                about VARCHAR(160) NOT NULL DEFAULT 'Available on Chat',
                last_seen_at TIMESTAMPTZ,
                password_hash VARCHAR(256),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS otp_codes (
                id SERIAL PRIMARY KEY,
                email VARCHAR(254) NOT NULL,
                code_hash VARCHAR(128) NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
                delivered_at TIMESTAMPTZ,
                seen_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS messages_created_at_idx
                ON messages (created_at DESC);
            """
        )
        await connection.execute(
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE"
        )
        await connection.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ")
        await connection.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ")
        await connection.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(256)"
        )
        await connection.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS about VARCHAR(160) NOT NULL DEFAULT 'Available on Chat'"
        )
        await connection.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ"
        )
        await connection.execute(
            """
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'phone'
                ) AND NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'email'
                ) THEN
                    ALTER TABLE users RENAME COLUMN phone TO email;
                END IF;
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'otp_codes' AND column_name = 'phone'
                ) AND NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'otp_codes' AND column_name = 'email'
                ) THEN
                    ALTER TABLE otp_codes RENAME COLUMN phone TO email;
                END IF;
            END $$;
            """
        )


async def close_db() -> None:
    global pool
    if pool is not None:
        await pool.close()
        pool = None


def get_pool() -> asyncpg.Pool:
    if pool is None:
        raise RuntimeError("Database pool is not initialized")
    return pool
