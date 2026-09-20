import socketio

from auth import decode_access_token
from database import get_pool

sio_server = socketio.AsyncServer(
    async_mode="asgi",
    # FastAPI's CORS middleware handles both API and Socket.IO responses.
    cors_allowed_origins=[],
)

sio_app = socketio.ASGIApp(
    sio_server,
    socketio_path="sockets"
    )

connected_users = {}


@sio_server.event
async def connect(sid, environ, auth):
    try:
        token = auth.get("token") if isinstance(auth, dict) else None
        user = decode_access_token(token or "")
    except (ValueError, KeyError):
        raise ConnectionRefusedError("Authentication error")

    connected_users[sid] = user
    pool = get_pool()
    async with pool.acquire() as connection:
        await connection.execute("UPDATE users SET last_seen_at = NULL WHERE id = $1", int(user['sub']))
        delivered_messages = await connection.fetch(
            """
            UPDATE messages
            SET delivered_at = NOW()
            WHERE recipient_id = $1 AND delivered_at IS NULL
            RETURNING id, user_id, delivered_at
            """,
            int(user['sub']),
        )
        rows = await connection.fetch(
            """
                SELECT messages.id, users.display_name, messages.body, messages.created_at,
                         messages.user_id, messages.recipient_id,
                         messages.delivered_at, messages.seen_at
            FROM messages JOIN users ON users.id = messages.user_id
                WHERE messages.recipient_id IS NULL
                    OR messages.user_id = $1 OR messages.recipient_id = $1
            ORDER BY messages.created_at DESC LIMIT 100
                """, int(user['sub'])
        )
    await sio_server.emit(
        'history',
        [
            {
                'id': row['id'],
                'sid': row['display_name'],
                'message': row['body'],
                'sender_id': row['user_id'],
                'recipient_id': row['recipient_id'],
                'delivered_at': row['delivered_at'].isoformat() if row['delivered_at'] else None,
                'seen_at': row['seen_at'].isoformat() if row['seen_at'] else None,
                'created_at': row['created_at'].isoformat(),
                'type': 'chat',
            }
            for row in reversed(rows)
        ],
        to=sid,
    )
    for delivered_message in delivered_messages:
        status = {
            'id': delivered_message['id'],
            'delivered_at': delivered_message['delivered_at'].isoformat(),
            'seen_at': None,
        }
        for connected_sid, connected_user in connected_users.items():
            if int(connected_user['sub']) == int(delivered_message['user_id']):
                await sio_server.emit('message_status', status, to=connected_sid)
    await sio_server.emit('join', {'sid': user['display_name']})
    await sio_server.emit('presence', {
        'user_id': int(user['sub']),
        'online': True,
        'last_seen_at': None,
    })
    for connected_user in connected_users.values():
        await sio_server.emit('presence', {
            'user_id': int(connected_user['sub']),
            'online': True,
            'last_seen_at': None,
        }, to=sid)


@sio_server.event
async def chat(sid, message):
    user = connected_users.get(sid)
    if not user or not isinstance(message, dict):
        return
    body = message.get('message', '').strip()
    recipient_id = message.get('recipient_id')
    if not isinstance(body, str) or not body or len(body) > 2000:
        return
    try:
        recipient_id = int(recipient_id)
    except (TypeError, ValueError):
        return
    if recipient_id == int(user['sub']):
        return

    pool = get_pool()
    recipient_online = any(
        int(connected_user['sub']) == recipient_id
        for connected_user in connected_users.values()
    )
    async with pool.acquire() as connection:
        row = await connection.fetchrow(
            """
            INSERT INTO messages (user_id, recipient_id, body, delivered_at)
            SELECT $1, id, $3, CASE WHEN $4 THEN NOW() ELSE NULL END
            FROM users WHERE id = $2
            RETURNING id, recipient_id, created_at, delivered_at, seen_at
            """,
            int(user['sub']),
            recipient_id,
            body,
            recipient_online,
        )
    if row is None:
        return
    event = {
        'id': row['id'],
        'sid': user['display_name'],
        'message': body,
        'sender_id': int(user['sub']),
        'recipient_id': row['recipient_id'],
        'delivered_at': row['delivered_at'].isoformat() if row['delivered_at'] else None,
        'seen_at': row['seen_at'].isoformat() if row['seen_at'] else None,
        'created_at': row['created_at'].isoformat(),
        'type': 'chat',
    }
    await sio_server.emit('chat', event, to=sid)
    for connected_sid, connected_user in connected_users.items():
        if int(connected_user['sub']) == recipient_id:
            await sio_server.emit('chat', event, to=connected_sid)


@sio_server.event
async def message_seen(sid, message_id):
    user = connected_users.get(sid)
    if not user:
        return
    try:
        message_id = int(message_id)
    except (TypeError, ValueError):
        return
    pool = get_pool()
    async with pool.acquire() as connection:
        row = await connection.fetchrow(
            """
            UPDATE messages
            SET seen_at = COALESCE(seen_at, NOW()), delivered_at = COALESCE(delivered_at, NOW())
            WHERE id = $1 AND recipient_id = $2
            RETURNING id, seen_at
            """,
            message_id,
            int(user['sub']),
        )
    if row is None:
        return
    status = {
        'id': row['id'],
        'delivered_at': None,
        'seen_at': row['seen_at'].isoformat(),
    }
    for connected_sid, connected_user in connected_users.items():
        await sio_server.emit('message_status', status, to=connected_sid)

@sio_server.event
async def disconnect(sid):
    user = connected_users.pop(sid, None)
    if not user:
        return
    user_id = int(user['sub'])
    if any(int(connected_user['sub']) == user_id for connected_user in connected_users.values()):
        return
    pool = get_pool()
    async with pool.acquire() as connection:
        last_seen_at = await connection.fetchval(
            "UPDATE users SET last_seen_at = NOW() WHERE id = $1 RETURNING last_seen_at",
            user_id,
        )
    await sio_server.emit('presence', {
        'user_id': user_id,
        'online': False,
        'last_seen_at': last_seen_at.isoformat(),
    })