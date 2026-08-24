"""
Dream Cloud bot: long-polling Telegram bot.

Send it a file (document, photo, video, audio, voice) and it replies
with a public download link — the file is registered in the cloud DB
and served by the web app at PUBLIC_URL.
"""
import asyncio
import uuid
import httpx

from config import (
    BOT_TOKEN, DUMP_USER_ID, TG_API_BASE,
    PUBLIC_URL, MAX_FILE_SIZE, BOT_ALLOWED_USERS,
)
from database import init_db, save_file

API_URL = f"{TG_API_BASE}/bot{BOT_TOKEN}"
MAX_FILE_SIZE_MB = MAX_FILE_SIZE // (1024 * 1024)

# Long-poll timeout is 60s, so the HTTP read timeout must be higher.
POLL_TIMEOUT = httpx.Timeout(connect=30.0, read=90.0, write=30.0, pool=30.0)

HELP_TEXT = (
    "☁️ <b>Dream Cloud</b>\n\n"
    "Просто отправь мне файл (до {max_mb} МБ) — документ, фото, видео или аудио — "
    "и я верну ссылку на скачивание.\n\n"
    "Веб-версия: {public_url}"
).format(max_mb=MAX_FILE_SIZE_MB, public_url=PUBLIC_URL)


def format_size(size: int) -> str:
    if not size:
        return "0 Б"
    units = ["Б", "КБ", "МБ", "ГБ"]
    i = 0
    value = float(size)
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    return f"{value:.1f} {units[i]}"


async def api_call(client: httpx.AsyncClient, method: str, payload: dict) -> dict:
    response = await client.post(f"{API_URL}/{method}", json=payload)
    response.raise_for_status()
    data = response.json()
    if not data.get("ok"):
        raise Exception(f"Bot API error on {method}: {data}")
    return data["result"]


def extract_file(message: dict) -> dict | None:
    """Pull (file_id, filename, mime, size) out of any media message."""
    doc = message.get("document")
    if doc:
        return {
            "file_id": doc["file_id"],
            "filename": doc.get("file_name") or f"file_{uuid.uuid4().hex[:8]}",
            "mime": doc.get("mime_type", "application/octet-stream"),
            "size": doc.get("file_size", 0),
        }
    for media_type, default_name, default_mime in (
        ("video", "video", "video/mp4"),
        ("audio", "audio", "audio/mpeg"),
        ("voice", "voice", "audio/ogg"),
        ("video_note", "video_note", "video/mp4"),
    ):
        media = message.get(media_type)
        if media:
            return {
                "file_id": media["file_id"],
                "filename": media.get("file_name")
                    or f"{default_name}_{media.get('file_unique_id', uuid.uuid4().hex[:8])}.{default_mime.split('/')[-1]}",
                "mime": media.get("mime_type", default_mime),
                "size": media.get("file_size", 0),
            }
    photos = message.get("photo")
    if photos:
        biggest = photos[-1]  # last size is the largest
        return {
            "file_id": biggest["file_id"],
            "filename": f"photo_{biggest.get('file_unique_id', uuid.uuid4().hex[:8])}.jpg",
            "mime": "image/jpeg",
            "size": biggest.get("file_size", 0),
        }
    return None


async def archive_file_id(client: httpx.AsyncClient, message: dict, fallback_file_id: str) -> str:
    """Forward the message to the dump chat so the file is archived like web uploads."""
    if message["chat"]["id"] == DUMP_USER_ID:
        return fallback_file_id
    try:
        forwarded = await api_call(client, "forwardMessage", {
            "chat_id": DUMP_USER_ID,
            "from_chat_id": message["chat"]["id"],
            "message_id": message["message_id"],
        })
        archived = extract_file(forwarded)
        if archived:
            return archived["file_id"]
    except Exception as e:
        print(f"Archive forward failed, using original file_id: {e}")
    return fallback_file_id


async def handle_message(client: httpx.AsyncClient, message: dict):
    chat_id = message["chat"]["id"]
    user_id = message.get("from", {}).get("id")

    if BOT_ALLOWED_USERS and user_id not in BOT_ALLOWED_USERS:
        await api_call(client, "sendMessage", {
            "chat_id": chat_id,
            "text": "⛔️ У тебя нет доступа к этому облаку.",
        })
        return

    file_info = extract_file(message)

    if not file_info:
        text = message.get("text", "") or ""
        if text.startswith(("/start", "/help")):
            await api_call(client, "sendMessage", {
                "chat_id": chat_id, "text": HELP_TEXT, "parse_mode": "HTML",
                "disable_web_page_preview": True,
            })
        else:
            await api_call(client, "sendMessage", {
                "chat_id": chat_id,
                "text": "📎 Пришли мне файл — я загружу его в облако и верну ссылку на скачивание.",
            })
        return

    if file_info["size"] > MAX_FILE_SIZE:
        await api_call(client, "sendMessage", {
            "chat_id": chat_id,
            "text": f"❌ Файл слишком большой ({format_size(file_info['size'])}). Максимум: {MAX_FILE_SIZE_MB} МБ.",
        })
        return

    # Archive to the dump chat, then register in the cloud DB
    tg_ref = await archive_file_id(client, message, file_info["file_id"])

    file_id = uuid.uuid4().hex[:12]
    save_file(file_id, file_info["filename"], file_info["mime"], file_info["size"], "bot", tg_ref)
    url = f"{PUBLIC_URL}/file/{file_id}"

    await api_call(client, "sendMessage", {
        "chat_id": chat_id,
        "text": (
            f"✅ <b>Загружено в облако!</b>\n\n"
            f"📄 {file_info['filename']}\n"
            f"💾 {format_size(file_info['size'])}\n\n"
            f"🔗 {url}"
        ),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })
    print(f"Registered {file_info['filename']} ({file_info['size']} bytes) as {file_id}")


async def main():
    init_db()
    offset = None
    async with httpx.AsyncClient(timeout=POLL_TIMEOUT) as client:
        me = await api_call(client, "getMe", {})
        print(f"Bot started as @{me.get('username')} (id={me.get('id')})")

        # Drop updates queued while the bot was offline
        pending = await api_call(client, "getUpdates", {"offset": -1, "timeout": 0})
        if pending:
            offset = pending[-1]["update_id"] + 1
            print(f"Skipped {len(pending)} pending update(s)")

        while True:
            try:
                updates = await api_call(client, "getUpdates", {
                    "offset": offset,
                    "timeout": 60,
                    "allowed_updates": ["message"],
                })
                for update in updates:
                    offset = update["update_id"] + 1
                    message = update.get("message")
                    if message:
                        try:
                            await handle_message(client, message)
                        except Exception as e:
                            print(f"handle_message error: {e}")
            except Exception as e:
                print(f"Polling error: {e}")
                await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
