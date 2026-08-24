import httpx
from typing import BinaryIO, AsyncGenerator

from config import BOT_TOKEN, DUMP_USER_ID, TG_API_BASE

API_URL = f"{TG_API_BASE}/bot{BOT_TOKEN}"
FILE_URL = f"{TG_API_BASE}/file/bot{BOT_TOKEN}"

# Timeouts sized for transferring files up to 2 GB over slow links.
# read/write apply per socket operation, not per whole request.
UPLOAD_TIMEOUT = httpx.Timeout(connect=30.0, read=600.0, write=600.0, pool=30.0)
DOWNLOAD_TIMEOUT = httpx.Timeout(connect=30.0, read=600.0, write=600.0, pool=30.0)


async def upload_file_bot(file_obj: BinaryIO, filename: str) -> str:
    """Stream-upload an open binary file to Telegram, return its file_id."""
    async with httpx.AsyncClient(timeout=UPLOAD_TIMEOUT) as client:
        response = await client.post(
            f"{API_URL}/sendDocument",
            data={"chat_id": str(DUMP_USER_ID)},
            files={"document": (filename, file_obj)},
        )
        response.raise_for_status()
        json_data = response.json()
        if not json_data.get("ok"):
            raise Exception(f"Bot API Error: {json_data}")
        return json_data["result"]["document"]["file_id"]


async def download_file_bot(file_id: str) -> AsyncGenerator[bytes, None]:
    """Resolve file_id and stream its content chunk by chunk."""
    async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT) as client:
        response = await client.post(f"{API_URL}/getFile", json={"file_id": file_id})
        response.raise_for_status()
        json_data = response.json()
        if not json_data.get("ok"):
            raise Exception(f"Bot API Error: {json_data}")
        file_path = json_data["result"]["file_path"]

        async with client.stream("GET", f"{FILE_URL}/{file_path}") as r:
            r.raise_for_status()
            async for chunk in r.aiter_bytes(1024 * 1024):
                yield chunk
