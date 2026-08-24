"""
Integration test against the real self-hosted Bot API (see TG_API_BASE in .env).

Run: python tests/test_integration.py

Verifies:
  1. getMe works through the self-hosted API (no proxy).
  2. Streaming upload of a ~40MB file (above the old 20MB bot limit)
     with flat memory usage.
  3. Streaming download + SHA256 round-trip.
  4. Bot message-handling logic registers the file and replies with a link.
"""
import asyncio
import hashlib
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import psutil

import config
from tg_bot import upload_file_bot, download_file_bot, API_URL

TEST_SIZE = 40 * 1024 * 1024  # 40MB: impossible with the old 20MB-limited setup
CHUNK = 1024 * 1024


def make_test_file(path: str, size: int) -> str:
    """Create a pseudo-random file, return its sha256."""
    rnd = uuid.uuid4().bytes
    h = hashlib.sha256()
    with open(path, "wb") as f:
        written = 0
        while written < size:
            block = (rnd * (CHUNK // len(rnd) + 1))[: min(CHUNK, size - written)]
            f.write(block)
            h.update(block)
            written += len(block)
    return h.hexdigest()


async def main():
    proc = psutil.Process(os.getpid())
    rss_start = proc.memory_info().rss / 1024 / 1024
    print(f"[0] RSS at start: {rss_start:.1f} MB")

    # 1. getMe
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{API_URL}/getMe")
        me = r.json()
        assert me.get("ok"), f"getMe failed: {me}"
        print(f"[1] getMe OK: @{me['result']['username']}")

        # getUpdates must not conflict (nothing else polling)
        r = await client.post(f"{API_URL}/getUpdates", json={"timeout": 0})
        upd = r.json()
        assert upd.get("ok"), f"getUpdates failed: {upd}"
        print(f"[1b] getUpdates OK ({len(upd['result'])} pending)")

    # 2. Streaming upload
    test_path = os.path.join(os.path.dirname(__file__), "test_blob.bin")
    expected_sha = make_test_file(test_path, TEST_SIZE)
    print(f"[2] Test file: {TEST_SIZE / 1024 / 1024:.0f} MB, sha256={expected_sha[:16]}...")

    with open(test_path, "rb") as f:
        tg_file_id = await upload_file_bot(f, "test_blob.bin")
    rss_after_upload = proc.memory_info().rss / 1024 / 1024
    print(f"[2] Upload OK, file_id={tg_file_id[:30]}...")
    print(f"[2] RSS after upload: {rss_after_upload:.1f} MB "
          f"(delta {rss_after_upload - rss_start:+.1f} MB for a {TEST_SIZE // 1024 // 1024} MB file)")
    assert rss_after_upload - rss_start < TEST_SIZE / 1024 / 1024 / 2, \
        "Upload buffered the whole file in memory!"

    # 3. Streaming download + hash compare
    h = hashlib.sha256()
    total = 0
    async for chunk in download_file_bot(tg_file_id):
        h.update(chunk)
        total += len(chunk)
    got_sha = h.hexdigest()
    print(f"[3] Download OK: {total / 1024 / 1024:.1f} MB, sha256={got_sha[:16]}...")
    rss_after_dl = proc.memory_info().rss / 1024 / 1024
    print(f"[3] RSS after download: {rss_after_dl:.1f} MB")
    assert total == TEST_SIZE, f"Size mismatch: {total} != {TEST_SIZE}"
    assert got_sha == expected_sha, "SHA256 mismatch!"
    print("[3] Round-trip integrity: OK")

    # 4. Bot handler logic with a fabricated incoming message
    import bot
    import database
    test_db = os.path.join(os.path.dirname(__file__), "test_files.db")
    database.DB_PATH = test_db  # point the database module at a throwaway DB
    database.init_db()
    get_file = database.get_file

    captured = {}

    async def fake_api_call(client, method, payload):
        if method == "sendMessage":
            captured["text"] = payload["text"]
            captured["chat_id"] = payload["chat_id"]
            return {"ok": True}
        if method == "forwardMessage":
            raise Exception("skip forwarding in test")
        raise AssertionError(f"unexpected api call: {method}")

    fake_message = {
        "message_id": 1,
        "chat": {"id": config.DUMP_USER_ID},
        "from": {"id": config.DUMP_USER_ID},
        "document": {
            "file_id": tg_file_id,
            "file_name": "test_blob.bin",
            "mime_type": "application/octet-stream",
            "file_size": TEST_SIZE,
        },
    }

    orig_api_call = bot.api_call
    bot.api_call = fake_api_call
    try:
        await bot.handle_message(None, fake_message)
    finally:
        bot.api_call = orig_api_call

    assert "text" in captured, "Bot did not reply"
    assert config.PUBLIC_URL in captured["text"], f"No link in reply: {captured['text']}"
    link = captured["text"].split(config.PUBLIC_URL + "/file/")[1].split()[0]
    record = get_file(link)
    assert record, "File not saved in DB"
    assert record["size"] == TEST_SIZE
    assert record["filename"] == "test_blob.bin"
    print(f"[4] Bot logic OK: reply contains link .../file/{link}, DB record verified")

    # 5. Oversized file rejection
    fake_message["document"]["file_size"] = config.MAX_FILE_SIZE + 1
    captured.clear()
    bot.api_call = fake_api_call
    try:
        await bot.handle_message(None, fake_message)
    finally:
        bot.api_call = orig_api_call
    assert "❌" in captured.get("text", ""), "Oversized file not rejected"
    print("[5] Oversized rejection OK")

    # Cleanup
    os.remove(test_path)
    os.remove(test_db)
    print("\nALL INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
