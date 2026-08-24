# Dream Cloud

Self-hosted file-sharing cloud backed by Telegram storage. Upload files through the
web UI, a REST API, or a Telegram bot — and get back a public download link.

Files are stored on Telegram via a **self-hosted Bot API server**, which raises the
upload limit from the official cloud Bot API's 20 MB to **2 GB** per file. No
userbot (Telethon/MTProto) is involved anymore: everything runs through the plain
HTTP Bot API, so there are no session files, no `api_id`/`api_hash`, and no risk of
the account getting flagged.

## Architecture

```
Browser / curl / bot ──► FastAPI web app (main.py)
                            │   streams upload to disk, then into the Bot API
                            ▼
                 Self-hosted Telegram Bot API server (TG_API_BASE)
                            │
                            ▼
                     Telegram (file storage)

bot.py — long-polling bot: send it a file in Telegram, get a download link.
database.py — SQLite index mapping short file IDs to Telegram file_ids.
tg_bot.py — thin httpx client for sendDocument/getFile streaming.
```

- **Streaming end-to-end**: uploads go to a temp file on disk and are streamed
  straight into the Bot API request; downloads stream chunk-by-chunk from
  Telegram to the client. Memory usage stays flat even at 2 GB.
- **Storage backend**: files live in a private dump chat; only `file_id`
  references are kept in SQLite (`files.db`).
- **Web auth**: signed HMAC CSRF tokens for the browser UI, `X-Api-Key` header
  for programmatic access.

## Requirements

- Python 3.10+
- A **self-hosted Telegram Bot API server** (required for the 2 GB limit;
  the official `api.telegram.org` caps uploads at 20 MB). See
  [tdlib.github.io/telegram-bot-api](https://tdlib.github.io/telegram-bot-api/)
  or run it with Docker:
  ```bash
  docker run -d --name telegram-bot-api \
    -v telegram-bot-api-data:/var/lib/telegram-bot-api \
    -p 8081:8081 \
    aiogram/telegram-bot-api \
    --local --api-id=<YOUR_API_ID> --api-hash=<YOUR_API_HASH>
  ```
  The `--local` flag enables local mode: no proxy needed and up to 2000 MB
  uploads/downloads.

## Installation

```bash
git clone https://github.com/dreamcatchered/dreamCloud.git
cd dreamCloud
pip install -r requirements.txt

# Configure (see .env.example for all variables)
export BOT_TOKEN="123456:ABC..."          # from @BotFather
export DUMP_USER_ID="123456789"           # your Telegram user id (dump chat)
export API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export TG_API_BASE="http://localhost:8081"
export PUBLIC_URL="https://your-domain.example"
export MAX_FILE_SIZE_MB=2000
```

Run the web app:

```bash
uvicorn main:app --host 127.0.0.1 --port 5033
```

Run the Telegram bot (optional, separate process):

```bash
python bot.py
```

### systemd

Example unit files are included:

```bash
sudo cp dream-cloud.service dream-cloud-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dream-cloud dream-cloud-bot
```

Put the environment variables into an `EnvironmentFile=/etc/dreamcloud.env`
(root-only readable) instead of exporting them manually.

## Configuration reference

| Variable           | Description                                              |
|--------------------|----------------------------------------------------------|
| `BOT_TOKEN`        | Bot token from @BotFather (**required**)                  |
| `DUMP_USER_ID`     | Telegram user ID of the dump chat where files are archived (**required**) |
| `API_KEY`          | API key for `X-Api-Key` auth; also signs CSRF tokens (**required**) |
| `TG_API_BASE`      | Base URL of the self-hosted Bot API (default `http://localhost:8081`) |
| `PUBLIC_URL`       | Public base URL used in generated links                   |
| `MAX_FILE_SIZE_MB` | Upload limit in MB (default `2000`)                       |
| `DB_PATH`          | SQLite path (default `files.db`)                          |

## Usage

### Web UI

Open `PUBLIC_URL` in a browser and drop a file.

### REST API

```bash
curl -X POST "https://your-domain.example/upload" \
  -H "x-api-key: $API_KEY" \
  -F "file=@bigvideo.mkv"
```

Response:

```json
{
  "file_id": "a1b2c3d4e5f6",
  "url": "https://your-domain.example/file/a1b2c3d4e5f6"
}
```

Download: `GET /file/<file_id>` (streams with correct filename).
Health check: `GET /health`.

### Telegram bot

Send any document/photo/video/audio (up to 2 GB) to the bot — it replies with a
public download link and archives the file in the dump chat. Access is restricted
to `BOT_ALLOWED_USERS`.

## Tests

Integration test (requires a running Bot API server and real credentials):

```bash
pip install psutil
python tests/test_integration.py
```

It verifies `getMe`, a ~40 MB streaming upload with flat memory usage,
SHA256 round-trip integrity, and the bot's message-handling logic.

## Security notes

- Never commit `.env`, `*.session`, `files.db`, or uploaded content — they are
  gitignored.
- All secrets are read from environment variables only (`config.py` contains no
  hardcoded credentials).
- Run the app behind a reverse proxy (nginx/Caddy) with TLS; keep
  `TG_API_BASE` internal if the Bot API server is not exposed publicly.
