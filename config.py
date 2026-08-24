import os

# Dream Cloud configuration
# =========================
# All secrets come from environment variables (.env file loaded by systemd
# EnvironmentFile=, docker --env-file, or your shell). Never hardcode them.

BOT_TOKEN = os.environ["BOT_TOKEN"]
DUMP_USER_ID = int(os.environ["DUMP_USER_ID"])
API_KEY = os.environ["API_KEY"]

DB_PATH = os.environ.get("DB_PATH", "files.db")

# Self-hosted Telegram Bot API server.
# No proxy needed and files up to 2000 MB are supported both ways.
TG_API_BASE = os.environ.get("TG_API_BASE", "http://localhost:8081")

# Upload limit of the self-hosted Bot API: 2000 MB.
MAX_FILE_SIZE_MB = int(os.environ.get("MAX_FILE_SIZE_MB", "2000"))
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024

PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://127.0.0.1:5033")

# Telegram user IDs allowed to use the bot (send a file -> get a link).
BOT_ALLOWED_USERS = [DUMP_USER_ID]
