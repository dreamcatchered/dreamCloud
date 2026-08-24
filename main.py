import os
import uuid
import time
import secrets
import base64
import hmac
import hashlib
import asyncio
import aiofiles
import glob
from urllib.parse import quote
from fastapi import FastAPI, Header, HTTPException, Request, UploadFile, File
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from config import API_KEY, MAX_FILE_SIZE, PUBLIC_URL
from database import init_db, save_file, get_file
from tg_bot import upload_file_bot, download_file_bot

app = FastAPI(title="Dream Cloud API", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

MAX_FILE_SIZE_MB = MAX_FILE_SIZE // (1024 * 1024)

# --- Signed Token System ---
def generate_signed_token():
    timestamp = int(time.time())
    random_part = secrets.token_hex(16)
    message = f"{timestamp}:{random_part}"
    signature = hmac.new(API_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{message}:{signature}"

def verify_signed_token(token: str):
    try:
        parts = token.split(":")
        if len(parts) != 3: return False
        timestamp, random_part, signature = parts
        if time.time() - int(timestamp) > 86400: return False
        message = f"{timestamp}:{random_part}"
        expected_signature = hmac.new(API_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except: return False

# --- Background Cleanup Task ---
async def cleanup_task():
    """Periodically clean up old /tmp upload files."""
    while True:
        try:
            current_time = time.time()
            for tmp_file in glob.glob("/tmp/cloud_*"):
                if current_time - os.path.getmtime(tmp_file) > 3600:
                    try: os.remove(tmp_file)
                    except: pass
        except Exception as e:
            print(f"Cleanup error: {e}")
        await asyncio.sleep(3600) # Run every hour

@app.on_event("startup")
async def startup_event():
    init_db()
    asyncio.create_task(cleanup_task())

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    token = generate_signed_token()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"csrf_token": token, "max_file_size": MAX_FILE_SIZE}
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),
    x_api_key: str = Header(None),
    x_csrf_token: str = Header(None),
    x_browser_verify: str = Header(None)
):
    # Auth
    is_api = x_api_key == API_KEY
    is_web = False
    if not is_api and x_csrf_token and verify_signed_token(x_csrf_token):
        expected_verify = base64.b64encode(f"{x_csrf_token}_dream".encode()).decode()
        if x_browser_verify == expected_verify: is_web = True
    if not is_api and not is_web: raise HTTPException(status_code=401, detail="Unauthorized.")

    # Reject oversized uploads early, before reading the body
    content_length = request.headers.get('content-length')
    if content_length and int(content_length) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Max: {MAX_FILE_SIZE_MB}MB.")

    filename = file.filename or "file"
    temp_path = f"/tmp/cloud_{uuid.uuid4().hex}"

    try:
        # Save to disk temporarily (streamed, 1MB chunks)
        async with aiofiles.open(temp_path, 'wb') as f:
            total_size = 0
            while content := await file.read(1024 * 1024):
                total_size += len(content)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail=f"File too large. Max: {MAX_FILE_SIZE_MB}MB.")
                await f.write(content)

        file_size = os.path.getsize(temp_path)
        if file_size == 0:
            raise Exception("File is empty")

        print(f"DEBUG: Uploading {filename} ({file_size} bytes) to Telegram...")

        # Stream from disk straight into the Bot API request (no in-memory buffering)
        with open(temp_path, 'rb') as f:
            tg_ref = await upload_file_bot(f, filename)

        if os.path.exists(temp_path): os.remove(temp_path)

        file_id = uuid.uuid4().hex[:12]
        save_file(file_id, filename, "application/octet-stream", file_size, "bot", tg_ref)
        return {"file_id": file_id, "url": f"{PUBLIC_URL}/file/{file_id}"}

    except HTTPException:
        if os.path.exists(temp_path): os.remove(temp_path)
        raise
    except Exception as e:
        if os.path.exists(temp_path): os.remove(temp_path)
        print(f"DEBUG ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/file/{file_id}")
async def download(file_id: str):
    file_data = get_file(file_id)
    if not file_data: raise HTTPException(status_code=404, detail="File not found")

    filename = file_data['filename']
    mime_type = file_data['mime_type']
    stream = download_file_bot(file_data['tg_ref'])

    return StreamingResponse(
        stream,
        media_type=mime_type,
        headers={"Content-Disposition": f'inline; filename="{quote(filename)}"; filename*=UTF-8\'\'{quote(filename)}'}
    )
