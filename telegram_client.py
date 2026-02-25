import os
import asyncio
import logging
from telethon import TelegramClient
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global client instance
_client = None
_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)

def get_telegram_client():
    """Get or create Telegram client"""
    global _client
    if _client is None:
        session_path = os.path.abspath(Config.TELEGRAM_SESSION_NAME)
        logger.info(f"Initializing Telegram client with session: {session_path}")
        
        _client = TelegramClient(
            session_path,
            Config.TELEGRAM_API_ID,
            Config.TELEGRAM_API_HASH,
            loop=_loop
        )
        
        # Start the client (connect)
        _loop.run_until_complete(_client.connect())
        
    return _client

def run_async(coro):
    """Run async coroutine in the global loop"""
    return _loop.run_until_complete(coro)

def sync_upload_file(file_path, filename=None):
    """Upload file to Telegram (sync wrapper)"""
    client = get_telegram_client()

    async def _upload():
        if not await client.is_user_authorized():
            logger.error("Client not authorized! Run init_telegram.py first.")
            return None, None, None

        try:
            # Upload to Saved Messages (me) or configured chat
            chat_id = Config.TELEGRAM_CHAT_ID if Config.TELEGRAM_CHAT_ID != 0 else 'me'

            # Send file
            message = await client.send_file(
                chat_id,
                file_path,
                force_document=True,
                caption=f"File: {filename or os.path.basename(file_path)}"
            )
            # Return (file_id, access_hash, message_id)
            return message.media.document.id, message.media.document.access_hash, message.id
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return None, None, None

    return run_async(_upload())

def sync_download_file(message_id, output_path):
    """Download file from Telegram (sync wrapper)"""
    client = get_telegram_client()
    
    async def _download():
        if not await client.is_user_authorized():
            return False
            
        try:
            chat_id = Config.TELEGRAM_CHAT_ID if Config.TELEGRAM_CHAT_ID != 0 else 'me'
            
            # Get message
            message = await client.get_messages(chat_id, ids=message_id)
            if not message or not message.media:
                return False
                
            # Download
            await client.download_media(message, file=output_path)
            return True
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    return run_async(_download())

def sync_delete_file(message_id):
    """Delete file from Telegram (sync wrapper)"""
    client = get_telegram_client()
    
    async def _delete():
        if not await client.is_user_authorized():
            return False
            
        try:
            chat_id = Config.TELEGRAM_CHAT_ID if Config.TELEGRAM_CHAT_ID != 0 else 'me'
            await client.delete_messages(chat_id, [message_id])
            return True
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return False

    return run_async(_delete())
