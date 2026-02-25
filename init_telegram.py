from telethon import TelegramClient
from config import Config
import os
import asyncio

async def main():
    print("=== Dream Cloud Telegram Session Initializer ===")
    print(f"API ID: {Config.TELEGRAM_API_ID}")
    print(f"Session File: {Config.TELEGRAM_SESSION_NAME}.session")
    
    if Config.TELEGRAM_API_ID == 0:
        print("Error: TELEGRAM_API_ID not set in .env")
        return

    client = TelegramClient(
        Config.TELEGRAM_SESSION_NAME,
        Config.TELEGRAM_API_ID,
        Config.TELEGRAM_API_HASH
    )
    
    print("\nConnecting to Telegram...")
    await client.start()
    
    me = await client.get_me()
    print(f"\nSuccess! Logged in as: {me.first_name} (@{me.username})")
    print(f"Session file saved to: {os.path.abspath(Config.TELEGRAM_SESSION_NAME + '.session')}")
    print("\nYou can now run the main application.")

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
