#!/home/dream/projects/cloud/venv/bin/python
"""
Dream Cloud - Application Entry Point
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, start_worker, start_telegram_bot
from config import Config

if __name__ == '__main__':
    app = create_app()
    
    # Ensure database tables exist
    with app.app_context():
        from models import db
        db.create_all()
        print("✅ Database tables verified")
    
    start_worker()
    start_telegram_bot()
    
    print(f"🌥️  Dream Cloud starting on http://{Config.HOST}:{Config.PORT}")
    print(f"🤖 Telegram bot: @{Config.TELEGRAM_BOT_USERNAME}")
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=False,
        threaded=True
    )

