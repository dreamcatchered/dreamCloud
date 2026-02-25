"""
Dream Cloud Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    
    # ==================== FLASK ====================
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5033))
    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    # ==================== DATABASE ====================
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///cloud.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ==================== TELEGRAM ====================
    TELEGRAM_API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
    TELEGRAM_API_HASH = os.getenv('TELEGRAM_API_HASH', '')
    TELEGRAM_CHAT_ID = int(os.getenv('TELEGRAM_CHAT_ID', '0'))
    TELEGRAM_SESSION_NAME = os.getenv('TELEGRAM_SESSION_NAME', 'cloud_session')
    USE_SERVER_TELEGRAM = os.getenv('USE_SERVER_TELEGRAM', 'true').lower() == 'true'
    
    # ==================== SSO INTEGRATION ====================
    SSO_ENABLED = os.getenv('SSO_ENABLED', 'true').lower() == 'true'
    SSO_CLIENT_ID = os.getenv('SSO_CLIENT_ID', '')
    SSO_CLIENT_SECRET = os.getenv('SSO_CLIENT_SECRET', '')
    SSO_AUTH_URL = os.getenv('SSO_AUTH_URL', '')
    
    # ==================== FILE LIMITS ====================
    MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', 2000))
    MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024
    TEMP_UPLOAD_DIR = os.getenv('TEMP_UPLOAD_DIR', './temp_uploads')
    
    # ==================== TELEGRAM LIMITS ====================
    TELEGRAM_UPLOAD_DELAY = float(os.getenv('TELEGRAM_UPLOAD_DELAY', '1'))
    MAX_QUEUE_SIZE = int(os.getenv('MAX_QUEUE_SIZE', '100'))
    
    # ==================== ENCRYPTION ====================
    PBKDF2_ITERATIONS = int(os.getenv('PBKDF2_ITERATIONS', '600000'))
    
    # ==================== RATE LIMITING ====================
    RATE_LIMIT_PER_HOUR = int(os.getenv('RATE_LIMIT_PER_HOUR', '1000'))
    
    # ==================== TELEGRAM BOT ====================
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '8374181291:AAFdRqbghK0RXqAHCUjwx1k4yk492fpdlVo')
    TELEGRAM_BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME', 'DreamCloudRobot')
    _webapp_url = os.getenv('WEBAPP_URL', 'https://cloud.dreampartners.online')
    WEBAPP_URL = _webapp_url.rstrip('/') if _webapp_url else None
    
    # ==================== SECURITY ====================
    SESSION_COOKIE_SECURE = WEBAPP_URL.startswith('https') if WEBAPP_URL else False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

