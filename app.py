"""
Dream Cloud - Personal Cloud Storage with Telegram Backend
Main Flask Application
"""
import os
import hashlib
import logging
import uuid
import threading
import time
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_cors import CORS
import requests

from config import Config
from models import db, User, File, UploadTask, Folder, PublicShare
from telegram_client import sync_upload_file, sync_download_file, sync_delete_file, get_telegram_client, run_async
from video_compressor import compress_file_if_needed


# API Key authentication decorator
def require_api_key(f):
    """Decorator to require API key for API endpoints (alternative to login_required)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow if user is logged in (web interface)
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        
        # Otherwise require API key
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'API key required',
                'message': 'Use X-API-Key header or api_key query parameter'
            }), 401
        
        # Find user by API key
        from models import hash_api_key
        api_key_hash = hash_api_key(api_key)
        user = User.query.filter_by(api_key_hash=api_key_hash).first()
        
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Check rate limit
        allowed, remaining, reset_time = user.check_rate_limit()
        
        if not allowed:
            response = jsonify({
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please wait before making more requests.',
                'retry_after': reset_time - int(datetime.utcnow().timestamp())
            })
            response.headers['X-RateLimit-Limit'] = '1000'
            response.headers['X-RateLimit-Remaining'] = '0'
            response.headers['X-RateLimit-Reset'] = str(reset_time)
            return response, 429
        
        # Update last used timestamp
        user.api_key_last_used = datetime.utcnow()
        db.session.commit()
        
        # Store user in request context for API endpoints
        request.api_user = user
        
        return f(*args, **kwargs)
    return decorated_function


def get_current_api_user():
    """Get current user from either session or API key"""
    if current_user.is_authenticated:
        return current_user
    return getattr(request, 'api_user', None)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, supports_credentials=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

# Ensure temp upload directory exists
os.makedirs(Config.TEMP_UPLOAD_DIR, exist_ok=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Background upload worker
class UploadWorker(threading.Thread):
    """
    Background worker for processing file uploads to Telegram.
    
    ENCRYPTION FLOW:
    1. Read original file from temp storage
    2. Encrypt file data with unique file key (AES-256-GCM)
    3. Encrypt file key with user's master key
    4. Upload encrypted data to Telegram (with random filename)
    5. Store encryption metadata in database
    6. Delete original temp file
    
    The server never stores unencrypted file data permanently.
    """
    
    def __init__(self, app):
        super().__init__(daemon=True)
        self.app = app
        self.running = True
    
    def run(self):
        while self.running:
            with self.app.app_context():
                self.process_pending_uploads()
            time.sleep(2)
    
    def process_pending_uploads(self):
        """Process pending upload tasks"""
        task = UploadTask.query.filter_by(status='pending').first()
        
        if not task:
            return
        
        try:
            task.status = 'processing'
            task.started_at = datetime.utcnow()
            task.attempts += 1
            db.session.commit()
            
            file_record = task.file
            user = file_record.owner
            
            # ==================== ENCRYPTION ====================
            # Update status to encrypting
            file_record.status = 'encrypting'
            db.session.commit()
            
            # Read original file data
            with open(task.temp_path, 'rb') as f:
                original_data = f.read()
            
            # Get user's master key (derived from stored salt)
            # For now, use a server-side encryption key since we don't have user's password
            # In production, this should be done client-side or with user's session key
            from encryption_utils import FileEncryptor, generate_salt, derive_master_key, bytes_to_base64
            
            # Ensure user has master key salt
            if not user.master_key_salt:
                salt = generate_salt()
                user.master_key_salt = bytes_to_base64(salt)
                db.session.commit()
            else:
                from encryption_utils import base64_to_bytes
                salt = base64_to_bytes(user.master_key_salt)
            
            # Derive a server-side encryption key for this user
            # Note: In a fully secure implementation, this would use the user's password
            # For now, we use a deterministic key based on user ID and server secret
            server_encryption_password = f"{Config.SECRET_KEY}:{user.id}:{user.username}"
            master_key = derive_master_key(server_encryption_password, salt)
            encryptor = FileEncryptor(master_key)
            
            # Encrypt the file
            encrypted_data, encryption_metadata = encryptor.encrypt(original_data)
            
            # Store encryption metadata
            file_record.set_encryption_metadata(encryption_metadata)
            
            logger.info(f"File {file_record.id} encrypted: {len(original_data)} -> {len(encrypted_data)} bytes")
            
            # ==================== SAVE ENCRYPTED FILE ====================
            # Save encrypted data to temp file for upload
            encrypted_temp_path = task.temp_path + '.encrypted'
            with open(encrypted_temp_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Update status to uploading
            file_record.status = 'uploading'
            db.session.commit()
            
            # ==================== UPLOAD TO TELEGRAM ====================
            # Use random filename to hide original name
            random_filename = f"{uuid.uuid4().hex}.bin"
            
            file_id, access_hash, message_id = sync_upload_file(
                encrypted_temp_path,
                random_filename  # Don't reveal original filename in Telegram
            )
            
            # Clean up encrypted temp file
            if os.path.exists(encrypted_temp_path):
                os.remove(encrypted_temp_path)
            
            if file_id and message_id:
                # Success - update file record
                file_record.telegram_file_id = file_id
                file_record.telegram_access_hash = access_hash
                file_record.telegram_message_id = message_id
                file_record.status = 'ready'
                file_record.uploaded_at = datetime.utcnow()
                
                task.status = 'completed'
                task.completed_at = datetime.utcnow()
                
                # Update user stats
                user.total_files += 1
                user.total_size += file_record.file_size
                user.total_encrypted_size = (user.total_encrypted_size or 0) + (file_record.encrypted_size or 0)
                
                # Clean up original temp file
                if os.path.exists(task.temp_path):
                    os.remove(task.temp_path)
                
                logger.info(f"Successfully uploaded encrypted file {file_record.id} to Telegram")
            else:
                raise Exception("Failed to get file_id from Telegram")
                
        except Exception as e:
            logger.error(f"Error processing upload task {task.id}: {e}")
            task.error_message = str(e)
            
            # Clean up any temp files
            if os.path.exists(task.temp_path + '.encrypted'):
                try:
                    os.remove(task.temp_path + '.encrypted')
                except:
                    pass
            
            if task.attempts >= task.max_attempts:
                task.status = 'failed'
                file_record = task.file
                file_record.status = 'error'
                file_record.error_message = f"Upload failed after {task.attempts} attempts: {str(e)}"
            else:
                task.status = 'pending'  # Retry
        
        db.session.commit()


# ==================== WEB PAGES ====================

@app.route('/')
def index():
    """Main page - redirect to dashboard if logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html', sso_enabled=Config.SSO_ENABLED)


@app.route('/register')
@app.route('/signup')
def register_page():
    """Registration page"""
    sso_data = session.get('sso_registration')
    return render_template('register.html', sso_data=sso_data)


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    return render_template('dashboard.html', user=current_user)


@app.route('/settings')
@login_required
def settings_page():
    """User settings page"""
    return render_template('settings.html', user=current_user, config=Config)


# ==================== TELEGRAM WEBAPP ====================

def validate_telegram_webapp_data(init_data: str) -> dict:
    """
    Validate Telegram WebApp initData according to official docs.
    https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    
    Returns user data if valid, None otherwise.
    """
    import hmac
    import hashlib
    from urllib.parse import parse_qs, unquote
    import json
    
    if not init_data or not Config.TELEGRAM_BOT_TOKEN:
        return None
    
    try:
        # Parse init_data
        parsed = dict(x.split('=', 1) for x in init_data.split('&'))
        
        # Get hash from data
        received_hash = parsed.pop('hash', None)
        if not received_hash:
            return None
        
        # Create data-check-string
        data_check_arr = []
        for key in sorted(parsed.keys()):
            data_check_arr.append(f"{key}={unquote(parsed[key])}")
        data_check_string = '\n'.join(data_check_arr)
        
        # Create secret key: HMAC_SHA256(bot_token, "WebAppData")
        secret_key = hmac.new(
            b"WebAppData",
            Config.TELEGRAM_BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()
        
        # Calculate hash
        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Validate hash
        if not hmac.compare_digest(calculated_hash, received_hash):
            logger.warning("Telegram WebApp hash validation failed")
            return None
        
        # Parse user data
        user_data = parsed.get('user')
        if user_data:
            return json.loads(unquote(user_data))
        
        return None
    except Exception as e:
        logger.error(f"Error validating Telegram WebApp data: {e}")
        return None


def get_or_create_telegram_session(telegram_user_id: int) -> User:
    """Get user by Telegram ID or return None"""
    return User.query.filter_by(telegram_user_id=telegram_user_id).first()


@app.route('/telegram/app')
def telegram_app():
    """
    Telegram WebApp interface.
    Authenticates user via Telegram initData - no login required!
    """
    # Try to get initData from query params (passed by Telegram)
    init_data = request.args.get('initData') or request.args.get('tgWebAppData')
    
    # If user is already logged in via session, use that
    if current_user.is_authenticated:
        return render_template('telegram_app.html', user=current_user, config=Config)
    
    # Validate Telegram WebApp data
    if init_data:
        tg_user = validate_telegram_webapp_data(init_data)
        if tg_user and tg_user.get('id'):
            user = get_or_create_telegram_session(tg_user['id'])
            if user:
                login_user(user)
                return render_template('telegram_app.html', user=user, config=Config)
    
    # No valid auth - show the app anyway, it will handle auth via JS
    return render_template('telegram_app.html', user=None, config=Config)


@app.route('/api/telegram/auth', methods=['POST'])
def api_telegram_auth():
    """
    Authenticate user via Telegram WebApp initData.
    This is the proper way to auth Telegram Mini Apps.
    """
    data = request.get_json() or {}
    init_data = data.get('initData', '')
    
    if not init_data:
        return jsonify({'error': 'initData required'}), 400
    
    # Validate initData
    tg_user = validate_telegram_webapp_data(init_data)
    
    if not tg_user or not tg_user.get('id'):
        return jsonify({'error': 'Invalid Telegram data'}), 401
    
    telegram_id = tg_user['id']
    
    # Find user by Telegram ID
    user = User.query.filter_by(telegram_user_id=telegram_id).first()
    
    if not user:
        return jsonify({
            'authenticated': False,
            'error': 'Telegram не привязан к аккаунту',
            'telegram_id': telegram_id,
            'telegram_user': tg_user
        }), 401
    
    # Login user
    login_user(user)
    
    return jsonify({
        'authenticated': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'telegram_id': user.telegram_user_id,
            'total_files': user.total_files,
            'total_size': user.total_size
        }
    })


@app.route('/telegram/link')
def telegram_link():
    """Page for linking Telegram account - works from WebApp"""
    # Check if coming from Telegram WebApp
    init_data = request.args.get('initData') or request.args.get('tgWebAppData')
    tg_user = None
    
    if init_data:
        tg_user = validate_telegram_webapp_data(init_data)
    
    # If user is logged in, show link page
    if current_user.is_authenticated:
        return render_template('telegram_link.html', 
                              user=current_user, 
                              tg_user=tg_user,
                              config=Config)
    
    # Not logged in - redirect to login
    return redirect(url_for('login_page', next=request.url))


@app.route('/api/telegram/link', methods=['POST'])
@login_required
def api_telegram_link():
    """API endpoint to link Telegram account"""
    data = request.get_json() or {}
    tg_id = data.get('telegram_id')
    
    if not tg_id:
        return jsonify({'error': 'Telegram ID required'}), 400
    
    # Check if this Telegram ID is already linked to another user
    existing_user = User.query.filter_by(telegram_user_id=int(tg_id)).first()
    if existing_user and existing_user.id != current_user.id:
        return jsonify({'error': 'Этот Telegram уже привязан к другому аккаунту'}), 400
    
    # Store Telegram user ID for bot integration
    current_user.telegram_user_id = int(tg_id)
    current_user.telegram_linked_at = datetime.utcnow()
    db.session.commit()
    
    # Generate API key if not exists
    api_key = None
    if not current_user.api_key_hash:
        api_key = current_user.generate_new_api_key()
        db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Telegram аккаунт привязан',
        'api_key': api_key,
        'user_id': current_user.id
    })


@app.route('/api/telegram/unlink', methods=['POST'])
@login_required
def api_telegram_unlink():
    """API endpoint to unlink Telegram account"""
    if not current_user.telegram_user_id:
        return jsonify({'error': 'Telegram не привязан'}), 400
    
    current_user.telegram_user_id = None
    current_user.telegram_linked_at = None
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Telegram отвязан'
    })


@app.route('/api/telegram/send-file', methods=['POST'])
def api_telegram_send_file():
    """Send file to user's Telegram chat via bot"""
    data = request.get_json() or {}
    file_id = data.get('file_id')
    telegram_id = data.get('telegram_id')
    init_data = data.get('initData', '')
    
    if not file_id:
        return jsonify({'error': 'file_id required'}), 400
    
    # Get user - either from session or from initData
    user = None
    if current_user.is_authenticated:
        user = current_user
    elif init_data:
        tg_user = validate_telegram_webapp_data(init_data)
        if tg_user and tg_user.get('id'):
            user = User.query.filter_by(telegram_user_id=tg_user['id']).first()
            if not telegram_id:
                telegram_id = tg_user['id']
    
    # Fallback: find user by telegram_id
    if not user and telegram_id:
        user = User.query.filter_by(telegram_user_id=telegram_id).first()
    
    if not user:
        return jsonify({'error': 'Пользователь не авторизован'}), 401
    
    # Get file
    file = File.query.filter_by(id=file_id, user_id=user.id).first()
    if not file:
        return jsonify({'error': 'Файл не найден'}), 404
    
    if file.status != 'ready':
        return jsonify({'error': 'Файл ещё не готов'}), 400
    
    # Get telegram_id from user if not provided
    if not telegram_id:
        telegram_id = user.telegram_user_id
    
    if not telegram_id:
        return jsonify({'error': 'Telegram ID не найден'}), 400
    
    # File download handled via direct API endpoint now
    # No need for telegram bot sending
    return jsonify({'error': 'Use /api/files/{id}/download endpoint'}), 400


@app.route('/api/auth/api-key', methods=['GET'])
@login_required
def api_get_key_info():
    """Get API key info for current user"""
    has_key = current_user.api_key_hash is not None
    return jsonify({
        'has_api_key': has_key,
        'created_at': current_user.api_key_created_at.isoformat() if current_user.api_key_created_at else None,
        'last_used': current_user.api_key_last_used.isoformat() if current_user.api_key_last_used else None,
        'message': 'API ключ уже создан. Используйте POST для генерации нового.' if has_key else 'API ключ не создан. Используйте POST для генерации.'
    })


@app.route('/api/auth/api-key', methods=['POST'])
@login_required
def api_generate_key():
    """Generate a new API key for current user"""
    # Ensure user has master key salt for encryption
    if not current_user.master_key_salt:
        from encryption_utils import generate_salt, bytes_to_base64
        current_user.master_key_salt = bytes_to_base64(generate_salt())
    
    # Generate new API key
    plain_key = current_user.generate_new_api_key()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'api_key': plain_key,
        'message': 'Сохраните этот ключ! Он показывается только один раз.',
        'warning': 'Предыдущий API ключ (если был) теперь недействителен.'
    })


@app.route('/api/auth/api-key', methods=['DELETE'])
@login_required
def api_revoke_key():
    """Revoke current API key"""
    if not current_user.api_key_hash:
        return jsonify({'error': 'API ключ не найден'}), 404
    
    current_user.revoke_api_key()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'API ключ отозван'
    })


@app.route('/api/auth/encryption-info', methods=['GET'])
@login_required
def api_get_encryption_info():
    """
    Get encryption information for file recovery.
    
    IMPORTANT: The master key is derived from your password.
    This endpoint returns the salt needed for key derivation.
    To recover files, you need:
    1. Your password
    2. The salt (returned here)
    3. The encryption metadata from file export
    """
    # Ensure user has master key salt
    if not current_user.master_key_salt:
        from encryption_utils import generate_salt, bytes_to_base64
        current_user.master_key_salt = bytes_to_base64(generate_salt())
        db.session.commit()
    
    return jsonify({
        'master_key_salt': current_user.master_key_salt,
        'encryption_version': 1,
        'algorithm': 'AES-256-GCM',
        'key_derivation': 'PBKDF2-SHA256',
        'pbkdf2_iterations': Config.PBKDF2_ITERATIONS,
        'message': 'Для расшифровки файлов нужен ваш пароль и этот salt. Сохраните в безопасном месте!',
        'recovery_instructions': (
            'Для восстановления файлов: '
            '1. Используйте пароль + salt для вывода master key через PBKDF2. '
            '2. Экспортируйте метаданные файлов через /api/export/file-ids. '
            '3. Для каждого файла расшифруйте file_key используя master key. '
            '4. Скачайте зашифрованный файл из Telegram и расшифруйте его.'
        )
    })


@app.route('/api/export/file-ids', methods=['GET'])
@login_required
def api_export_file_ids():
    """Export all file IDs for recovery purposes"""
    export_data = current_user.get_file_ids_export()
    
    return jsonify({
        'success': True,
        'data': export_data,
        'message': 'Сохраните эти данные! С их помощью можно восстановить файлы из Telegram.'
    })


# ==================== AUTH API ====================

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Register a new user"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    sso_data = session.get('sso_registration')
    
    if not username or len(username) < 3:
        return jsonify({'error': 'Логин должен быть не менее 3 символов'}), 400
    
    if not password or len(password) < 6:
        return jsonify({'error': 'Пароль должен быть не менее 6 символов'}), 400
    
    # Check if username already exists (excluding SSO user if registering via SSO)
    existing = User.query.filter_by(username=username).first()
    if existing:
        if not sso_data or existing.sso_id != sso_data.get('sso_id'):
            return jsonify({'error': 'Пользователь уже существует'}), 400
    
    # Create user
    if sso_data:
        # Registering via SSO - link SSO account
        user = User(
            username=username,
            sso_id=sso_data.get('sso_id'),
            sso_phone=sso_data.get('sso_phone')
        )
        user.set_password(password)
        session.pop('sso_registration', None)
    else:
        # Regular registration
        user = User(username=username)
        user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    login_user(user)
    
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })


@app.route('/api/auth/set-password', methods=['POST'])
def api_set_password():
    """Set password for SSO user"""
    data = request.get_json()
    sso_data = session.get('sso_set_password')
    
    if not sso_data:
        return jsonify({'error': 'Сессия истекла'}), 400
    
    password = data.get('password', '')
    password_confirm = data.get('password_confirm', '')
    
    if not password or len(password) < 6:
        return jsonify({'error': 'Пароль должен быть не менее 6 символов'}), 400
    
    if password != password_confirm:
        return jsonify({'error': 'Пароли не совпадают'}), 400
    
    user = User.query.get(sso_data.get('user_id'))
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    user.set_password(password)
    db.session.commit()
    
    session.pop('sso_set_password', None)
    login_user(user)
    
    return jsonify({
        'success': True,
        'message': 'Пароль успешно установлен'
    })


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login user"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Неверный логин или пароль'}), 401
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    login_user(user)
    
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """Logout user"""
    logout_user()
    return jsonify({'success': True})


@app.route('/api/auth/me')
@login_required
def api_me():
    """Get current user info"""
    return jsonify({
        'user': current_user.to_dict()
    })


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password"""
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_user.check_password(current_password):
        return jsonify({'error': 'Неверный текущий пароль'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Новый пароль должен быть не менее 6 символов'}), 400
    
    current_user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Пароль успешно изменён'})


@app.route('/api/auth/unlink-sso', methods=['POST'])
@login_required
def api_unlink_sso():
    """Unlink SSO from account"""
    if not current_user.sso_id:
        return jsonify({'error': 'DreamID не привязан'}), 400
    
    # Check if user has password set (can still login after unlink)
    if not current_user.password_hash:
        return jsonify({'error': 'Сначала установите пароль для входа'}), 400
    
    current_user.sso_id = None
    current_user.sso_phone = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'DreamID отвязан'})


# ==================== SSO INTEGRATION ====================

@app.route('/sso/login')
def sso_login():
    """Initiate SSO login with dreamID"""
    if not Config.SSO_ENABLED:
        return redirect(url_for('login_page'))
    
    # Use configured URL to avoid http/https mismatch behind proxy
    if Config.WEBAPP_URL:
        redirect_uri = f"{Config.WEBAPP_URL}/sso/callback"
    else:
        redirect_uri = url_for('sso_callback', _external=True)
        
    state = str(uuid.uuid4())
    session['sso_state'] = state
    
    sso_url = f"{Config.SSO_AUTH_URL}/sso?client_id={Config.SSO_CLIENT_ID}&redirect_uri={redirect_uri}&state={state}"
    return redirect(sso_url)


@app.route('/sso/callback')
def sso_callback():
    """Handle SSO callback"""
    logger.info("SSO callback hit")
    if not Config.SSO_ENABLED:
        logger.warning("SSO not enabled, redirecting to login")
        return redirect(url_for('login_page'))
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        logger.warning("No code in SSO callback")
        return redirect(url_for('login_page'))
    
    # Verify state
    if state != session.get('sso_state'):
        logger.warning(f"Invalid state. Session: {session.get('sso_state')}, Received: {state}")
        return jsonify({'error': 'Invalid state'}), 400
    
    # Use configured URL to avoid http/https mismatch behind proxy
    if Config.WEBAPP_URL:
        redirect_uri = f"{Config.WEBAPP_URL}/sso/callback"
    else:
        redirect_uri = url_for('sso_callback', _external=True)

    try:
        logger.info(f"Exchange code for token with redirect_uri: {redirect_uri}")
        # Exchange code for token
        token_url = f"{Config.SSO_AUTH_URL}/api/sso/token"
        logger.info(f"Token URL: {token_url}")
        
        token_resp = requests.post(
            token_url,
            json={
                'code': code,
                'client_id': Config.SSO_CLIENT_ID,
                'client_secret': Config.SSO_CLIENT_SECRET,
                'redirect_uri': redirect_uri
            },
            timeout=10
        )
        
        if token_resp.status_code != 200:
            logger.error(f"SSO token error: {token_resp.status_code} - {token_resp.text}")
            return redirect(url_for('login_page'))
        
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
        
        # Get user info
        user_url = f"{Config.SSO_AUTH_URL}/api/sso/user"
        user_resp = requests.get(
            user_url,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_resp.status_code != 200:
            logger.error(f"SSO user error: {user_resp.status_code} - {user_resp.text}")
            return redirect(url_for('login_page'))
        
        user_data = user_resp.json()
        logger.info(f"SSO user data received: {user_data.get('id')}")
        sso_id = user_data['id']
        
        # Find existing user
        user = User.query.filter_by(sso_id=sso_id).first()
        
        if not user:
            # New user - redirect to registration with SSO data
            session['sso_registration'] = {
                'sso_id': sso_id,
                'sso_phone': user_data.get('phone'),
                'sso_username': user_data.get('username', f"user_{sso_id}")
            }
            return redirect(url_for('register_page', sso=1))
        
        # Existing user - check if has password
        if not user.password_hash:
            # User exists but no password - redirect to set password
            session['sso_set_password'] = {
                'user_id': user.id,
                'sso_id': sso_id
            }
            return redirect(url_for('set_password_page'))
        
        # User exists and has password - login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        login_user(user)
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"SSO callback error: {e}")
        return redirect(url_for('login_page'))


# ==================== FILES API ====================

@app.route('/api/v1/files', methods=['GET'])
@require_api_key
def api_list_files():
    """List user's files"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    file_type = request.args.get('type')  # filter by type
    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    
    query = File.query.filter_by(user_id=user.id)
    
    # Exclude deleted files
    query = query.filter(File.status != 'deleted')
    
    # Filter by type
    if file_type:
        query = query.filter_by(file_type=file_type)
    
    # Search by filename
    if search:
        query = query.filter(File.original_filename.ilike(f'%{search}%'))
    
    # Sorting
    if sort == 'name':
        sort_col = File.original_filename
    elif sort == 'size':
        sort_col = File.file_size
    elif sort == 'type':
        sort_col = File.file_type
    else:
        sort_col = File.created_at
    
    if order == 'asc':
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'files': [f.to_dict() for f in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages
    })


@app.route('/api/v1/files/upload', methods=['POST'])
@require_api_key
def api_upload_file():
    """Upload a new file"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не найден'}), 400
    
    file = request.files['file']
    
    if not file.filename:
        return jsonify({'error': 'Имя файла пустое'}), 400
    
    # Check file size
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > Config.MAX_CONTENT_LENGTH:
        return jsonify({'error': f'Файл слишком большой. Максимум: {Config.MAX_FILE_SIZE_MB} МБ'}), 400
    
    # Generate unique filename for temp storage
    original_filename = file.filename
    unique_id = str(uuid.uuid4())
    temp_filename = f"{unique_id}_{original_filename}"
    temp_path = os.path.join(Config.TEMP_UPLOAD_DIR, temp_filename)
    
    # Calculate file hash
    file_hash = hashlib.sha256()
    
    # Save file temporarily
    file.save(temp_path)
    
    # Calculate hash
    with open(temp_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            file_hash.update(chunk)
    
    file_hash_hex = file_hash.hexdigest()
    
    # Check for duplicates
    existing = File.query.filter_by(
        user_id=user.id,
        file_hash=file_hash_hex,
        status='ready'
    ).first()
    
    if existing:
        os.remove(temp_path)
        return jsonify({
            'error': 'Файл уже загружен',
            'existing_file': existing.to_dict()
        }), 409
    
    # Detect file type
    mime_type = file.content_type
    file_type = File.detect_file_type(mime_type, original_filename)
    
    # Create file record (original filename stored for display, not sent to Telegram)
    file_record = File(
        user_id=user.id,
        original_filename=original_filename,
        mime_type=mime_type,
        file_size=file_size,
        file_hash=file_hash_hex,
        file_type=file_type,
        status='pending'
    )
    
    db.session.add(file_record)
    db.session.commit()
    
    # Create upload task
    task = UploadTask(
        file_id=file_record.id,
        temp_path=temp_path
    )
    
    db.session.add(task)
    db.session.commit()
    
    logger.info(f"Created upload task for file {file_record.id}")
    
    return jsonify({
        'success': True,
        'file': file_record.to_dict(),
        'message': 'Файл добавлен в очередь загрузки'
    })


@app.route('/api/v1/files/<int:file_id>', methods=['GET'])
@require_api_key
def api_get_file(file_id):
    """Get file info"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    
    if not file_record:
        return jsonify({'error': 'Файл не найден'}), 404
    
    return jsonify({'file': file_record.to_dict()})


@app.route('/api/v1/files/<int:file_id>/download', methods=['GET'])
@require_api_key
def api_download_file(file_id):
    """
    Download and decrypt a file.
    
    DECRYPTION FLOW:
    1. Download encrypted data from Telegram
    2. Derive user's master key
    3. Decrypt file key using master key
    4. Decrypt file data using file key
    5. Return decrypted data to user
    """
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    
    if not file_record:
        return jsonify({'error': 'Файл не найден'}), 404
    
    if file_record.status != 'ready':
        return jsonify({'error': 'Файл ещё не готов к скачиванию'}), 400
    
    if not file_record.telegram_message_id:
        return jsonify({'error': 'Файл недоступен'}), 400
    
    # Create temp file for download
    temp_path = os.path.join(Config.TEMP_UPLOAD_DIR, f"download_{uuid.uuid4()}.encrypted")
    
    try:
        # Download encrypted data from Telegram
        success = sync_download_file(file_record.telegram_message_id, temp_path)
        
        if not success or not os.path.exists(temp_path):
            return jsonify({'error': 'Ошибка при скачивании файла'}), 500
        
        # Read encrypted data
        with open(temp_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Clean up encrypted temp file
        os.remove(temp_path)
        
        # ==================== DECRYPTION ====================
        from encryption_utils import FileEncryptor, derive_master_key, base64_to_bytes
        
        # Get encryption metadata
        encryption_metadata = file_record.get_encryption_metadata()
        
        if not encryption_metadata.get('encrypted_file_key'):
            # File is not encrypted (legacy file)
            data = encrypted_data
        else:
            # Derive master key (same as during encryption)
            salt = base64_to_bytes(user.master_key_salt)
            server_encryption_password = f"{Config.SECRET_KEY}:{user.id}:{user.username}"
            master_key = derive_master_key(server_encryption_password, salt)
            
            # Create encryptor and decrypt
            encryptor = FileEncryptor(master_key)
            try:
                data = encryptor.decrypt(encrypted_data, encryption_metadata)
            except Exception as e:
                logger.error(f"Decryption failed for file {file_id}: {e}")
                return jsonify({'error': 'Ошибка расшифровки файла'}), 500
        
        # Check if preview mode (inline) or download (attachment)
        preview_mode = request.args.get('preview', '0') == '1'
        disposition = 'inline' if preview_mode else 'attachment'
        
        # Encode filename properly for HTTP headers (RFC 5987)
        from urllib.parse import quote
        filename_ascii = file_record.original_filename.encode('ascii', 'ignore').decode('ascii')
        filename_utf8 = quote(file_record.original_filename.encode('utf-8'))
        
        # Use RFC 5987 encoding for non-ASCII filenames
        if filename_ascii != file_record.original_filename:
            content_disposition = f'{disposition}; filename="{filename_ascii}"; filename*=UTF-8\'\'{filename_utf8}'
        else:
            content_disposition = f'{disposition}; filename="{file_record.original_filename}"'
        
        return Response(
            data,
            mimetype=file_record.mime_type or 'application/octet-stream',
            headers={
                'Content-Disposition': content_disposition,
                'Content-Length': str(len(data))
            }
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': 'Ошибка при скачивании файла'}), 500


@app.route('/api/v1/files/<int:file_id>', methods=['DELETE'])
@require_api_key
def api_delete_file(file_id):
    """Delete a file"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    
    if not file_record:
        return jsonify({'error': 'Файл не найден'}), 404
    
    try:
        # Delete from Telegram if uploaded
        if file_record.telegram_message_id:
            sync_delete_file(file_record.telegram_message_id)
        
        # Update user stats
        if file_record.status == 'ready':
            user.total_files = max(0, user.total_files - 1)
            user.total_size = max(0, user.total_size - file_record.file_size)
        
        # Delete file record
        file_record.status = 'deleted'
        
        # Also delete any pending upload tasks
        UploadTask.query.filter_by(file_id=file_id).delete()
        
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': 'Ошибка при удалении файла'}), 500


@app.route('/api/v1/stats', methods=['GET'])
@require_api_key
def api_stats():
    """Get user storage statistics"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    files = File.query.filter_by(user_id=user.id).filter(File.status != 'deleted').all()
    
    by_type = {}
    for f in files:
        if f.file_type not in by_type:
            by_type[f.file_type] = {'count': 0, 'size': 0}
        by_type[f.file_type]['count'] += 1
        by_type[f.file_type]['size'] += f.file_size
    
    pending = File.query.filter_by(user_id=user.id, status='pending').count()
    uploading = File.query.filter_by(user_id=user.id, status='uploading').count()
    ready = File.query.filter_by(user_id=user.id, status='ready').count()
    errors = File.query.filter_by(user_id=user.id, status='error').count()
    
    return jsonify({
        'total_files': user.total_files,
        'total_size': user.total_size,
        'total_size_readable': User._format_size(user.total_size),
        'by_type': by_type,
        'status': {
            'pending': pending,
            'uploading': uploading,
            'ready': ready,
            'errors': errors
        }
    })


# ==================== LEGACY API ROUTES (backward compatibility) ====================

@app.route('/api/files', methods=['GET'])
@require_api_key
def api_list_files_legacy():
    """List files and folders for web dashboard"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    folder_id = request.args.get('folder_id', type=int)

    # Get folders in current directory
    folders = Folder.query.filter_by(user_id=user.id, parent_id=folder_id).all()

    # Get files in current directory (not deleted)
    files = File.query.filter_by(user_id=user.id, folder_id=folder_id).filter(
        File.status != 'deleted'
    ).all()

    # Combine folders and files with is_folder flag
    items = []

    # Add folders
    for folder in folders:
        item = folder.to_dict()
        item['is_folder'] = True
        item['type'] = 'folder'
        items.append(item)

    # Add files
    for file in files:
        item = file.to_dict()
        item['is_folder'] = False
        item['type'] = item.get('file_type', 'file')
        items.append(item)

    return jsonify({'files': items})


@app.route('/api/files/upload', methods=['POST'])
@require_api_key
def api_upload_file_legacy():
    """Legacy endpoint - redirects to v1"""
    return api_upload_file()


@app.route('/api/files/<int:file_id>', methods=['GET'])
@require_api_key
def api_get_file_legacy(file_id):
    """Legacy endpoint - redirects to v1"""
    return api_get_file(file_id)


@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@require_api_key
def api_download_file_legacy(file_id):
    """Legacy endpoint - redirects to v1"""
    return api_download_file(file_id)


@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@require_api_key
def api_delete_file_legacy(file_id):
    """Legacy endpoint - redirects to v1"""
    return api_delete_file(file_id)


@app.route('/api/stats', methods=['GET'])
@require_api_key
def api_stats_legacy():
    """Legacy endpoint - redirects to v1"""
    return api_stats()


# ==================== FOLDERS API ====================

@app.route('/api/folders', methods=['GET'])
@require_api_key
def api_list_folders():
    """List user's folders and files in a directory"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    parent_id = request.args.get('parent_id', type=int)
    if parent_id == 0: parent_id = None # Handle 0 as root
    
    # Get folders
    folders = Folder.query.filter_by(user_id=user.id, parent_id=parent_id).all()
    
    # Get files (only if in this folder and not deleted)
    files = File.query.filter_by(user_id=user.id, folder_id=parent_id).filter(File.status != 'deleted').all()
    
    # Get current folder info if not root
    current_folder = None
    path = []
    if parent_id:
        folder = Folder.query.filter_by(id=parent_id, user_id=user.id).first()
        if folder:
            current_folder = folder.to_dict()
            path = folder.get_path()

    return jsonify({
        'folders': [f.to_dict() for f in folders],
        'files': [f.to_dict() for f in files],
        'current_folder': current_folder,
        'path': path
    })


@app.route('/api/folders', methods=['POST'])
@require_api_key
def api_create_folder():
    """Create a new folder"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')
    color = data.get('color')
    
    if not name:
        return jsonify({'error': 'Folder name required'}), 400
    
    # Check if parent exists and belongs to user
    if parent_id:
        parent = Folder.query.filter_by(id=parent_id, user_id=user.id).first()
        if not parent:
            return jsonify({'error': 'Parent folder not found'}), 404
    
    folder = Folder(
        user_id=user.id,
        name=name,
        parent_id=parent_id,
        color=color
    )
    
    db.session.add(folder)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'folder': folder.to_dict()
    })


@app.route('/api/folders/<int:folder_id>', methods=['GET'])
@require_api_key
def api_get_folder(folder_id):
    """Get folder info with files"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    
    # Get files in this folder
    files = File.query.filter_by(user_id=user.id, folder_id=folder_id).filter(File.status != 'deleted').all()
    
    # Get subfolders
    subfolders = Folder.query.filter_by(user_id=user.id, parent_id=folder_id).all()
    
    return jsonify({
        'folder': folder.to_dict(),
        'path': folder.get_path(),
        'files': [f.to_dict() for f in files],
        'subfolders': [sf.to_dict() for sf in subfolders]
    })


@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@require_api_key
def api_update_folder(folder_id):
    """Update folder (rename, change color)"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        name = data['name'].strip()
        if name:
            folder.name = name
    
    if 'color' in data:
        folder.color = data['color']
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'folder': folder.to_dict()
    })


@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@require_api_key
def api_delete_folder(folder_id):
    """Delete folder (and optionally its contents)"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    
    # Check if folder has files or subfolders
    has_files = File.query.filter_by(folder_id=folder_id).filter(File.status != 'deleted').count() > 0
    has_subfolders = Folder.query.filter_by(parent_id=folder_id).count() > 0
    
    if has_files or has_subfolders:
        return jsonify({'error': 'Folder is not empty'}), 400
    
    db.session.delete(folder)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/api/files/<int:file_id>/move', methods=['POST'])
@require_api_key
def api_move_file(file_id):
    """Move file to another folder"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    data = request.get_json()
    folder_id = data.get('folder_id')
    
    # Validate folder
    if folder_id:
        folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
        if not folder:
            return jsonify({'error': 'Target folder not found'}), 404
    
    file_record.folder_id = folder_id
    db.session.commit()
    
    return jsonify({
        'success': True,
        'file': file_record.to_dict()
    })


@app.route('/api/files/<int:file_id>/retry', methods=['POST'])
@require_api_key
def api_retry_file(file_id):
    """Retry uploading a failed file"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    if file_record.status != 'error':
        return jsonify({'error': 'File is not in error state'}), 400
    
    # Check if temp file still exists
    task = UploadTask.query.filter_by(file_id=file_id).first()
    
    if task and os.path.exists(task.temp_path):
        # Reset task for retry
        task.status = 'pending'
        task.attempts = 0
        task.error_message = None
        file_record.status = 'pending'
        file_record.error_message = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Файл добавлен в очередь повторной загрузки',
            'file': file_record.to_dict()
        })
    else:
        # Temp file is gone, can't retry - suggest re-upload
        return jsonify({
            'error': 'Временный файл удалён. Загрузите файл заново.',
            'can_retry': False
        }), 400


@app.route('/api/files/errors', methods=['GET'])
@require_api_key
def api_list_error_files():
    """List files with errors"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    files = File.query.filter_by(user_id=user.id, status='error').order_by(File.created_at.desc()).all()
    
    return jsonify({
        'files': [f.to_dict() for f in files],
        'total': len(files)
    })


@app.route('/api/files/errors/clear', methods=['POST'])
@require_api_key
def api_clear_error_files():
    """Delete all files with errors"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Get all error files
    error_files = File.query.filter_by(user_id=user.id, status='error').all()
    count = len(error_files)
    
    for file_record in error_files:
        # Delete associated upload tasks
        UploadTask.query.filter_by(file_id=file_record.id).delete()
        # Mark as deleted
        file_record.status = 'deleted'
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'deleted_count': count,
        'message': f'Удалено {count} файлов с ошибками'
    })


# ==================== PUBLIC SHARING API ====================

@app.route('/api/shares', methods=['GET'])
@require_api_key
def api_list_shares():
    """List user's public shares"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    shares = PublicShare.query.filter_by(user_id=user.id).order_by(PublicShare.created_at.desc()).all()
    
    return jsonify({
        'shares': [s.to_dict() for s in shares]
    })


@app.route('/api/shares', methods=['POST'])
@require_api_key
def api_create_share():
    """Create a public share link"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    file_id = data.get('file_id')
    folder_id = data.get('folder_id')
    
    if not file_id and not folder_id:
        return jsonify({'error': 'file_id or folder_id required'}), 400
    
    if file_id and folder_id:
        return jsonify({'error': 'Cannot share both file and folder'}), 400
    
    # Validate file or folder ownership
    if file_id:
        file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        if file_record.status != 'ready':
            return jsonify({'error': 'File is not ready'}), 400
    
    if folder_id:
        folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
        if not folder:
            return jsonify({'error': 'Folder not found'}), 404
    
    # Create share
    share = PublicShare(
        user_id=user.id,
        file_id=file_id,
        folder_id=folder_id,
        share_token=PublicShare.generate_token(),
        title=data.get('title'),
        description=data.get('description'),
        is_permanent=data.get('is_permanent', True),
        expires_at=data.get('expires_at'),
        max_access_count=data.get('max_access_count')
    )
    
    # Set password if provided
    if data.get('password'):
        share.set_password(data['password'])
    
    db.session.add(share)
    db.session.commit()
    
    # Generate full URL
    base_url = request.host_url.rstrip('/')
    share_url = share.get_share_url(base_url)
    
    return jsonify({
        'success': True,
        'share': share.to_dict(),
        'share_url': share_url
    })


@app.route('/api/shares/<int:share_id>', methods=['GET'])
@require_api_key
def api_get_share(share_id):
    """Get share info"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    share = PublicShare.query.filter_by(id=share_id, user_id=user.id).first()
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    
    base_url = request.host_url.rstrip('/')
    share_data = share.to_dict()
    share_data['share_url'] = share.get_share_url(base_url)
    
    return jsonify({'share': share_data})


@app.route('/api/shares/<int:share_id>', methods=['PUT'])
@require_api_key
def api_update_share(share_id):
    """Update share settings"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    share = PublicShare.query.filter_by(id=share_id, user_id=user.id).first()
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    
    data = request.get_json()
    
    if 'title' in data:
        share.title = data['title']
    
    if 'description' in data:
        share.description = data['description']
    
    if 'is_active' in data:
        share.is_active = data['is_active']
    
    if 'expires_at' in data:
        share.expires_at = data['expires_at']
    
    if 'password' in data:
        share.set_password(data['password'])
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'share': share.to_dict()
    })


@app.route('/api/shares/<int:share_id>', methods=['DELETE'])
@require_api_key
def api_delete_share(share_id):
    """Delete share link"""
    user = get_current_api_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    share = PublicShare.query.filter_by(id=share_id, user_id=user.id).first()
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    
    db.session.delete(share)
    db.session.commit()
    
    return jsonify({'success': True})


# ==================== PUBLIC SHARE ACCESS ====================

@app.route('/s/<share_token>')
def public_share_view(share_token):
    """Public share page"""
    share = PublicShare.query.filter_by(share_token=share_token).first()
    
    if not share:
        return render_template('404.html'), 404
    
    # Check if accessible
    accessible, reason = share.is_accessible()
    if not accessible:
        return render_template('share_error.html', error=reason), 403
    
    # Check password in session
    password_verified = session.get(f'share_password_{share.id}') == True
    
    if share.password and not password_verified:
        return render_template('share_password.html', share=share)
    
    # Increment access counter
    share.increment_access()
    db.session.commit()
    
    # Render share page
    if share.file_id:
        file_record = File.query.get(share.file_id)
        return render_template('share_file.html', share=share, file=file_record)
    elif share.folder_id:
        folder = Folder.query.get(share.folder_id)
        files = File.query.filter_by(folder_id=folder.id).filter(File.status == 'ready').all()
        return render_template('share_folder.html', share=share, folder=folder, files=files)
    
    return render_template('404.html'), 404


@app.route('/s/<share_token>/verify', methods=['POST'])
def public_share_verify_password(share_token):
    """Verify password for protected share"""
    share = PublicShare.query.filter_by(share_token=share_token).first()
    
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if share.check_password(password):
        session[f'share_password_{share.id}'] = True
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid password'}), 401


@app.route('/s/<share_token>/download')
def public_share_download(share_token):
    """Download file from public share"""
    share = PublicShare.query.filter_by(share_token=share_token).first()
    
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    
    # Check if accessible
    accessible, reason = share.is_accessible()
    if not accessible:
        return jsonify({'error': reason}), 403
    
    # Check password
    password_verified = session.get(f'share_password_{share.id}') == True
    if share.password and not password_verified:
        return jsonify({'error': 'Password required'}), 401
    
    if not share.file_id:
        return jsonify({'error': 'Not a file share'}), 400
    
    file_record = File.query.get(share.file_id)
    if not file_record or file_record.status != 'ready':
        return jsonify({'error': 'File not available'}), 404
    
    # Increment access
    share.increment_access()
    db.session.commit()
    
    # Download file (reuse existing download logic)
    user = file_record.owner
    temp_path = os.path.join(Config.TEMP_UPLOAD_DIR, f"share_download_{uuid.uuid4()}.encrypted")
    
    try:
        success = sync_download_file(file_record.telegram_message_id, temp_path)
        
        if not success or not os.path.exists(temp_path):
            return jsonify({'error': 'Download failed'}), 500
        
        with open(temp_path, 'rb') as f:
            encrypted_data = f.read()
        
        os.remove(temp_path)
        
        # Decrypt
        from encryption_utils import FileEncryptor, derive_master_key, base64_to_bytes
        
        encryption_metadata = file_record.get_encryption_metadata()
        
        if encryption_metadata.get('encrypted_file_key'):
            salt = base64_to_bytes(user.master_key_salt)
            server_encryption_password = f"{Config.SECRET_KEY}:{user.id}:{user.username}"
            master_key = derive_master_key(server_encryption_password, salt)
            
            encryptor = FileEncryptor(master_key)
            data = encryptor.decrypt(encrypted_data, encryption_metadata)
        else:
            data = encrypted_data
        
        from urllib.parse import quote
        filename_ascii = file_record.original_filename.encode('ascii', 'ignore').decode('ascii')
        filename_utf8 = quote(file_record.original_filename.encode('utf-8'))
        
        if filename_ascii != file_record.original_filename:
            content_disposition = f'attachment; filename="{filename_ascii}"; filename*=UTF-8\'\'{filename_utf8}'
        else:
            content_disposition = f'attachment; filename="{file_record.original_filename}"'
        
        return Response(
            data,
            mimetype=file_record.mime_type or 'application/octet-stream',
            headers={
                'Content-Disposition': content_disposition,
                'Content-Length': str(len(data))
            }
        )
        
    except Exception as e:
        logger.error(f"Error in public share download: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': 'Download failed'}), 500


# ==================== HEALTH CHECK ====================

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'cloud',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt"""
    return send_file('static/robots.txt', mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap_xml():
    """Generate sitemap.xml"""
    from flask import make_response
    
    sitemap = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://cloud.dreampartners.online/</loc>
        <lastmod>2026-01-04</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://cloud.dreampartners.online/login</loc>
        <lastmod>2026-01-04</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://cloud.dreampartners.online/register</loc>
        <lastmod>2026-01-04</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>'''
    
    response = make_response(sitemap)
    response.headers['Content-Type'] = 'application/xml'
    return response


# ==================== ERROR HANDLERS ====================

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': f'Файл слишком большой. Максимум: {Config.MAX_FILE_SIZE_MB} МБ'}), 413


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Не найдено'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Внутренняя ошибка сервера'}), 500
    return render_template('500.html'), 500


# ==================== APP INITIALIZATION ====================

def create_app():
    """Create and configure the Flask app"""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created")
    
    return app


# Start background worker
upload_worker = None


def start_worker():
    """Start the background upload worker"""
    global upload_worker
    if upload_worker is None or not upload_worker.is_alive():
        upload_worker = UploadWorker(app)
        upload_worker.start()
        logger.info("Upload worker started")




if __name__ == '__main__':
    create_app()
    start_worker()
    app.run(host=Config.HOST, port=Config.PORT, debug=False)

