"""
Database Models for Dream Cloud
================================

This module defines the database schema for the encrypted cloud storage system.
All file contents are encrypted before being stored in Telegram.

Architecture:
- User: Authentication, master key derivation salt, Telegram credentials
- File: Metadata only (no actual file content), encryption parameters
- UploadTask: Queue for async file uploads to Telegram

Security:
- Passwords are hashed with bcrypt
- Master keys are derived from passwords using PBKDF2
- File keys are encrypted with master keys
- Original file content is NEVER stored on the server
"""
from datetime import datetime
import secrets
import hashlib
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt

db = SQLAlchemy()


def generate_api_key():
    """Generate a secure API key"""
    return f"dc_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


class User(db.Model, UserMixin):
    """
    User model for authentication and encryption.
    
    Each user has:
    - Their own master key (derived from password, salt stored here)
    - Their own Telegram credentials (optional, for personal storage)
    - API key for programmatic access
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # nullable for SSO users
    
    # SSO fields
    sso_id = db.Column(db.Integer, nullable=True)  # ID from dreamID SSO
    sso_phone = db.Column(db.String(20), nullable=True)
    
    # Admin flag
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    
    # ==================== ENCRYPTION ====================
    # Salt for deriving master key from password (PBKDF2)
    # Master key is NEVER stored - only derived when needed
    master_key_salt = db.Column(db.String(44), nullable=True)  # Base64 encoded 16 bytes
    
    # ==================== TELEGRAM CREDENTIALS ====================
    # Each user can configure their own Telegram account for storage
    # These are encrypted with the user's master key
    telegram_api_id = db.Column(db.String(255), nullable=True)  # Encrypted
    telegram_api_hash = db.Column(db.String(255), nullable=True)  # Encrypted
    telegram_phone = db.Column(db.String(255), nullable=True)  # Encrypted
    telegram_session = db.Column(db.Text, nullable=True)  # Encrypted session string
    telegram_chat_id = db.Column(db.String(255), nullable=True)  # Target chat/channel for storage
    telegram_configured = db.Column(db.Boolean, default=False)
    
    # ==================== TELEGRAM BOT INTEGRATION ====================
    # Telegram user ID for bot authentication (not encrypted - needed for lookup)
    telegram_user_id = db.Column(db.BigInteger, nullable=True, unique=True, index=True)
    telegram_linked_at = db.Column(db.DateTime, nullable=True)
    
    # ==================== API KEY ====================
    api_key_hash = db.Column(db.String(64), nullable=True, unique=True)  # SHA-256 hash
    api_key_created_at = db.Column(db.DateTime, nullable=True)
    api_key_last_used = db.Column(db.DateTime, nullable=True)
    
    # ==================== RATE LIMITING ====================
    api_requests_count = db.Column(db.Integer, default=0)
    api_requests_reset_at = db.Column(db.DateTime, nullable=True)
    
    # ==================== METADATA ====================
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Storage stats
    total_files = db.Column(db.Integer, default=0)
    total_size = db.Column(db.BigInteger, default=0)  # Original file sizes in bytes
    total_encrypted_size = db.Column(db.BigInteger, default=0)  # Encrypted sizes
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password: str):
        """Hash and set password, also initialize master key salt"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # Initialize master key salt for encryption
        if not self.master_key_salt:
            from encryption_utils import generate_salt, bytes_to_base64
            self.master_key_salt = bytes_to_base64(generate_salt())
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def get_master_key(self, password: str) -> bytes:
        """
        Derive master key from password.
        This key is used to encrypt/decrypt file keys.
        NEVER store this key - derive it each time needed.
        """
        if not self.master_key_salt:
            raise ValueError("Master key salt not initialized")
        from encryption_utils import derive_master_key, base64_to_bytes
        salt = base64_to_bytes(self.master_key_salt)
        return derive_master_key(password, salt)
    
    def get_encryptor(self, password: str):
        """Get a FileEncryptor instance for this user"""
        from encryption_utils import FileEncryptor
        master_key = self.get_master_key(password)
        return FileEncryptor(master_key)
    
    def generate_new_api_key(self) -> str:
        """Generate a new API key for this user. Returns the plain key (only shown once)."""
        plain_key = generate_api_key()
        self.api_key_hash = hash_api_key(plain_key)
        self.api_key_created_at = datetime.utcnow()
        return plain_key
    
    def verify_api_key(self, api_key: str) -> bool:
        """Verify if the provided API key matches"""
        if not self.api_key_hash or not api_key:
            return False
        return self.api_key_hash == hash_api_key(api_key)
    
    def revoke_api_key(self):
        """Revoke the current API key"""
        self.api_key_hash = None
        self.api_key_created_at = None
        self.api_key_last_used = None
    
    def get_file_ids_export(self) -> dict:
        """
        Export all file IDs and encryption metadata for recovery.
        
        IMPORTANT: This export contains encrypted file keys.
        To decrypt files, user needs:
        1. Their password (to derive master key)
        2. The encryption metadata from this export
        3. Access to the Telegram chat where files are stored
        """
        files_data = []
        for f in self.files.filter(File.status != 'deleted').all():
            files_data.append({
                'id': f.id,
                'original_filename': f.original_filename,
                'telegram_file_id': f.telegram_file_id,
                'telegram_access_hash': f.telegram_access_hash,
                'telegram_message_id': f.telegram_message_id,
                'file_size': f.file_size,
                'encrypted_size': f.encrypted_size,
                'file_hash': f.file_hash,
                # Encryption metadata (needed for decryption)
                'encrypted_file_key': f.encrypted_file_key,
                'file_nonce': f.file_nonce,
                'key_nonce': f.key_nonce,
                'encryption_version': f.encryption_version,
                'created_at': f.created_at.isoformat() if f.created_at else None
            })
        return {
            'export_version': 1,
            'user_id': self.id,
            'username': self.username,
            'master_key_salt': self.master_key_salt,
            'telegram_chat_id': self.telegram_chat_id,
            'total_files': len(files_data),
            'files': files_data,
            'exported_at': datetime.utcnow().isoformat(),
            'recovery_instructions': (
                'To recover files: '
                '1. Use your password to derive master key (with the salt above). '
                '2. For each file, decrypt the file_key using master key and key_nonce. '
                '3. Download encrypted file from Telegram using telegram_file_id. '
                '4. Decrypt file data using file_key and file_nonce.'
            )
        }
    
    def check_rate_limit(self, limit_per_hour: int = 1000) -> tuple:
        """Check if user is within rate limits. Returns (allowed, remaining, reset_time)"""
        now = datetime.utcnow()
        
        # Reset counter if hour has passed
        if not self.api_requests_reset_at or (now - self.api_requests_reset_at).total_seconds() > 3600:
            self.api_requests_count = 0
            self.api_requests_reset_at = now
        
        remaining = limit_per_hour - self.api_requests_count
        reset_time = self.api_requests_reset_at.timestamp() + 3600 if self.api_requests_reset_at else now.timestamp() + 3600
        
        if self.api_requests_count >= limit_per_hour:
            return False, 0, int(reset_time)
        
        self.api_requests_count += 1
        return True, remaining - 1, int(reset_time)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'total_files': self.total_files,
            'total_size': self.total_size,
            'total_size_readable': self._format_size(self.total_size),
            'telegram_configured': self.telegram_configured
        }
    
    def get_storage_used(self):
        """Get human-readable storage used"""
        return self._format_size(self.total_size)
    
    @staticmethod
    def _format_size(size_bytes):
        """Format bytes to human readable"""
        if size_bytes is None:
            size_bytes = 0
        for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} ПБ"


class Folder(db.Model):
    """
    Folder model for organizing files.
    Supports nested folders (parent_id).
    """
    __tablename__ = 'folders'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Folder info
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(db.String(7), nullable=True)  # Hex color for UI
    
    # Nested folders support
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = db.relationship('User', backref='folders')
    parent = db.relationship('Folder', remote_side=[id], backref='subfolders')
    files = db.relationship('File', backref='folder', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'color': self.color,
            'parent_id': self.parent_id,
            'file_count': self.files.count(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_path(self) -> list:
        """Get full path from root to this folder"""
        path = [{'id': self.id, 'name': self.name}]
        current = self.parent
        while current:
            path.insert(0, {'id': current.id, 'name': current.name})
            current = current.parent
        return path


class File(db.Model):
    """
    File metadata model.
    
    IMPORTANT: This table stores ONLY metadata, never actual file content.
    File content is encrypted and stored in Telegram.
    
    Encryption fields store the parameters needed to decrypt the file:
    - encrypted_file_key: The file's encryption key, encrypted with user's master key
    - file_nonce: Nonce used for encrypting file data
    - key_nonce: Nonce used for encrypting the file key
    """
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)  # NULL = root
    
    # ==================== FILE METADATA ====================
    # Original filename (for display only, not stored in Telegram)
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=False)  # Original size in bytes
    encrypted_size = db.Column(db.BigInteger, nullable=True)  # Encrypted size in bytes
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 of original data
    
    # File type categorization
    file_type = db.Column(db.String(20), default='file')  # image, video, audio, document, archive, file
    
    # ==================== TELEGRAM STORAGE ====================
    # File is stored in Telegram as encrypted binary with random name
    telegram_file_id = db.Column(db.String(255), nullable=True)
    telegram_access_hash = db.Column(db.String(255), nullable=True)
    telegram_message_id = db.Column(db.Integer, nullable=True)
    
    # ==================== ENCRYPTION PARAMETERS ====================
    # These are required to decrypt the file
    encrypted_file_key = db.Column(db.String(100), nullable=True)  # Base64, ~60 bytes
    file_nonce = db.Column(db.String(24), nullable=True)  # Base64, 12 bytes -> 16 chars
    key_nonce = db.Column(db.String(24), nullable=True)  # Base64, 12 bytes -> 16 chars
    encryption_version = db.Column(db.Integer, default=1)  # For future algorithm changes
    
    # ==================== STATUS ====================
    status = db.Column(db.String(20), default='pending')  # pending, encrypting, uploading, ready, error, deleted
    error_message = db.Column(db.Text, nullable=True)
    
    # ==================== TIMESTAMPS ====================
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_at = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        """Public file info (no encryption details)"""
        return {
            'id': self.id,
            'filename': self.original_filename,
            'original_filename': self.original_filename,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'size': self.file_size,
            'size_readable': self._format_size(self.file_size),
            'encrypted_size': self.encrypted_size,
            'status': self.status,
            'file_type': self.file_type,
            'encrypted': self.encrypted_file_key is not None,
            'telegram_message_id': self.telegram_message_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'error': self.error_message
        }
    
    def get_encryption_metadata(self) -> dict:
        """
        Get encryption metadata needed for decryption.
        This is sensitive data - only return to authenticated owner.
        """
        return {
            'encrypted_file_key': self.encrypted_file_key,
            'file_nonce': self.file_nonce,
            'key_nonce': self.key_nonce,
            'encryption_version': self.encryption_version,
            'file_hash': self.file_hash
        }
    
    def set_encryption_metadata(self, metadata: dict):
        """Set encryption metadata from FileEncryptor"""
        self.encrypted_file_key = metadata.get('encrypted_file_key')
        self.file_nonce = metadata.get('file_nonce')
        self.key_nonce = metadata.get('key_nonce')
        self.encryption_version = metadata.get('encryption_version', 1)
        self.file_hash = metadata.get('file_hash')
        self.encrypted_size = metadata.get('encrypted_size')
    
    @staticmethod
    def _format_size(size_bytes):
        """Format bytes to human readable"""
        if size_bytes is None:
            size_bytes = 0
        for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} ПБ"
    
    @staticmethod
    def detect_file_type(mime_type: str, filename: str) -> str:
        """Detect file category from mime type"""
        if not mime_type:
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            mime_map = {
                'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image', 'webp': 'image', 'svg': 'image',
                'mp4': 'video', 'avi': 'video', 'mov': 'video', 'mkv': 'video', 'webm': 'video',
                'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'ogg': 'audio', 'm4a': 'audio',
                'pdf': 'document', 'doc': 'document', 'docx': 'document', 'xls': 'document', 'xlsx': 'document', 'txt': 'document',
                'zip': 'archive', 'rar': 'archive', '7z': 'archive', 'tar': 'archive', 'gz': 'archive',
            }
            return mime_map.get(ext, 'file')
        
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif mime_type in ['application/pdf', 'application/msword', 
                           'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           'text/plain']:
            return 'document'
        elif mime_type in ['application/zip', 'application/x-rar-compressed', 
                           'application/x-7z-compressed', 'application/x-tar']:
            return 'archive'
        return 'file'


class PublicShare(db.Model):
    """
    Public share links for files and folders.
    Supports both permanent and one-time links.
    """
    __tablename__ = 'public_shares'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Share target (either file or folder)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    
    # Share info
    share_token = db.Column(db.String(64), unique=True, nullable=False, index=True)  # URL-safe token
    title = db.Column(db.String(255), nullable=True)  # Custom title
    description = db.Column(db.Text, nullable=True)  # Custom description
    
    # Share settings
    is_permanent = db.Column(db.Boolean, default=True)  # False = one-time link
    is_active = db.Column(db.Boolean, default=True)  # Can be disabled
    password = db.Column(db.String(255), nullable=True)  # Optional password protection (hashed)
    expires_at = db.Column(db.DateTime, nullable=True)  # Optional expiration
    
    # Access tracking
    access_count = db.Column(db.Integer, default=0)
    max_access_count = db.Column(db.Integer, nullable=True)  # Optional access limit
    last_accessed_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = db.relationship('User', backref='shares')
    file = db.relationship('File', backref='public_shares')
    folder = db.relationship('Folder', backref='public_shares')
    
    @staticmethod
    def generate_token() -> str:
        """Generate a unique share token"""
        return secrets.token_urlsafe(32)
    
    def set_password(self, password: str):
        """Hash and set password for protected share"""
        if password:
            self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            self.password = None
    
    def check_password(self, password: str) -> bool:
        """Verify password for protected share"""
        if not self.password:
            return True  # No password set
        if not password:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
    def is_accessible(self) -> tuple:
        """Check if share is accessible. Returns (accessible, reason)"""
        if not self.is_active:
            return False, 'Share has been disabled'
        
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False, 'Share has expired'
        
        if self.max_access_count and self.access_count >= self.max_access_count:
            return False, 'Access limit reached'
        
        if not self.is_permanent and self.access_count > 0:
            return False, 'One-time link already used'
        
        return True, None
    
    def increment_access(self):
        """Increment access counter and update last accessed time"""
        self.access_count += 1
        self.last_accessed_at = datetime.utcnow()
    
    def get_share_url(self, base_url: str) -> str:
        """Get full public share URL"""
        return f"{base_url}/s/{self.share_token}"
    
    def to_dict(self, include_token=True):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'is_permanent': self.is_permanent,
            'is_active': self.is_active,
            'has_password': self.password is not None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'access_count': self.access_count,
            'max_access_count': self.max_access_count,
            'last_accessed_at': self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'file_id': self.file_id,
            'folder_id': self.folder_id
        }
        
        if include_token:
            data['share_token'] = self.share_token
        
        return data


class UploadTask(db.Model):
    """Upload task queue"""
    __tablename__ = 'upload_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    
    # Task info
    temp_path = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    attempts = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=3)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Error tracking
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationship
    file = db.relationship('File', backref='upload_task')

