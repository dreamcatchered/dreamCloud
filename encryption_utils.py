"""
Encryption Module for Dream Cloud
==================================

This module implements end-to-end encryption for files stored in Telegram.
Files are encrypted BEFORE being sent to Telegram, making it impossible
for anyone (including server operators) to read file contents without the user's master key.

Encryption Scheme:
- Algorithm: AES-256-GCM (authenticated encryption)
- Each file has a unique file_key
- File keys are encrypted with user's master_key
- Master key is derived from user's password using PBKDF2
- IV/Nonce is unique per file and stored alongside encrypted data

Security Properties:
- Confidentiality: Files cannot be read without the key
- Integrity: Any tampering is detected via GCM authentication tag
- Forward secrecy: Compromising one file key doesn't compromise others
"""

import os
import base64
import hashlib
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Current encryption version - increment when changing scheme
ENCRYPTION_VERSION = 1

# Constants
KEY_SIZE = 32  # 256 bits for AES-256
NONCE_SIZE = 12  # 96 bits for GCM
SALT_SIZE = 16  # 128 bits for PBKDF2
TAG_SIZE = 16  # 128 bits GCM tag (included in ciphertext by AESGCM)
PBKDF2_ITERATIONS = 600000  # OWASP recommended minimum for PBKDF2-SHA256


class CryptoError(Exception):
    """Base exception for crypto operations"""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (wrong key or corrupted data)"""
    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails"""
    pass


def generate_file_key() -> bytes:
    """
    Generate a random 256-bit key for file encryption.
    Each file gets its own unique key.
    
    Returns:
        32 bytes of cryptographically secure random data
    """
    return secrets.token_bytes(KEY_SIZE)


def generate_nonce() -> bytes:
    """
    Generate a random 96-bit nonce for AES-GCM.
    Must be unique for each encryption operation with the same key.
    
    Returns:
        12 bytes of cryptographically secure random data
    """
    return secrets.token_bytes(NONCE_SIZE)


def generate_salt() -> bytes:
    """
    Generate a random salt for key derivation.
    
    Returns:
        16 bytes of cryptographically secure random data
    """
    return secrets.token_bytes(SALT_SIZE)


def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a master key from user's password using PBKDF2.
    
    Args:
        password: User's password
        salt: Random salt (must be stored for later derivation)
    
    Returns:
        32-byte derived key
    
    Raises:
        KeyDerivationError: If derivation fails
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    except Exception as e:
        raise KeyDerivationError(f"Failed to derive master key: {e}")


def encrypt_file_key(file_key: bytes, master_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt a file key with the user's master key.
    
    Args:
        file_key: The 32-byte file encryption key
        master_key: The user's 32-byte master key
    
    Returns:
        Tuple of (encrypted_file_key, nonce)
    """
    nonce = generate_nonce()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(master_key)
    encrypted_key = aesgcm.encrypt(nonce, file_key, None)
    return encrypted_key, nonce


def decrypt_file_key(encrypted_file_key: bytes, nonce: bytes, master_key: bytes) -> bytes:
    """
    Decrypt a file key using the user's master key.
    
    Args:
        encrypted_file_key: The encrypted file key
        nonce: The nonce used during encryption
        master_key: The user's 32-byte master key
    
    Returns:
        The decrypted 32-byte file key
    
    Raises:
        DecryptionError: If decryption fails (wrong key or corrupted data)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, encrypted_file_key, None)
    except Exception as e:
        raise DecryptionError(f"Failed to decrypt file key: {e}")


def encrypt_file(data: bytes, file_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt file data using AES-256-GCM.
    
    Args:
        data: Raw file data to encrypt
        file_key: 32-byte encryption key for this file
    
    Returns:
        Tuple of (encrypted_data, nonce)
        Note: encrypted_data includes the GCM authentication tag
    """
    nonce = generate_nonce()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(file_key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    return encrypted_data, nonce


def decrypt_file(encrypted_data: bytes, nonce: bytes, file_key: bytes) -> bytes:
    """
    Decrypt file data using AES-256-GCM.
    
    Args:
        encrypted_data: Encrypted file data (includes GCM tag)
        nonce: The nonce used during encryption
        file_key: 32-byte encryption key for this file
    
    Returns:
        Decrypted file data
    
    Raises:
        DecryptionError: If decryption fails (wrong key or corrupted/tampered data)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise DecryptionError(f"Failed to decrypt file: {e}")


def encrypt_file_streaming(input_path: str, output_path: str, file_key: bytes) -> bytes:
    """
    Encrypt a file from disk to disk (for large files).
    Note: For simplicity, this loads the entire file. For very large files,
    consider implementing chunked encryption.
    
    Args:
        input_path: Path to the plaintext file
        output_path: Path where encrypted file will be written
        file_key: 32-byte encryption key
    
    Returns:
        The nonce used for encryption
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    
    encrypted_data, nonce = encrypt_file(data, file_key)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return nonce


def decrypt_file_streaming(input_path: str, output_path: str, nonce: bytes, file_key: bytes) -> None:
    """
    Decrypt a file from disk to disk.
    
    Args:
        input_path: Path to the encrypted file
        output_path: Path where decrypted file will be written
        nonce: The nonce used during encryption
        file_key: 32-byte encryption key
    
    Raises:
        DecryptionError: If decryption fails
    """
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_file(encrypted_data, nonce, file_key)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)


# Encoding helpers for database storage
def bytes_to_base64(data: bytes) -> str:
    """Encode bytes to base64 string for database storage"""
    return base64.b64encode(data).decode('ascii')


def base64_to_bytes(data: str) -> bytes:
    """Decode base64 string from database to bytes"""
    return base64.b64decode(data.encode('ascii'))


def compute_file_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of file data.
    Used for deduplication and integrity verification.
    
    Args:
        data: File data
    
    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


class FileEncryptor:
    """
    High-level interface for file encryption operations.
    
    Usage:
        # Initialize with user's master key
        encryptor = FileEncryptor(master_key)
        
        # Encrypt a file
        encrypted_data, metadata = encryptor.encrypt(file_data)
        
        # Store metadata in database, send encrypted_data to Telegram
        
        # Later, decrypt the file
        decrypted_data = encryptor.decrypt(encrypted_data, metadata)
    """
    
    def __init__(self, master_key: bytes):
        """
        Initialize encryptor with user's master key.
        
        Args:
            master_key: 32-byte master key derived from user's password
        """
        if len(master_key) != KEY_SIZE:
            raise ValueError(f"Master key must be {KEY_SIZE} bytes")
        self.master_key = master_key
    
    def encrypt(self, data: bytes) -> Tuple[bytes, dict]:
        """
        Encrypt file data with a new unique key.
        
        Args:
            data: Raw file data
        
        Returns:
            Tuple of (encrypted_data, metadata)
            metadata contains: encrypted_file_key, file_nonce, key_nonce, version
        """
        # Generate unique key for this file
        file_key = generate_file_key()
        
        # Encrypt the file data
        encrypted_data, file_nonce = encrypt_file(data, file_key)
        
        # Encrypt the file key with master key
        encrypted_file_key, key_nonce = encrypt_file_key(file_key, self.master_key)
        
        metadata = {
            'encrypted_file_key': bytes_to_base64(encrypted_file_key),
            'file_nonce': bytes_to_base64(file_nonce),
            'key_nonce': bytes_to_base64(key_nonce),
            'encryption_version': ENCRYPTION_VERSION,
            'original_size': len(data),
            'encrypted_size': len(encrypted_data),
            'file_hash': compute_file_hash(data)
        }
        
        return encrypted_data, metadata
    
    def decrypt(self, encrypted_data: bytes, metadata: dict) -> bytes:
        """
        Decrypt file data using stored metadata.
        
        Args:
            encrypted_data: Encrypted file data from Telegram
            metadata: Encryption metadata from database
        
        Returns:
            Decrypted file data
        
        Raises:
            DecryptionError: If decryption fails
        """
        # Decode metadata
        encrypted_file_key = base64_to_bytes(metadata['encrypted_file_key'])
        file_nonce = base64_to_bytes(metadata['file_nonce'])
        key_nonce = base64_to_bytes(metadata['key_nonce'])
        
        # Decrypt the file key
        file_key = decrypt_file_key(encrypted_file_key, key_nonce, self.master_key)
        
        # Decrypt the file data
        decrypted_data = decrypt_file(encrypted_data, file_nonce, file_key)
        
        # Verify integrity if hash is available
        if 'file_hash' in metadata:
            actual_hash = compute_file_hash(decrypted_data)
            if actual_hash != metadata['file_hash']:
                raise DecryptionError("File hash mismatch - data may be corrupted")
        
        return decrypted_data
    
    @staticmethod
    def create_from_password(password: str, salt: Optional[bytes] = None) -> Tuple['FileEncryptor', bytes]:
        """
        Create a FileEncryptor from a password.
        
        Args:
            password: User's password
            salt: Optional salt (will be generated if not provided)
        
        Returns:
            Tuple of (FileEncryptor instance, salt)
            The salt must be stored for future key derivation
        """
        if salt is None:
            salt = generate_salt()
        
        master_key = derive_master_key(password, salt)
        return FileEncryptor(master_key), salt


# Export key functions and classes
__all__ = [
    'ENCRYPTION_VERSION',
    'CryptoError',
    'DecryptionError', 
    'KeyDerivationError',
    'generate_file_key',
    'generate_nonce',
    'generate_salt',
    'derive_master_key',
    'encrypt_file',
    'decrypt_file',
    'encrypt_file_key',
    'decrypt_file_key',
    'encrypt_file_streaming',
    'decrypt_file_streaming',
    'bytes_to_base64',
    'base64_to_bytes',
    'compute_file_hash',
    'FileEncryptor',
]
