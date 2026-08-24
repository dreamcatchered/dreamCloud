import sqlite3
import os
from config import DB_PATH

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT,
            mime_type TEXT,
            size INTEGER,
            upload_type TEXT,
            tg_ref TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_file(file_id, filename, mime_type, size, upload_type, tg_ref):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO files (id, filename, mime_type, size, upload_type, tg_ref)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (file_id, filename, mime_type, size, upload_type, tg_ref))
    conn.commit()
    conn.close()

def get_file(file_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE id = ?', (file_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None
