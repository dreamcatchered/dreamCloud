"""
Database migration script for adding folders and public shares
Run this once to update existing database
"""
from app import app, db
from models import Folder, PublicShare

with app.app_context():
    # Create new tables
    db.create_all()
    print("✓ Database tables created/updated successfully")
    print("✓ Folders table ready")
    print("✓ PublicShare table ready")
    print("\nMigration complete!")
