"""Database Migration Manager

Handles running and managing database migrations for ProxC enhancements.
Provides safe migration execution with rollback capabilities.
"""

import logging
import importlib
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class MigrationManager:
    """Manages database migrations for ProxC"""
    
    def __init__(self, database_manager):
        self.db_manager = database_manager
        self.migrations_dir = Path(__file__).parent / "migrations"
        
    def get_available_migrations(self) -> List[str]:
        """Get list of available migration files"""
        migrations = []
        
        if not self.migrations_dir.exists():
            return migrations
            
        for file_path in self.migrations_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            
            migration_id = file_path.stem
            migrations.append(migration_id)
        
        return sorted(migrations)
    
    def get_applied_migrations(self) -> List[Dict[str, Any]]:
        """Get list of applied migrations from database"""
        try:
            if self.db_manager.mongo_db:
                return self._get_applied_migrations_mongodb()
            else:
                return self._get_applied_migrations_sql()
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    def _get_applied_migrations_sql(self) -> List[Dict[str, Any]]:
        """Get applied migrations from SQL database"""
        try:
            from sqlalchemy import text
            
            with self.db_manager.get_session() as session:
                # Ensure migrations table exists
                session.execute(text("""
                    CREATE TABLE IF NOT EXISTS migrations (
                        id INTEGER PRIMARY KEY,
                        migration_id VARCHAR(255) UNIQUE NOT NULL,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        description TEXT
                    )
                """))
                
                result = session.execute(text("""
                    SELECT migration_id, applied_at, description 
                    FROM migrations 
                    ORDER BY applied_at
                """))
                
                return [
                    {
                        "migration_id": row[0],
                        "applied_at": row[1],
                        "description": row[2] or ""
                    }
                    for row in result
                ]
        except Exception as e:
            logger.error(f"SQL get applied migrations failed: {e}")
            return []
    
    def _get_applied_migrations_mongodb(self) -> List[Dict[str, Any]]:
        """Get applied migrations from MongoDB"""
        try:
            migrations_collection = self.db_manager.mongo_db.migrations
            cursor = migrations_collection.find({}).sort("applied_at", 1)
            
            return [
                {
                    "migration_id": doc["migration_id"],
                    "applied_at": doc["applied_at"],
                    "description": doc.get("description", "")
                }
                for doc in cursor
            ]
        except Exception as e:
            logger.error(f"MongoDB get applied migrations failed: {e}")
            return []
    
    def get_pending_migrations(self) -> List[str]:
        """Get list of pending (not yet applied) migrations"""
        available = set(self.get_available_migrations())
        applied = set(migration["migration_id"] for migration in self.get_applied_migrations())
        
        pending = available - applied
        return sorted(list(pending))
    
    def apply_migration(self, migration_id: str) -> bool:
        """Apply a specific migration"""
        try:
            # Import the migration module
            module_name = f"proxc.database.migrations.{migration_id}"
            migration_module = importlib.import_module(module_name)
            
            # Check if migration has apply_migration function
            if not hasattr(migration_module, 'apply_migration'):
                logger.error(f"Migration {migration_id} missing apply_migration function")
                return False
            
            # Apply the migration
            logger.info(f"Applying migration: {migration_id}")
            success = migration_module.apply_migration(self.db_manager)
            
            if success:
                logger.info(f"Migration {migration_id} applied successfully")
            else:
                logger.error(f"Migration {migration_id} failed")
            
            return success
            
        except ImportError as e:
            logger.error(f"Could not import migration {migration_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Migration {migration_id} failed: {e}")
            return False
    
    def rollback_migration(self, migration_id: str) -> bool:
        """Rollback a specific migration"""
        try:
            # Import the migration module
            module_name = f"proxc.database.migrations.{migration_id}"
            migration_module = importlib.import_module(module_name)
            
            # Check if migration has rollback_migration function
            if not hasattr(migration_module, 'rollback_migration'):
                logger.error(f"Migration {migration_id} missing rollback_migration function")
                return False
            
            # Rollback the migration
            logger.info(f"Rolling back migration: {migration_id}")
            success = migration_module.rollback_migration(self.db_manager)
            
            if success:
                logger.info(f"Migration {migration_id} rolled back successfully")
            else:
                logger.error(f"Migration {migration_id} rollback failed")
            
            return success
            
        except ImportError as e:
            logger.error(f"Could not import migration {migration_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Migration {migration_id} rollback failed: {e}")
            return False
    
    def apply_all_pending(self) -> Dict[str, bool]:
        """Apply all pending migrations"""
        pending = self.get_pending_migrations()
        results = {}
        
        if not pending:
            logger.info("No pending migrations to apply")
            return results
        
        logger.info(f"Applying {len(pending)} pending migrations")
        
        for migration_id in pending:
            success = self.apply_migration(migration_id)
            results[migration_id] = success
            
            if not success:
                logger.error(f"Migration {migration_id} failed, stopping migration process")
                break
        
        successful = sum(1 for success in results.values() if success)
        logger.info(f"Applied {successful}/{len(pending)} migrations successfully")
        
        return results
    
    def migrate_to_latest(self) -> bool:
        """Migrate database to the latest version"""
        results = self.apply_all_pending()
        return all(results.values()) if results else True
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get comprehensive migration status"""
        available = self.get_available_migrations()
        applied = self.get_applied_migrations()
        pending = self.get_pending_migrations()
        
        return {
            "available_count": len(available),
            "applied_count": len(applied),
            "pending_count": len(pending),
            "available_migrations": available,
            "applied_migrations": applied,
            "pending_migrations": pending,
            "up_to_date": len(pending) == 0
        }
    
    def create_backup(self) -> Optional[str]:
        """Create database backup before migration (for SQL databases)"""
        try:
            if self.db_manager.mongo_db:
                logger.info("MongoDB backups should be handled externally")
                return None
            
            # For SQLite, we can copy the file
            db_url = self.db_manager.config.get('database_url', '')
            if db_url.startswith('sqlite:///'):
                db_file = db_url.replace('sqlite:///', '')
                if os.path.exists(db_file):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_file = f"{db_file}.backup_{timestamp}"
                    
                    import shutil
                    shutil.copy2(db_file, backup_file)
                    logger.info(f"Database backup created: {backup_file}")
                    return backup_file
            
            logger.info("Backup not implemented for this database type")
            return None
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return None
    
    def verify_database_integrity(self) -> bool:
        """Verify database integrity after migration"""
        try:
            # Basic connectivity test
            if self.db_manager.mongo_db:
                # MongoDB ping
                self.db_manager.mongo_client.admin.command('ping')
            else:
                # SQL query test
                with self.db_manager.get_session() as session:
                    from sqlalchemy import text
                    session.execute(text("SELECT 1"))
            
            logger.info("Database integrity verification passed")
            return True
            
        except Exception as e:
            logger.error(f"Database integrity verification failed: {e}")
            return False


def create_migration_manager(database_manager):
    """Factory function to create migration manager"""
    return MigrationManager(database_manager)


if __name__ == "__main__":
    # Example usage
    from ..database import create_sqlite_database
    
    # Create test database manager
    db_manager = create_sqlite_database("test_migrations.db")
    
    # Create migration manager
    migration_manager = MigrationManager(db_manager)
    
    # Show migration status
    status = migration_manager.get_migration_status()
    print(f"Migration Status: {status}")
    
    # Apply all pending migrations
    if status["pending_count"] > 0:
        print("Applying pending migrations...")
        results = migration_manager.apply_all_pending()
        print(f"Migration results: {results}")
    else:
        print("Database is up to date")