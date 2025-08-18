"""Database Migration 001: Add Enhancement Fields for Intelligent Proxy Management

This migration adds the core enhancement fields required for:
- Multi-tiered scanning strategy
- Intelligent scheduling 
- Geographical optimization
- Risk categorization

Added fields:
- region: Geographical region (continent level)
- country: Country code (ISO 3166-1 alpha-2) 
- city: City name for granular filtering
- risk_category: ACTIVE, AT_RISK, INACTIVE, UNKNOWN
- scan_priority: Priority level for scheduling (1-10)
- next_scheduled_check: Intelligent scheduling timestamp
- check_frequency: Current check frequency in hours
- tier_level: Scanning tier (1-4)
"""

import logging
from datetime import datetime
from typing import Optional

try:
    from sqlalchemy import text, MetaData, Table, Column, String, Integer, DateTime, Enum as SQLEnum
    from sqlalchemy.exc import SQLAlchemyError
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
    HAS_MONGODB = True
except ImportError:
    HAS_MONGODB = False

logger = logging.getLogger(__name__)


class RiskCategory:
    """Risk category enumeration for database migration"""
    ACTIVE = "active"
    AT_RISK = "at_risk" 
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class Migration001:
    """Migration to add enhancement fields to proxy database"""
    
    def __init__(self, database_manager):
        self.db_manager = database_manager
        self.migration_id = "001_add_enhancement_fields"
        self.description = "Add fields for intelligent proxy management"
        
    def up(self) -> bool:
        """Apply the migration (add new fields)"""
        try:
            if self.db_manager.mongo_db:
                return self._up_mongodb()
            else:
                return self._up_sql()
        except Exception as e:
            logger.error(f"Migration {self.migration_id} failed: {e}")
            return False
    
    def down(self) -> bool:
        """Reverse the migration (remove added fields)"""
        try:
            if self.db_manager.mongo_db:
                return self._down_mongodb()
            else:
                return self._down_sql()
        except Exception as e:
            logger.error(f"Migration {self.migration_id} rollback failed: {e}")
            return False
    
    def _up_sql(self) -> bool:
        """Apply migration for SQL databases"""
        if not HAS_SQLALCHEMY:
            logger.error("SQLAlchemy required for SQL database migration")
            return False
            
        try:
            with self.db_manager.get_session() as session:
                # Check if migration already applied
                if self._is_applied_sql(session):
                    logger.info(f"Migration {self.migration_id} already applied")
                    return True
                
                # Add new columns to proxies table
                migration_sql = [
                    # Geographical fields
                    "ALTER TABLE proxies ADD COLUMN region VARCHAR(50)",
                    "ALTER TABLE proxies ADD COLUMN country VARCHAR(50)", 
                    "ALTER TABLE proxies ADD COLUMN city VARCHAR(100)",
                    
                    # Risk and tier management
                    f"ALTER TABLE proxies ADD COLUMN risk_category VARCHAR(20) DEFAULT '{RiskCategory.UNKNOWN}'",
                    "ALTER TABLE proxies ADD COLUMN scan_priority INTEGER DEFAULT 5",
                    "ALTER TABLE proxies ADD COLUMN tier_level INTEGER DEFAULT 4",
                    
                    # Scheduling fields
                    "ALTER TABLE proxies ADD COLUMN next_scheduled_check TIMESTAMP",
                    "ALTER TABLE proxies ADD COLUMN check_frequency INTEGER DEFAULT 24",
                ]
                
                # Execute migration SQL
                for sql in migration_sql:
                    try:
                        session.execute(text(sql))
                        logger.debug(f"Executed: {sql}")
                    except SQLAlchemyError as e:
                        # Handle cases where column might already exist
                        if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                            logger.warning(f"Column already exists, skipping: {sql}")
                        else:
                            raise
                
                # Create new indexes for performance
                index_sql = [
                    "CREATE INDEX IF NOT EXISTS idx_proxies_region ON proxies(region)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_country ON proxies(country)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_risk_category ON proxies(risk_category)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_tier_level ON proxies(tier_level)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_scan_priority ON proxies(scan_priority)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_next_scheduled ON proxies(next_scheduled_check)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_tier_priority ON proxies(tier_level, scan_priority)",
                    "CREATE INDEX IF NOT EXISTS idx_proxies_geo_risk ON proxies(country, risk_category)",
                ]
                
                for sql in index_sql:
                    try:
                        session.execute(text(sql))
                        logger.debug(f"Created index: {sql}")
                    except SQLAlchemyError as e:
                        if "already exists" in str(e).lower():
                            logger.warning(f"Index already exists: {sql}")
                        else:
                            logger.warning(f"Index creation failed: {sql} - {e}")
                
                # Record migration
                self._record_migration_sql(session)
                
                session.commit()
                logger.info(f"Migration {self.migration_id} applied successfully")
                return True
                
        except Exception as e:
            logger.error(f"SQL migration failed: {e}")
            return False
    
    def _up_mongodb(self) -> bool:
        """Apply migration for MongoDB"""
        if not HAS_MONGODB:
            logger.error("PyMongo required for MongoDB migration")
            return False
            
        try:
            # Check if migration already applied
            if self._is_applied_mongodb():
                logger.info(f"Migration {self.migration_id} already applied")
                return True
            
            collection = self.db_manager.mongo_db.proxies
            
            # Update existing documents with new fields (set defaults)
            update_result = collection.update_many(
                {},  # All documents
                {
                    "$set": {
                        "region": None,
                        "country": None, 
                        "city": None,
                        "risk_category": RiskCategory.UNKNOWN,
                        "scan_priority": 5,
                        "tier_level": 4,
                        "next_scheduled_check": None,
                        "check_frequency": 24
                    }
                },
                upsert=False
            )
            
            # Create indexes for performance
            indexes = [
                ("region", 1),
                ("country", 1),
                ("risk_category", 1),
                ("tier_level", 1),
                ("scan_priority", 1),
                ("next_scheduled_check", 1),
                ([("tier_level", 1), ("scan_priority", 1)], {}),  # Compound index
                ([("country", 1), ("risk_category", 1)], {}),     # Compound index
            ]
            
            for index in indexes:
                try:
                    if isinstance(index, tuple) and len(index) == 2:
                        # Compound index
                        collection.create_index(index[0], **index[1])
                    else:
                        # Simple index
                        collection.create_index([index])
                    logger.debug(f"Created MongoDB index: {index}")
                except Exception as e:
                    logger.warning(f"Index creation failed: {index} - {e}")
            
            # Record migration
            self._record_migration_mongodb()
            
            logger.info(f"Migration {self.migration_id} applied to {update_result.modified_count} documents")
            return True
            
        except Exception as e:
            logger.error(f"MongoDB migration failed: {e}")
            return False
    
    def _down_sql(self) -> bool:
        """Rollback migration for SQL databases"""
        try:
            with self.db_manager.get_session() as session:
                # Remove indexes first
                index_sql = [
                    "DROP INDEX IF EXISTS idx_proxies_region",
                    "DROP INDEX IF EXISTS idx_proxies_country", 
                    "DROP INDEX IF EXISTS idx_proxies_risk_category",
                    "DROP INDEX IF EXISTS idx_proxies_tier_level",
                    "DROP INDEX IF EXISTS idx_proxies_scan_priority",
                    "DROP INDEX IF EXISTS idx_proxies_next_scheduled",
                    "DROP INDEX IF EXISTS idx_proxies_tier_priority",
                    "DROP INDEX IF EXISTS idx_proxies_geo_risk",
                ]
                
                for sql in index_sql:
                    try:
                        session.execute(text(sql))
                    except SQLAlchemyError as e:
                        logger.warning(f"Index removal failed: {sql} - {e}")
                
                # Remove columns
                rollback_sql = [
                    "ALTER TABLE proxies DROP COLUMN region",
                    "ALTER TABLE proxies DROP COLUMN country",
                    "ALTER TABLE proxies DROP COLUMN city",
                    "ALTER TABLE proxies DROP COLUMN risk_category",
                    "ALTER TABLE proxies DROP COLUMN scan_priority",
                    "ALTER TABLE proxies DROP COLUMN tier_level",
                    "ALTER TABLE proxies DROP COLUMN next_scheduled_check",
                    "ALTER TABLE proxies DROP COLUMN check_frequency",
                ]
                
                for sql in rollback_sql:
                    try:
                        session.execute(text(sql))
                    except SQLAlchemyError as e:
                        logger.warning(f"Column removal failed: {sql} - {e}")
                
                # Remove migration record
                session.execute(
                    text("DELETE FROM migrations WHERE migration_id = :migration_id"),
                    {"migration_id": self.migration_id}
                )
                
                session.commit()
                logger.info(f"Migration {self.migration_id} rolled back successfully")
                return True
                
        except Exception as e:
            logger.error(f"SQL rollback failed: {e}")
            return False
    
    def _down_mongodb(self) -> bool:
        """Rollback migration for MongoDB"""
        try:
            collection = self.db_manager.mongo_db.proxies
            
            # Remove new fields from all documents
            update_result = collection.update_many(
                {},  # All documents
                {
                    "$unset": {
                        "region": "",
                        "country": "",
                        "city": "",
                        "risk_category": "",
                        "scan_priority": "",
                        "tier_level": "",
                        "next_scheduled_check": "",
                        "check_frequency": ""
                    }
                }
            )
            
            # Remove indexes (MongoDB will ignore if they don't exist)
            indexes_to_drop = [
                "region_1",
                "country_1", 
                "risk_category_1",
                "tier_level_1",
                "scan_priority_1",
                "next_scheduled_check_1"
            ]
            
            for index_name in indexes_to_drop:
                try:
                    collection.drop_index(index_name)
                except Exception as e:
                    logger.warning(f"Index drop failed: {index_name} - {e}")
            
            # Remove migration record
            migrations_collection = self.db_manager.mongo_db.migrations
            migrations_collection.delete_one({"migration_id": self.migration_id})
            
            logger.info(f"Migration {self.migration_id} rolled back from {update_result.modified_count} documents")
            return True
            
        except Exception as e:
            logger.error(f"MongoDB rollback failed: {e}")
            return False
    
    def _is_applied_sql(self, session) -> bool:
        """Check if migration is already applied in SQL database"""
        try:
            # Create migrations table if it doesn't exist
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS migrations (
                    id INTEGER PRIMARY KEY,
                    migration_id VARCHAR(255) UNIQUE NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            """))
            
            result = session.execute(
                text("SELECT COUNT(*) FROM migrations WHERE migration_id = :migration_id"),
                {"migration_id": self.migration_id}
            )
            return result.scalar() > 0
        except Exception:
            return False
    
    def _is_applied_mongodb(self) -> bool:
        """Check if migration is already applied in MongoDB"""
        try:
            migrations_collection = self.db_manager.mongo_db.migrations
            return migrations_collection.count_documents({"migration_id": self.migration_id}) > 0
        except Exception:
            return False
    
    def _record_migration_sql(self, session):
        """Record migration in SQL database"""
        session.execute(
            text("""
                INSERT INTO migrations (migration_id, applied_at, description)
                VALUES (:migration_id, :applied_at, :description)
            """),
            {
                "migration_id": self.migration_id,
                "applied_at": datetime.utcnow(),
                "description": self.description
            }
        )
    
    def _record_migration_mongodb(self):
        """Record migration in MongoDB"""
        migrations_collection = self.db_manager.mongo_db.migrations
        migrations_collection.insert_one({
            "migration_id": self.migration_id,
            "applied_at": datetime.utcnow(),
            "description": self.description
        })


def apply_migration(database_manager) -> bool:
    """Apply the enhancement fields migration"""
    migration = Migration001(database_manager)
    return migration.up()


def rollback_migration(database_manager) -> bool:
    """Rollback the enhancement fields migration"""
    migration = Migration001(database_manager)
    return migration.down()


if __name__ == "__main__":
    # Example usage for testing
    from ..database import create_sqlite_database
    
    # Create test database
    db_manager = create_sqlite_database("test_migration.db")
    
    # Apply migration
    if apply_migration(db_manager):
        print("Migration applied successfully")
    else:
        print("Migration failed")
    
    # Test rollback
    # if rollback_migration(db_manager):
    #     print("Migration rolled back successfully")
    # else:
    #     print("Rollback failed")