"""Proxy Core Database - Multi-Database Support with Simple Interface"""

import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Third-party imports with fallbacks
try:
    from sqlalchemy import (
        create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, 
        Enum as SQLEnum, MetaData, Table, Index
    )
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.pool import StaticPool, QueuePool
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
    HAS_MONGODB = True
except ImportError:
    HAS_MONGODB = False

from .models import ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus, ValidationStatus, SecurityLevel
from .config import ConfigManager


# ===============================================================================
# DATABASE TABLE DEFINITIONS
# ===============================================================================

if HAS_SQLALCHEMY:
    Base = declarative_base()
    
    class ProxyTable(Base):
        """SQLAlchemy table definition for proxies"""
        __tablename__ = 'proxies'
        
        # Primary key
        id = Column(Integer, primary_key=True, autoincrement=True)
        proxy_id = Column(String(50), unique=True, nullable=False, index=True)
        
        # Basic proxy info
        host = Column(String(255), nullable=False, index=True)
        port = Column(Integer, nullable=False)
        protocol = Column(SQLEnum(ProxyProtocol), nullable=False)
        
        # Authentication
        username = Column(String(255), nullable=True)
        password = Column(String(255), nullable=True)
        
        # Status and classification
        status = Column(SQLEnum(ProxyStatus), nullable=False, default=ProxyStatus.INACTIVE, index=True)
        anonymity_level = Column(SQLEnum(AnonymityLevel), nullable=False, default=AnonymityLevel.TRANSPARENT)
        threat_level = Column(SQLEnum(ThreatLevel), nullable=False, default=ThreatLevel.LOW, index=True)
        security_level = Column(SQLEnum(SecurityLevel), nullable=False, default=SecurityLevel.LOW)
        validation_status = Column(SQLEnum(ValidationStatus), nullable=False, default=ValidationStatus.PENDING)
        
        # Metadata
        source = Column(String(255), nullable=True, index=True)
        discovered_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
        last_updated = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Geographic data (JSON)
        geo_data = Column(Text, nullable=True)  # JSON string
        
        # Metrics (JSON)
        metrics_data = Column(Text, nullable=True)  # JSON string
        
        # Additional data
        tags = Column(Text, nullable=True)  # JSON array as string
        notes = Column(Text, nullable=True)
        
        # Indexes for performance
        __table_args__ = (
            Index('idx_host_port', 'host', 'port'),
            Index('idx_status_threat', 'status', 'threat_level'),
            Index('idx_discovered_source', 'discovered_at', 'source'),
        )


# ===============================================================================
# DATABASE MANAGERS
# ===============================================================================

class DatabaseManager:
    """Universal database manager supporting multiple database types"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.engine = None
        self.session_factory = None
        self.mongo_client = None
        self.mongo_db = None
        self._lock = threading.Lock()
        
        self.logger = logging.getLogger(__name__)
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database connection based on URL"""
        db_url = self.config.get('database_url', 'sqlite:///proxies.db')
        
        if db_url.startswith('mongodb://') or db_url.startswith('mongodb+srv://'):
            self._initialize_mongodb(db_url)
        else:
            self._initialize_sql_database(db_url)
    
    def _initialize_sql_database(self, db_url: str):
        """Initialize SQL database (SQLite, PostgreSQL, MySQL)"""
        if not HAS_SQLALCHEMY:
            raise RuntimeError("SQLAlchemy is required for SQL databases. Install with: pip install sqlalchemy")
        
        try:
            # Configure engine based on database type
            engine_kwargs = self._get_engine_config(db_url)
            
            self.engine = create_engine(db_url, **engine_kwargs)
            self.session_factory = sessionmaker(bind=self.engine)
            
            # Create tables
            Base.metadata.create_all(self.engine)
            
            # Log initialization success
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info(f"Initialized SQL database: {db_url.split('://')[0]}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize SQL database: {e}")
    
    def _initialize_mongodb(self, db_url: str):
        """Initialize MongoDB database"""
        if not HAS_MONGODB:
            raise RuntimeError("PyMongo is required for MongoDB. Install with: pip install pymongo")
        
        try:
            self.mongo_client = MongoClient(db_url)
            
            # Extract database name from URL or use default
            db_name = db_url.split('/')[-1] if '/' in db_url else 'proxc'
            self.mongo_db = self.mongo_client[db_name]
            
            # Test connection
            self.mongo_client.admin.command('ismaster')
            
            # Create indexes
            self._create_mongodb_indexes()
            
            # Log initialization success
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info(f"Initialized MongoDB database: {db_name}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize MongoDB: {e}")
    
    def _get_engine_config(self, db_url: str) -> Dict[str, Any]:
        """Get engine configuration based on database type"""
        config = {}
        
        # SQLite specific settings
        if db_url.startswith('sqlite:'):
            config.update({
                'poolclass': StaticPool,
                'connect_args': {'check_same_thread': False},
                'echo': False
            })
        
        # PostgreSQL specific settings
        elif db_url.startswith('postgresql:') or db_url.startswith('postgres:'):
            config.update({
                'poolclass': QueuePool,
                'pool_size': self.config.get('database_pool_size', 5),
                'max_overflow': 10,
                'pool_timeout': self.config.get('database_timeout', 30),
                'echo': False
            })
        
        # MySQL specific settings
        elif db_url.startswith('mysql:'):
            config.update({
                'poolclass': QueuePool,
                'pool_size': self.config.get('database_pool_size', 5),
                'max_overflow': 10,
                'pool_timeout': self.config.get('database_timeout', 30),
                'echo': False
            })
        
        return config
    
    def _create_mongodb_indexes(self):
        """Create MongoDB indexes for performance"""
        collection = self.mongo_db.proxies
        
        # Create indexes
        collection.create_index([("proxy_id", 1)], unique=True)
        collection.create_index([("host", 1), ("port", 1)])
        collection.create_index([("status", 1), ("threat_level", 1)])
        collection.create_index([("discovered_at", -1)])
        collection.create_index([("source", 1)])
    
    @contextmanager
    def get_session(self):
        """Get database session (for SQL databases)"""
        if not self.session_factory:
            raise RuntimeError("SQL database not initialized")
        
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def add_proxy(self, proxy: ProxyInfo) -> bool:
        """Add a single proxy to database (returns True if successful, False if failed)"""
        try:
            if self.mongo_db:
                return self._add_proxy_mongodb(proxy)
            else:
                return self._add_proxy_sql(proxy)
        except Exception as e:
            self.logger.error(f"Failed to add proxy {proxy.proxy_id}: {e}")
            return False
    
    def add_or_update_proxy(self, proxy: ProxyInfo) -> tuple[bool, str]:
        """Add or update proxy, returns (success, action) where action is 'added' or 'updated'"""
        try:
            if self.mongo_db:
                # MongoDB implementation would go here
                result = self._add_proxy_mongodb(proxy)
                return result, "added"  # Simplified for now
            else:
                return self._add_or_update_proxy_sql(proxy)
        except Exception as e:
            self.logger.error(f"Failed to add/update proxy {proxy.proxy_id}: {e}")
            return False, "error"
    
    def _add_proxy_sql(self, proxy: ProxyInfo) -> bool:
        """Add proxy to SQL database"""
        with self.get_session() as session:
            try:
                # Check if proxy already exists
                existing = session.query(ProxyTable).filter_by(
                    host=proxy.host, port=proxy.port
                ).first()
                
                if existing:
                    self.logger.debug(f"Proxy {proxy.address} already exists, updating...")
                    self._update_proxy_sql(session, existing, proxy)
                else:
                    # Create new proxy record
                    proxy_record = ProxyTable(
                        proxy_id=proxy.proxy_id,
                        host=proxy.host,
                        port=proxy.port,
                        protocol=proxy.protocol,
                        username=proxy.username,
                        password=proxy.password,
                        status=proxy.status,
                        anonymity_level=proxy.anonymity_level,
                        threat_level=proxy.threat_level,
                        security_level=proxy.security_level,
                        validation_status=proxy.validation_status,
                        source=proxy.source,
                        discovered_at=proxy.discovered_at,
                        geo_data=json.dumps(proxy.geo_location.to_dict() if proxy.geo_location else None),
                        metrics_data=json.dumps(proxy.metrics.to_dict() if proxy.metrics else None),
                        tags=json.dumps(proxy.tags),
                        notes=proxy.notes
                    )
                    
                    session.add(proxy_record)
                
                return True
                
            except IntegrityError:
                session.rollback()
                self.logger.warning(f"Duplicate proxy detected: {proxy.address}")
                return False
    
    def _add_or_update_proxy_sql(self, proxy: ProxyInfo) -> tuple[bool, str]:
        """Add or update proxy in SQL database, returns (success, action)"""
        with self.get_session() as session:
            try:
                # Check if proxy already exists
                existing = session.query(ProxyTable).filter_by(
                    host=proxy.host, port=proxy.port
                ).first()
                
                if existing:
                    self.logger.debug(f"Proxy {proxy.address} already exists, updating...")
                    self._update_proxy_sql(session, existing, proxy)
                    return True, "updated"
                else:
                    # Create new proxy record
                    proxy_record = ProxyTable(
                        proxy_id=proxy.proxy_id,
                        host=proxy.host,
                        port=proxy.port,
                        protocol=proxy.protocol,
                        username=proxy.username,
                        password=proxy.password,
                        status=proxy.status,
                        anonymity_level=proxy.anonymity_level,
                        threat_level=proxy.threat_level,
                        security_level=proxy.security_level,
                        validation_status=proxy.validation_status,
                        source=proxy.source,
                        discovered_at=proxy.discovered_at,
                        geo_data=json.dumps(proxy.geo_location.to_dict() if proxy.geo_location else None),
                        metrics_data=json.dumps(proxy.metrics.to_dict() if proxy.metrics else None),
                        tags=json.dumps(proxy.tags),
                        notes=proxy.notes
                    )
                    
                    session.add(proxy_record)
                    return True, "added"
                
            except IntegrityError:
                session.rollback()
                self.logger.warning(f"Duplicate proxy detected: {proxy.address}")
                return False, "error"
            except Exception as e:
                session.rollback()
                self.logger.error(f"Database error for {proxy.address}: {e}")
                return False, "error"
    
    def _update_proxy_sql(self, session: Session, existing: 'ProxyTable', proxy: ProxyInfo) -> None:
        """Update existing proxy record in SQL database"""
        try:
            # Update fields
            existing.protocol = proxy.protocol
            existing.username = proxy.username
            existing.password = proxy.password
            existing.status = proxy.status
            existing.anonymity_level = proxy.anonymity_level
            existing.threat_level = proxy.threat_level
            existing.security_level = proxy.security_level
            existing.validation_status = proxy.validation_status
            existing.source = proxy.source
            existing.last_updated = datetime.utcnow()
            existing.geo_data = json.dumps(proxy.geo_location.to_dict() if proxy.geo_location else None)
            existing.metrics_data = json.dumps(proxy.metrics.to_dict() if proxy.metrics else None)
            existing.tags = json.dumps(proxy.tags)
            existing.notes = proxy.notes
            
            # Session will be committed by the context manager
            self.logger.debug(f"Updated proxy {proxy.address}")
            
        except Exception as e:
            self.logger.error(f"Failed to update proxy {proxy.address}: {e}")
            raise
    
    def _add_proxy_mongodb(self, proxy: ProxyInfo) -> bool:
        """Add proxy to MongoDB"""
        try:
            collection = self.mongo_db.proxies
            
            # Prepare document
            doc = {
                'proxy_id': proxy.proxy_id,
                'host': proxy.host,
                'port': proxy.port,
                'protocol': proxy.protocol.value,
                'username': proxy.username,
                'password': proxy.password,
                'status': proxy.status.value,
                'anonymity_level': proxy.anonymity_level.value,
                'threat_level': proxy.threat_level.value,
                'security_level': proxy.security_level.value,
                'validation_status': proxy.validation_status.value,
                'source': proxy.source,
                'discovered_at': proxy.discovered_at,
                'last_updated': datetime.utcnow(),
                'geo_data': proxy.geo_location.__dict__ if proxy.geo_location else None,
                'metrics_data': proxy.metrics.__dict__ if proxy.metrics else None,
                'tags': proxy.tags,
                'notes': proxy.notes
            }
            
            # Upsert (update if exists, insert if not)
            collection.replace_one(
                {'host': proxy.host, 'port': proxy.port},
                doc,
                upsert=True
            )
            
            return True
            
        except PyMongoError as e:
            self.logger.error(f"MongoDB error adding proxy: {e}")
            return False
    
    def add_proxies(self, proxies: List[ProxyInfo]) -> Dict[str, int]:
        """Add multiple proxies to database"""
        stats = {'added': 0, 'updated': 0, 'failed': 0}
        
        for proxy in proxies:
            if self.add_proxy(proxy):
                stats['added'] += 1
            else:
                stats['failed'] += 1
        
        return stats
    
    def get_proxy(self, proxy_id: str) -> Optional[ProxyInfo]:
        """Get proxy by ID"""
        try:
            if self.mongo_db:
                return self._get_proxy_mongodb(proxy_id)
            else:
                return self._get_proxy_sql(proxy_id)
        except Exception as e:
            self.logger.error(f"Failed to get proxy {proxy_id}: {e}")
            return None
    
    def _get_proxy_sql(self, proxy_id: str) -> Optional[ProxyInfo]:
        """Get proxy from SQL database"""
        with self.get_session() as session:
            record = session.query(ProxyTable).filter_by(proxy_id=proxy_id).first()
            if record:
                return self._record_to_proxy(record)
            return None
    
    def _get_proxy_mongodb(self, proxy_id: str) -> Optional[ProxyInfo]:
        """Get proxy from MongoDB"""
        collection = self.mongo_db.proxies
        doc = collection.find_one({'proxy_id': proxy_id})
        if doc:
            return self._doc_to_proxy(doc)
        return None
    
    def get_proxies(self, limit: Optional[int] = None, status: Optional[ProxyStatus] = None,
                   threat_level: Optional[ThreatLevel] = None) -> List[ProxyInfo]:
        """Get proxies with optional filtering"""
        try:
            if self.mongo_db:
                return self._get_proxies_mongodb(limit, status, threat_level)
            else:
                return self._get_proxies_sql(limit, status, threat_level)
        except Exception as e:
            self.logger.error(f"Failed to get proxies: {e}")
            return []
    
    def _get_proxies_sql(self, limit: Optional[int] = None, 
                        status: Optional[ProxyStatus] = None,
                        threat_level: Optional[ThreatLevel] = None) -> List[ProxyInfo]:
        """Get proxies from SQL database"""
        with self.get_session() as session:
            query = session.query(ProxyTable)
            
            if status:
                query = query.filter(ProxyTable.status == status)
            if threat_level:
                query = query.filter(ProxyTable.threat_level == threat_level)
            
            query = query.order_by(ProxyTable.discovered_at.desc())
            
            if limit:
                query = query.limit(limit)
            
            records = query.all()
            return [self._record_to_proxy(record) for record in records]
    
    def _get_proxies_mongodb(self, limit: Optional[int] = None,
                           status: Optional[ProxyStatus] = None,
                           threat_level: Optional[ThreatLevel] = None) -> List[ProxyInfo]:
        """Get proxies from MongoDB"""
        collection = self.mongo_db.proxies
        
        # Build query
        query = {}
        if status:
            query['status'] = status.value
        if threat_level:
            query['threat_level'] = threat_level.value
        
        # Execute query
        cursor = collection.find(query).sort('discovered_at', -1)
        if limit:
            cursor = cursor.limit(limit)
        
        return [self._doc_to_proxy(doc) for doc in cursor]
    
    def update_proxy(self, proxy: ProxyInfo) -> bool:
        """Update existing proxy"""
        try:
            if self.mongo_db:
                return self._update_proxy_mongodb(proxy)
            else:
                return self._update_proxy_sql_direct(proxy)
        except Exception as e:
            self.logger.error(f"Failed to update proxy {proxy.proxy_id}: {e}")
            return False
    
    def _update_proxy_sql_direct(self, proxy: ProxyInfo) -> bool:
        """Update proxy directly in SQL database"""
        try:
            with self.get_session() as session:
                existing = session.query(ProxyTable).filter_by(
                    host=proxy.host, port=proxy.port
                ).first()
                
                if existing:
                    # Update the existing record
                    self._update_proxy_sql(session, existing, proxy)
                    return True
                else:
                    self.logger.warning(f"Proxy {proxy.address} not found for update")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to update proxy {proxy.proxy_id}: {e}")
            return False
    
    def delete_proxy(self, proxy_id: str) -> bool:
        """Delete proxy by ID"""
        try:
            if self.mongo_db:
                result = self.mongo_db.proxies.delete_one({'proxy_id': proxy_id})
                return result.deleted_count > 0
            else:
                with self.get_session() as session:
                    result = session.query(ProxyTable).filter_by(proxy_id=proxy_id).delete()
                    return result > 0
        except Exception as e:
            self.logger.error(f"Failed to delete proxy {proxy_id}: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            if self.mongo_db:
                return self._get_statistics_mongodb()
            else:
                return self._get_statistics_sql()
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _get_statistics_sql(self) -> Dict[str, Any]:
        """Get statistics from SQL database"""
        with self.get_session() as session:
            total = session.query(ProxyTable).count()
            active = session.query(ProxyTable).filter(ProxyTable.status == ProxyStatus.ACTIVE).count()
            valid = session.query(ProxyTable).filter(ProxyTable.validation_status == ValidationStatus.VALID).count()
            
            return {
                'total_proxies': total,
                'active_proxies': active,
                'valid_proxies': valid,
                'success_rate': (valid / total * 100) if total > 0 else 0
            }
    
    def _get_statistics_mongodb(self) -> Dict[str, Any]:
        """Get statistics from MongoDB"""
        collection = self.mongo_db.proxies
        
        total = collection.count_documents({})
        active = collection.count_documents({'status': ProxyStatus.ACTIVE.value})
        valid = collection.count_documents({'validation_status': ValidationStatus.VALID.value})
        
        return {
            'total_proxies': total,
            'active_proxies': active,
            'valid_proxies': valid,
            'success_rate': (valid / total * 100) if total > 0 else 0
        }
    
    def _record_to_proxy(self, record) -> ProxyInfo:
        """Convert SQL record to ProxyInfo"""
        from .models import GeoLocation, ProxyMetrics
        
        # Parse JSON data
        geo_data = json.loads(record.geo_data) if record.geo_data else None
        metrics_data = json.loads(record.metrics_data) if record.metrics_data else None
        tags = json.loads(record.tags) if record.tags else []
        
        # Create objects
        geo_location = GeoLocation(**geo_data) if geo_data else None
        
        # Handle metrics data migration (total_checks -> check_count)
        if metrics_data:
            # Fix legacy field name if present
            if 'total_checks' in metrics_data and 'check_count' not in metrics_data:
                metrics_data['check_count'] = metrics_data.pop('total_checks')
            # Remove any unknown fields to avoid TypeError
            metrics_data = {k: v for k, v in metrics_data.items() 
                          if k in ['response_time', 'uptime_percentage', 'success_rate', 
                                  'last_checked', 'check_count', 'failure_count', 
                                  'total_bytes_transferred', 'average_speed', 'peak_speed', 
                                  'downtime_incidents']}
            metrics = ProxyMetrics(**metrics_data)
        else:
            metrics = ProxyMetrics()
        
        return ProxyInfo(
            host=record.host,
            port=record.port,
            protocol=record.protocol,
            username=record.username,
            password=record.password,
            status=record.status,
            anonymity_level=record.anonymity_level,
            threat_level=record.threat_level,
            security_level=record.security_level,
            validation_status=record.validation_status,
            proxy_id=record.proxy_id,
            source=record.source,
            discovered_at=record.discovered_at,
            geo_location=geo_location,
            metrics=metrics,
            tags=tags,
            notes=record.notes or ""
        )
    
    def _doc_to_proxy(self, doc: Dict) -> ProxyInfo:
        """Convert MongoDB document to ProxyInfo"""
        from .models import GeoLocation, ProxyMetrics
        
        # Create objects
        geo_location = GeoLocation(**doc['geo_data']) if doc.get('geo_data') else None
        
        # Handle metrics data migration (total_checks -> check_count)
        metrics_data = doc.get('metrics_data', {})
        if metrics_data:
            # Fix legacy field name if present
            if 'total_checks' in metrics_data and 'check_count' not in metrics_data:
                metrics_data['check_count'] = metrics_data.pop('total_checks')
            # Remove any unknown fields to avoid TypeError
            metrics_data = {k: v for k, v in metrics_data.items() 
                          if k in ['response_time', 'uptime_percentage', 'success_rate', 
                                  'last_checked', 'check_count', 'failure_count', 
                                  'total_bytes_transferred', 'average_speed', 'peak_speed', 
                                  'downtime_incidents']}
            metrics = ProxyMetrics(**metrics_data)
        else:
            metrics = ProxyMetrics()
        
        return ProxyInfo(
            host=doc['host'],
            port=doc['port'],
            protocol=ProxyProtocol(doc['protocol']),
            username=doc.get('username'),
            password=doc.get('password'),
            status=ProxyStatus(doc['status']),
            anonymity_level=AnonymityLevel(doc['anonymity_level']),
            threat_level=ThreatLevel(doc['threat_level']),
            security_level=SecurityLevel(doc['security_level']),
            validation_status=ValidationStatus(doc['validation_status']),
            proxy_id=doc['proxy_id'],
            source=doc.get('source'),
            discovered_at=doc['discovered_at'],
            geo_location=geo_location,
            metrics=metrics,
            tags=doc.get('tags', []),
            notes=doc.get('notes', "")
        )
    
    def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()
        if self.mongo_client:
            self.mongo_client.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        self.close()
        return False


# ===============================================================================
# DATABASE FACTORY FUNCTIONS
# ===============================================================================

def create_database_manager(database_url: Optional[str] = None, 
                          config: Optional[ConfigManager] = None) -> DatabaseManager:
    """Create database manager with automatic configuration"""
    if config is None:
        config = ConfigManager()
    
    if database_url:
        config.set('database_url', database_url)
    
    return DatabaseManager(config)


def create_sqlite_database(db_path: str = "proxies.db") -> DatabaseManager:
    """Create SQLite database manager"""
    return create_database_manager(f"sqlite:///{db_path}")


def create_postgresql_database(host: str, database: str, username: str, password: str, 
                             port: int = 5432) -> DatabaseManager:
    """Create PostgreSQL database manager"""
    url = f"postgresql://{username}:{password}@{host}:{port}/{database}"
    return create_database_manager(url)


def create_mysql_database(host: str, database: str, username: str, password: str,
                         port: int = 3306) -> DatabaseManager:
    """Create MySQL database manager"""
    url = f"mysql://{username}:{password}@{host}:{port}/{database}"
    return create_database_manager(url)


def create_mongodb_database(host: str, database: str, username: Optional[str] = None,
                          password: Optional[str] = None, port: int = 27017) -> DatabaseManager:
    """Create MongoDB database manager"""
    if username and password:
        url = f"mongodb://{username}:{password}@{host}:{port}/{database}"
    else:
        url = f"mongodb://{host}:{port}/{database}"
    return create_database_manager(url)


# ===============================================================================
# EXTENDED DATABASE OPERATIONS (New Functions)
# ===============================================================================

class DatabaseManagerExtended(DatabaseManager):
    """Extended database manager with additional CLI-focused operations"""
    
    def exists(self, host: str, port: int) -> bool:
        """Check if proxy exists in database by host:port"""
        try:
            if self.mongo_db:
                return self._exists_mongodb(host, port)
            else:
                return self._exists_sql(host, port)
        except Exception as e:
            self.logger.error(f"Failed to check existence for {host}:{port}: {e}")
            return False
    
    def _exists_sql(self, host: str, port: int) -> bool:
        """Check if proxy exists in SQL database"""
        with self.get_session() as session:
            count = session.query(ProxyTable).filter_by(host=host, port=port).count()
            return count > 0
    
    def _exists_mongodb(self, host: str, port: int) -> bool:
        """Check if proxy exists in MongoDB"""
        collection = self.mongo_db.proxies
        count = collection.count_documents({'host': host, 'port': port})
        return count > 0
    
    def get_filtered_proxies(self, filters: Dict[str, Any]) -> List[ProxyInfo]:
        """Get proxies with advanced filtering"""
        try:
            if self.mongo_db:
                return self._get_filtered_proxies_mongodb(filters)
            else:
                return self._get_filtered_proxies_sql(filters)
        except Exception as e:
            self.logger.error(f"Failed to get filtered proxies: {e}")
            return []
    
    def _get_filtered_proxies_sql(self, filters: Dict[str, Any]) -> List[ProxyInfo]:
        """Get filtered proxies from SQL database"""
        with self.get_session() as session:
            query = session.query(ProxyTable)
            
            # Apply filters
            if 'status' in filters:
                query = query.filter(ProxyTable.status == ProxyStatus(filters['status']))
            
            if 'threat_level' in filters:
                query = query.filter(ProxyTable.threat_level == ThreatLevel(filters['threat_level']))
            
            if 'anonymity_level' in filters:
                query = query.filter(ProxyTable.anonymity_level == AnonymityLevel(filters['anonymity_level']))
            
            if 'protocol' in filters:
                query = query.filter(ProxyTable.protocol == ProxyProtocol(filters['protocol']))
            
            if 'source' in filters:
                query = query.filter(ProxyTable.source.ilike(f"%{filters['source']}%"))
            
            if 'country' in filters:
                # Filter by country code in geo_data JSON
                query = query.filter(ProxyTable.geo_data.like(f'%"country_code":"{filters["country"]}"%'))
            
            if 'discovered_after' in filters:
                query = query.filter(ProxyTable.discovered_at >= filters['discovered_after'])
            
            if 'discovered_before' in filters:
                query = query.filter(ProxyTable.discovered_at <= filters['discovered_before'])
            
            # Apply limit
            if 'limit' in filters:
                query = query.limit(filters['limit'])
            
            # Order by discovery date (newest first)
            query = query.order_by(ProxyTable.discovered_at.desc())
            
            records = query.all()
            return [self._record_to_proxy(record) for record in records]
    
    def _get_filtered_proxies_mongodb(self, filters: Dict[str, Any]) -> List[ProxyInfo]:
        """Get filtered proxies from MongoDB"""
        collection = self.mongo_db.proxies
        
        # Build query
        query = {}
        
        if 'status' in filters:
            query['status'] = filters['status']
        
        if 'threat_level' in filters:
            query['threat_level'] = filters['threat_level']
        
        if 'anonymity_level' in filters:
            query['anonymity_level'] = filters['anonymity_level']
        
        if 'protocol' in filters:
            query['protocol'] = filters['protocol']
        
        if 'source' in filters:
            query['source'] = {'$regex': filters['source'], '$options': 'i'}
        
        if 'country' in filters:
            query['geo_data.country_code'] = filters['country']
        
        if 'discovered_after' in filters:
            query['discovered_at'] = {'$gte': filters['discovered_after']}
        
        if 'discovered_before' in filters:
            if 'discovered_at' in query:
                query['discovered_at'].update({'$lte': filters['discovered_before']})
            else:
                query['discovered_at'] = {'$lte': filters['discovered_before']}
        
        # Execute query
        cursor = collection.find(query).sort('discovered_at', -1)
        
        if 'limit' in filters:
            cursor = cursor.limit(filters['limit'])
        
        return [self._doc_to_proxy(doc) for doc in cursor]
    
    def load_from_file(self, file_path: str, file_format: Optional[str] = None) -> Dict[str, int]:
        """Load proxies from file into database"""
        stats = {'added': 0, 'updated': 0, 'failed': 0, 'duplicates': 0}
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Auto-detect format if not specified
        if not file_format:
            file_format = self._detect_file_format(file_path)
        
        try:
            proxies = self._parse_file(file_path, file_format)
            
            for proxy in proxies:
                try:
                    if self.exists(proxy.host, proxy.port):
                        success, action = self.add_or_update_proxy(proxy)
                        if success:
                            if action == "updated":
                                stats['updated'] += 1
                            else:
                                stats['duplicates'] += 1
                        else:
                            stats['failed'] += 1
                    else:
                        if self.add_proxy(proxy):
                            stats['added'] += 1
                        else:
                            stats['failed'] += 1
                            
                except Exception as e:
                    self.logger.error(f"Failed to process proxy {proxy.address}: {e}")
                    stats['failed'] += 1
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to load file {file_path}: {e}")
            raise
    
    def export_to_file(self, file_path: str, filters: Optional[Dict[str, Any]] = None,
                      file_format: Optional[str] = None) -> int:
        """Export proxies to file with optional filtering"""
        
        # Get proxies (filtered or all)
        if filters:
            proxies = self.get_filtered_proxies(filters)
        else:
            proxies = self.get_proxies()
        
        if not proxies:
            return 0
        
        # Auto-detect format if not specified
        if not file_format:
            file_format = self._detect_file_format(file_path)
        
        try:
            self._write_file(proxies, file_path, file_format)
            return len(proxies)
            
        except Exception as e:
            self.logger.error(f"Failed to export to {file_path}: {e}")
            raise
    
    def save_validation_result(self, proxy_id: str, url: str, method: str, 
                              response_time: Optional[float], success: bool, 
                              error_message: Optional[str] = None) -> bool:
        """Save validation result for a proxy"""
        try:
            # Update proxy metrics and status based on validation
            proxy = self.get_proxy(proxy_id)
            if not proxy:
                self.logger.warning(f"Proxy {proxy_id} not found for validation update")
                return False
            
            # Update metrics
            if proxy.metrics:
                proxy.metrics.last_checked = datetime.utcnow()
                proxy.metrics.check_count = (proxy.metrics.check_count or 0) + 1
                
                if success:
                    if response_time:
                        proxy.metrics.response_time = response_time
                    current_success_rate = proxy.metrics.success_rate or 0
                    proxy.metrics.success_rate = (
                        (current_success_rate * (proxy.metrics.check_count - 1) + 1) / 
                        proxy.metrics.check_count
                    )
                else:
                    proxy.metrics.failure_count = (proxy.metrics.failure_count or 0) + 1
                    current_success_rate = proxy.metrics.success_rate or 0
                    proxy.metrics.success_rate = (
                        (current_success_rate * (proxy.metrics.check_count - 1)) / 
                        proxy.metrics.check_count
                    )
            
            # Update status based on validation result
            if success:
                proxy.status = ProxyStatus.ACTIVE
                proxy.validation_status = ValidationStatus.VALID
            else:
                proxy.status = ProxyStatus.INACTIVE
                proxy.validation_status = ValidationStatus.INVALID
            
            # Update proxy in database
            return self.update_proxy(proxy)
            
        except Exception as e:
            self.logger.error(f"Failed to save validation result for {proxy_id}: {e}")
            return False
    
    def _detect_file_format(self, file_path: str) -> str:
        """Detect file format from extension"""
        ext = Path(file_path).suffix.lower()
        format_map = {
            '.json': 'json',
            '.csv': 'csv', 
            '.txt': 'txt',
            '.xlsx': 'xlsx',
            '.xls': 'xlsx'
        }
        return format_map.get(ext, 'txt')
    
    def _parse_file(self, file_path: str, file_format: str) -> List[ProxyInfo]:
        """Parse file and return list of ProxyInfo objects"""
        proxies = []
        
        if file_format == 'json':
            with open(file_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        proxy = self._dict_to_proxy(item)
                        if proxy:
                            proxies.append(proxy)
                elif isinstance(data, dict) and 'proxies' in data:
                    for item in data['proxies']:
                        proxy = self._dict_to_proxy(item)
                        if proxy:
                            proxies.append(proxy)
        
        elif file_format == 'csv':
            import csv
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    proxy = self._dict_to_proxy(row)
                    if proxy:
                        proxies.append(proxy)
        
        else:  # txt format
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                host = parts[0].strip()
                                port = int(parts[1].split()[0])  # Handle "port protocol" format
                                protocol = self._infer_protocol(line)
                                
                                proxy = ProxyInfo(
                                    host=host,
                                    port=port,
                                    protocol=ProxyProtocol(protocol)
                                )
                                proxies.append(proxy)
                            except (ValueError, KeyError):
                                continue
        
        return proxies
    
    def _write_file(self, proxies: List[ProxyInfo], file_path: str, file_format: str):
        """Write proxies to file in specified format"""
        
        if file_format == 'json':
            data = [self._proxy_to_dict(proxy) for proxy in proxies]
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif file_format == 'csv':
            import csv
            with open(file_path, 'w', newline='') as f:
                if proxies:
                    fieldnames = ['host', 'port', 'protocol', 'status', 'anonymity_level', 
                                'threat_level', 'source', 'discovered_at', 'country', 'response_time']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for proxy in proxies:
                        row = self._proxy_to_dict(proxy)
                        writer.writerow({k: row.get(k, '') for k in fieldnames})
        
        else:  # txt format
            with open(file_path, 'w') as f:
                for proxy in proxies:
                    f.write(f"{proxy.address}\n")
    
    def _dict_to_proxy(self, data: Dict[str, Any]) -> Optional[ProxyInfo]:
        """Convert dictionary to ProxyInfo object"""
        try:
            host = data.get('host') or data.get('ip')
            port = data.get('port')
            protocol = data.get('protocol', 'http')
            
            if not host or not port:
                return None
            
            return ProxyInfo(
                host=str(host),
                port=int(port),
                protocol=ProxyProtocol(protocol.lower()),
                status=ProxyStatus(data.get('status', 'inactive')),
                anonymity_level=AnonymityLevel(data.get('anonymity_level', 'transparent')),
                threat_level=ThreatLevel(data.get('threat_level', 'low')),
                source=data.get('source'),
                discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.utcnow()
            )
        except (ValueError, KeyError) as e:
            self.logger.warning(f"Invalid proxy data: {data}, error: {e}")
            return None
    
    def _proxy_to_dict(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Convert ProxyInfo object to dictionary"""
        return {
            'host': proxy.host,
            'port': proxy.port,
            'protocol': proxy.protocol.value,
            'status': proxy.status.value,
            'anonymity_level': proxy.anonymity_level.value,
            'threat_level': proxy.threat_level.value,
            'source': proxy.source,
            'discovered_at': proxy.discovered_at.isoformat() if proxy.discovered_at else None,
            'country': proxy.geo_location.country_code if proxy.geo_location else None,
            'response_time': proxy.metrics.response_time if proxy.metrics else None
        }
    
    def _infer_protocol(self, proxy_string: str) -> str:
        """Infer protocol from proxy string or port"""
        if ':' in proxy_string:
            parts = proxy_string.split(':')
            if len(parts) >= 2:
                try:
                    port = int(parts[1])
                    # Common port-based detection
                    if port in [1080, 9050, 9150]:
                        return 'socks5'
                    elif port in [1081, 9051]:
                        return 'socks4'
                    elif port in [443, 8443]:
                        return 'https'
                except ValueError:
                    pass
        return 'http'  # Default


# Create extended database manager factory
def create_extended_database_manager(database_url: Optional[str] = None, 
                                   config: Optional[ConfigManager] = None) -> DatabaseManagerExtended:
    """Create extended database manager with CLI-focused operations"""
    if config is None:
        config = ConfigManager()
    
    if database_url:
        config.set('database_url', database_url)
    
    return DatabaseManagerExtended(config)