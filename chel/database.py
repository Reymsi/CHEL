"""
Работа с базой данных уязвимостей
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from chel.config import DB_PATH, DB_DIR

logger = logging.getLogger(__name__)


class VulnDatabase:
    """Класс для работы с базой данных уязвимостей"""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._ensure_db_dir()
        self._initialize()
    
    def _ensure_db_dir(self):
        """Создание директории БД если не существует"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _initialize(self):
        """Инициализация БД: создание таблиц"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Таблица уязвимостей
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    cpe TEXT,
                    summary TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    affected_versions TEXT,
                    vuln_references TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Таблица продуктов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    possible_cpes TEXT,
                    vendor TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Таблица CPE mappings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cpe_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cpe TEXT UNIQUE NOT NULL,
                    product_name TEXT,
                    vendor TEXT,
                    version_pattern TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Индексы для быстрого поиска
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulns(cve_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulns_cpe ON vulns(cpe)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulns_cvss_score ON vulns(cvss_score)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_products_normalized_name ON products(normalized_name)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cpe_mappings_cpe ON cpe_mappings(cpe)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cpe_mappings_product_name ON cpe_mappings(product_name)
            """)
            
            conn.commit()
            logger.info(f"База данных инициализирована: {self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """Контекстный менеджер для работы с соединением"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def insert_vuln(self, cve_id: str, cpe: Optional[str] = None, 
                   summary: Optional[str] = None, cvss_score: Optional[float] = None,
                   cvss_vector: Optional[str] = None, affected_versions: Optional[List[str]] = None,
                   references: Optional[List[str]] = None, published_date: Optional[str] = None,
                   modified_date: Optional[str] = None, source: str = "nvd") -> bool:
        """Вставка или обновление уязвимости"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                affected_versions_json = json.dumps(affected_versions) if affected_versions else None
                references_json = json.dumps(references) if references else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO vulns 
                    (cve_id, cpe, summary, cvss_score, cvss_vector, 
                     affected_versions, vuln_references, published_date, modified_date, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (cve_id, cpe, summary, cvss_score, cvss_vector,
                      affected_versions_json, references_json, published_date, modified_date, source))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка при вставке уязвимости {cve_id}: {e}")
            return False
    
    def find_vulns_by_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Поиск уязвимостей по CPE"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM vulns WHERE cpe = ? ORDER BY cvss_score DESC
                """, (cpe,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Ошибка при поиске уязвимостей по CPE {cpe}: {e}")
            return []
    
    def find_vulns_by_product_version(self, product_name: str, version: str) -> List[Dict[str, Any]]:
        """Поиск уязвимостей по продукту и версии"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Поиск через CPE mappings
                cursor.execute("""
                    SELECT DISTINCT v.* FROM vulns v
                    JOIN cpe_mappings cm ON v.cpe = cm.cpe
                    WHERE cm.product_name LIKE ? 
                    AND (cm.version_pattern IS NULL OR ? LIKE cm.version_pattern || '%')
                    ORDER BY v.cvss_score DESC
                """, (f"%{product_name}%", version))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Ошибка при поиске уязвимостей для {product_name} {version}: {e}")
            return []
    
    def insert_product(self, product_name: str, normalized_name: str,
                      possible_cpes: Optional[List[str]] = None,
                      vendor: Optional[str] = None) -> bool:
        """Вставка продукта"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                possible_cpes_json = json.dumps(possible_cpes) if possible_cpes else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO products 
                    (product_name, normalized_name, possible_cpes, vendor)
                    VALUES (?, ?, ?, ?)
                """, (product_name, normalized_name, possible_cpes_json, vendor))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка при вставке продукта {product_name}: {e}")
            return False
    
    def find_product_by_normalized_name(self, normalized_name: str) -> Optional[Dict[str, Any]]:
        """Поиск продукта по нормализованному имени"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM products WHERE normalized_name = ? LIMIT 1
                """, (normalized_name,))
                
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Ошибка при поиске продукта {normalized_name}: {e}")
            return None
    
    def insert_cpe_mapping(self, cpe: str, product_name: Optional[str] = None,
                          vendor: Optional[str] = None, version_pattern: Optional[str] = None) -> bool:
        """Вставка CPE mapping"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO cpe_mappings 
                    (cpe, product_name, vendor, version_pattern)
                    VALUES (?, ?, ?, ?)
                """, (cpe, product_name, vendor, version_pattern))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка при вставке CPE mapping {cpe}: {e}")
            return False
    
    def get_vuln_count(self) -> int:
        """Получение количества уязвимостей в БД"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM vulns")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Ошибка при подсчёте уязвимостей: {e}")
            return 0
    
    def clear_all(self):
        """Очистка всех таблиц (для тестирования)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vulns")
                cursor.execute("DELETE FROM products")
                cursor.execute("DELETE FROM cpe_mappings")
                conn.commit()
                logger.info("База данных очищена")
        except Exception as e:
            logger.error(f"Ошибка при очистке БД: {e}")
