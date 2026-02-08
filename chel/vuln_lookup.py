"""
Модуль поиска уязвимостей в базе данных
"""
import json
import logging
import re
from typing import List, Dict, Any, Optional
from packaging import version as pkg_version

try:
    from rapidfuzz import fuzz
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False

from chel.database import VulnDatabase
from chel.utils import normalize_product_name, extract_version
from chel.config import FUZZY_THRESHOLD, PRIORITY_HIGH, PRIORITY_MEDIUM, EXPOSURE_EXTERNAL, EXPOSURE_LOCAL

logger = logging.getLogger(__name__)


class VulnMatcher:
    """Класс для сопоставления ПО с уязвимостями"""
    
    def __init__(self, verbose: bool = False):
        self.db = VulnDatabase()
        self.verbose = verbose
        self._normalization_cache = {}
    
    def _log(self, message: str, level: str = "info"):
        """Логирование с учётом verbose"""
        if self.verbose or level in ["warning", "error"]:
            if level == "info":
                logger.info(message)
            elif level == "warning":
                logger.warning(message)
            elif level == "error":
                logger.error(message)
    
    def normalize_product_name(self, name: str) -> str:
        """Нормализация названия продукта с кэшированием"""
        if name in self._normalization_cache:
            return self._normalization_cache[name]
        
        normalized = normalize_product_name(name)
        self._normalization_cache[name] = normalized
        return normalized
    
    def find_matching_cpe(self, product_name: str, vendor: Optional[str] = None) -> List[str]:
        """
        Поиск соответствующих CPE для продукта
        
        Args:
            product_name: Название продукта
            vendor: Производитель (опционально)
        
        Returns:
            Список возможных CPE
        """
        normalized_name = self.normalize_product_name(product_name)
        possible_cpes = []
        
        try:
            # Поиск в таблице products
            product = self.db.find_product_by_normalized_name(normalized_name)
            if product and product.get('possible_cpes'):
                cpes = json.loads(product['possible_cpes'])
                possible_cpes.extend(cpes)
            
            # Поиск в CPE mappings с fuzzy matching
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT cpe, product_name FROM cpe_mappings")
                rows = cursor.fetchall()
                
                for row in rows:
                    cpe_product_name = row[1]
                    if not cpe_product_name:
                        continue
                    
                    # Fuzzy matching
                    if RAPIDFUZZ_AVAILABLE:
                        similarity = fuzz.ratio(normalized_name.lower(), cpe_product_name.lower())
                        if similarity >= (FUZZY_THRESHOLD * 100):
                            possible_cpes.append(row[0])
                    else:
                        # Простое сравнение
                        if normalized_name.lower() in cpe_product_name.lower() or \
                           cpe_product_name.lower() in normalized_name.lower():
                            possible_cpes.append(row[0])
        
        except Exception as e:
            self._log(f"Ошибка при поиске CPE для {product_name}: {e}", "warning")
        
        return list(set(possible_cpes))  # Удаление дубликатов
    
    def match_version(self, product_version: str, affected_versions: Optional[List[str]]) -> bool:
        """
        Проверка соответствия версии продукта списку уязвимых версий
        
        Args:
            product_version: Версия продукта
            affected_versions: Список уязвимых версий (может содержать диапазоны)
        
        Returns:
            True если версия уязвима
        """
        if not affected_versions:
            return True  # Если нет информации о версиях, считаем уязвимым
        
        try:
            product_ver = self._parse_version(product_version)
            if not product_ver:
                return True  # Не можем определить версию, считаем уязвимым
            
            for affected_range in affected_versions:
                if self._version_in_range(product_ver, affected_range):
                    return True
        
        except Exception as e:
            self._log(f"Ошибка при сравнении версий: {e}", "warning")
            return True  # В случае ошибки считаем уязвимым
        
        return False
    
    def _parse_version(self, version_str: str) -> Optional[pkg_version.Version]:
        """Парсинг версии в объект Version"""
        if not version_str:
            return None
        
        try:
            # Очистка версии от лишних символов
            cleaned = version_str.strip()
            # Удаление префиксов v, вер.
            cleaned = re.sub(r'^[vV]', '', cleaned)
            cleaned = re.sub(r'^вер\.?\s*', '', cleaned, flags=re.IGNORECASE)
            
            return pkg_version.parse(cleaned)
        except Exception:
            return None
    
    def _version_in_range(self, version: pkg_version.Version, version_range: str) -> bool:
        """Проверка вхождения версии в диапазон"""
        # Поддержка форматов: >=1.2.3, <2.0.0, 1.2.3-2.0.0
        try:
            if version_range.startswith('>='):
                min_version = self._parse_version(version_range[2:])
                return min_version and version >= min_version
            elif version_range.startswith('<='):
                max_version = self._parse_version(version_range[2:])
                return max_version and version <= max_version
            elif version_range.startswith('>'):
                min_version = self._parse_version(version_range[1:])
                return min_version and version > min_version
            elif version_range.startswith('<'):
                max_version = self._parse_version(version_range[1:])
                return max_version and version < max_version
            elif '-' in version_range:
                # Диапазон 1.2.3-2.0.0
                parts = version_range.split('-')
                if len(parts) == 2:
                    min_v = self._parse_version(parts[0])
                    max_v = self._parse_version(parts[1])
                    if min_v and max_v:
                        return min_v <= version <= max_v
            else:
                # Точное совпадение
                target_version = self._parse_version(version_range)
                return target_version and version == target_version
        
        except Exception:
            pass
        
        return False
    
    def find_vulnerabilities(self, product_name: str, product_version: Optional[str] = None,
                            cpe: Optional[str] = None, port: Optional[int] = None,
                            is_external: bool = False) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей для продукта
        
        Args:
            product_name: Название продукта
            product_version: Версия продукта
            cpe: CPE (если известен)
            port: Порт на котором работает (для расчёта экспозиции)
            is_external: Доступен ли извне (для расчёта приоритета)
        
        Returns:
            Список найденных уязвимостей
        """
        vulnerabilities = []
        
        try:
            # Если CPE не указан, ищем возможные
            if not cpe:
                possible_cpes = self.find_matching_cpe(product_name)
            else:
                possible_cpes = [cpe]
            
            # Поиск уязвимостей по CPE
            for cpe_item in possible_cpes:
                vulns = self.db.find_vulns_by_cpe(cpe_item)
                
                for vuln in vulns:
                    # Проверка версии
                    if product_version:
                        affected_versions = None
                        if vuln.get('affected_versions'):
                            try:
                                affected_versions = json.loads(vuln['affected_versions'])
                            except:
                                pass
                        
                        if not self.match_version(product_version, affected_versions):
                            continue  # Версия не уязвима
                    
                    # Расчёт приоритета
                    priority = self.calculate_priority(
                        cvss_score=vuln.get('cvss_score'),
                        port=port,
                        is_external=is_external
                    )
                    
                    vuln_data = {
                        'cve_id': vuln.get('cve_id'),
                        'cpe': cpe_item,
                        'product': product_name,
                        'version': product_version,
                        'cvss_score': vuln.get('cvss_score'),
                        'cvss_vector': vuln.get('cvss_vector'),
                        'summary': vuln.get('summary'),
                        'references': json.loads(vuln['vuln_references']) if vuln.get('vuln_references') else [],
                        'priority': priority,
                        'port': port,
                        'is_external': is_external,
                        'published_date': vuln.get('published_date'),
                        'source': vuln.get('source', 'nvd')
                    }
                    
                    vulnerabilities.append(vuln_data)
            
            # Если не нашли по CPE, пробуем поиск по названию и версии
            if not vulnerabilities and product_version:
                vulns = self.db.find_vulns_by_product_version(product_name, product_version)
                
                for vuln in vulns:
                    priority = self.calculate_priority(
                        cvss_score=vuln.get('cvss_score'),
                        port=port,
                        is_external=is_external
                    )
                    
                    vuln_data = {
                        'cve_id': vuln.get('cve_id'),
                        'cpe': vuln.get('cpe'),
                        'product': product_name,
                        'version': product_version,
                        'cvss_score': vuln.get('cvss_score'),
                        'cvss_vector': vuln.get('cvss_vector'),
                        'summary': vuln.get('summary'),
                        'references': json.loads(vuln['vuln_references']) if vuln.get('vuln_references') else [],
                        'priority': priority,
                        'port': port,
                        'is_external': is_external,
                        'published_date': vuln.get('published_date'),
                        'source': vuln.get('source', 'nvd')
                    }
                    
                    vulnerabilities.append(vuln_data)
        
        except Exception as e:
            self._log(f"Ошибка при поиске уязвимостей для {product_name}: {e}", "error")
        
        # Сортировка по приоритету (высокий -> низкий)
        vulnerabilities.sort(key=lambda x: (
            {'High': 0, 'Medium': 1, 'Low': 2}.get(x.get('priority', 'Low'), 2),
            -(x.get('cvss_score') or 0)
        ))
        
        return vulnerabilities
    
    def calculate_priority(self, cvss_score: Optional[float], port: Optional[int] = None,
                          is_external: bool = False) -> str:
        """
        Расчёт приоритета уязвимости
        
        Args:
            cvss_score: Базовый CVSS score
            port: Порт на котором работает сервис
            is_external: Доступен ли извне
        
        Returns:
            Приоритет: 'High', 'Medium' или 'Low'
        """
        if not cvss_score:
            cvss_score = 0.0
        
        # Множитель экспозиции
        exposure_multiplier = EXPOSURE_EXTERNAL if is_external else EXPOSURE_LOCAL
        
        # Скорректированный score
        adjusted_score = cvss_score * exposure_multiplier
        
        # Определение приоритета
        if adjusted_score >= PRIORITY_HIGH:
            return 'High'
        elif adjusted_score >= PRIORITY_MEDIUM:
            return 'Medium'
        else:
            return 'Low'
    
    def find_vulnerabilities_for_software_list(self, software_list: List[Dict[str, Any]],
                                             open_ports: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей для списка ПО
        
        Args:
            software_list: Список установленного ПО
            open_ports: Список открытых портов (для определения экспозиции)
        
        Returns:
            Список всех найденных уязвимостей
        """
        all_vulnerabilities = []
        
        # Создание словаря портов для быстрого поиска
        port_services = {}
        if open_ports:
            for port_info in open_ports:
                port = port_info.get('port')
                service = port_info.get('service', '').lower()
                if port:
                    port_services[service] = port
        
        for software in software_list:
            product_name = software.get('name', '')
            product_version = software.get('version')
            
            if not product_name:
                continue
            
            # Определение экспозиции (если ПО работает на открытом порту)
            is_external = False
            port = None
            
            # Простая эвристика: проверка названия сервиса в портах
            normalized_name = self.normalize_product_name(product_name)
            for service, port_num in port_services.items():
                if normalized_name in service or service in normalized_name:
                    port = port_num
                    is_external = True  # Упрощённо считаем все открытые порты внешними
                    break
            
            # Поиск уязвимостей
            vulns = self.find_vulnerabilities(
                product_name=product_name,
                product_version=product_version,
                port=port,
                is_external=is_external
            )
            
            all_vulnerabilities.extend(vulns)
        
        # Удаление дубликатов (по CVE ID)
        seen_cves = set()
        unique_vulns = []
        for vuln in all_vulnerabilities:
            cve_id = vuln.get('cve_id')
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulns.append(vuln)
        
        return unique_vulns
