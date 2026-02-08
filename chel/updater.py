"""
Обновление базы данных уязвимостей из NVD и Vulners
"""
import json
import logging
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

from chel.config import (
    NVD_BASE_URL, NVD_FEED_PATTERN, NVD_MODIFIED_FEED, NVD_META_PATTERN,
    VULNERS_API_URL, REQUEST_TIMEOUT, NVD_RATE_LIMIT_DELAY
)
from chel.database import VulnDatabase

logger = logging.getLogger(__name__)


class VulnUpdater:
    """Класс для обновления базы данных уязвимостей"""
    
    def __init__(self, verbose: bool = False, api_key: Optional[str] = None):
        self.db = VulnDatabase()
        self.verbose = verbose
        self.api_key = api_key
        self.session = requests.Session()
        # NVD требует правильный User-Agent с контактной информацией
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate'
        })
        # Добавляем API ключ если есть
        if api_key:
            self.session.headers.update({
                'apiKey': api_key
            })
    
    def _log(self, message: str, level: str = "info"):
        """Логирование с учётом verbose"""
        if self.verbose or level in ["warning", "error"]:
            if level == "info":
                logger.info(message)
            elif level == "warning":
                logger.warning(message)
            elif level == "error":
                logger.error(message)
    
    def _download_file(self, url: str, retries: int = 3) -> Optional[bytes]:
        """Скачивание файла с повторными попытками"""
        # NVD требует задержку минимум 6 секунд между запросами
        time.sleep(NVD_RATE_LIMIT_DELAY)
        
        for attempt in range(retries):
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                
                # Проверка на rate limiting
                if response.status_code == 403:
                    # Если 403, пробуем с другим User-Agent или ждём дольше
                    if attempt == 0:
                        # Первая попытка - меняем User-Agent
                        self.session.headers.update({
                            'User-Agent': 'Mozilla/5.0 (compatible; CHEL-Scanner/0.1.0; +https://github.com/yourusername/chel-scanner)'
                        })
                        time.sleep(10)  # Дополнительная задержка
                        continue
                    else:
                        self._log(f"NVD вернул 403 Forbidden для {url}. Возможные причины:", "warning")
                        self._log("  1. Слишком частые запросы (нужна задержка 6+ секунд)", "warning")
                        self._log("  2. Неправильный User-Agent", "warning")
                        self._log("  3. Требуется API ключ (получите на https://nvd.nist.gov/developers/request-an-api-key)", "warning")
                        return None
                
                response.raise_for_status()
                return response.content
            except requests.RequestException as e:
                if attempt < retries - 1:
                    wait_time = 2 ** attempt * 5  # Увеличиваем задержку
                    self._log(f"Ошибка при загрузке {url}, повтор через {wait_time}с: {e}", "warning")
                    time.sleep(wait_time)
                else:
                    self._log(f"Не удалось загрузить {url} после {retries} попыток: {e}", "error")
                    return None
        return None
    
    def _parse_meta(self, meta_content: str) -> Dict[str, Any]:
        """Парсинг .meta файла NVD"""
        meta = {}
        for line in meta_content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key in ['lastModifiedDate', 'sha256', 'size']:
                    meta[key] = value
        return meta
    
    def _should_update_feed(self, year: int, force: bool = False) -> bool:
        """Проверка необходимости обновления фида"""
        if force:
            return True
        
        # Проверка метаданных
        meta_url = f"{NVD_BASE_URL}/{NVD_META_PATTERN.format(year=year)}"
        meta_content = self._download_file(meta_url)
        
        if not meta_content:
            return True  # Если не можем проверить, обновляем
        
        # TODO: Сохранять и сравнивать метаданные в БД
        # Пока всегда обновляем
        return True
    
    def download_nvd_feeds(self, years: Optional[List[int]] = None, force: bool = False) -> int:
        """Загрузка NVD фидов"""
        if years is None:
            # Загружаем последние 5 лет + текущий год
            current_year = datetime.now().year
            years = list(range(current_year - 4, current_year + 1))
        
        total_cves = 0
        
        # Сначала загружаем modified feed
        self._log("Загрузка modified feed...")
        modified_url = f"{NVD_BASE_URL}/{NVD_MODIFIED_FEED}"
        modified_data = self._download_file(modified_url)
        
        if modified_data:
            try:
                feed_json = json.loads(modified_data.decode('utf-8'))
                count = self.parse_nvd_json(feed_json)
                total_cves += count
                self._log(f"Обработано {count} CVE из modified feed")
            except json.JSONDecodeError as e:
                self._log(f"Ошибка парсинга modified feed: {e}", "error")
        
        # Затем загружаем фиды по годам
        for year in years:
            if not self._should_update_feed(year, force):
                self._log(f"Пропуск {year} года (нет обновлений)")
                continue
            
            self._log(f"Загрузка фида за {year} год...")
            feed_url = f"{NVD_BASE_URL}/{NVD_FEED_PATTERN.format(year=year)}"
            feed_data = self._download_file(feed_url)
            
            if feed_data:
                try:
                    feed_json = json.loads(feed_data.decode('utf-8'))
                    count = self.parse_nvd_json(feed_json)
                    total_cves += count
                    self._log(f"Обработано {count} CVE за {year} год")
                except json.JSONDecodeError as e:
                    self._log(f"Ошибка парсинга фида за {year} год: {e}", "error")
            else:
                self._log(f"Не удалось загрузить фид за {year} год", "warning")
        
        return total_cves
    
    def parse_nvd_json(self, feed_data: Dict[str, Any]) -> int:
        """Парсинг NVD JSON и сохранение в БД"""
        count = 0
        
        if 'CVE_Items' not in feed_data:
            return 0
        
        for item in feed_data['CVE_Items']:
            try:
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    continue
                
                # Описание
                descriptions = item.get('cve', {}).get('description', {}).get('description_data', [])
                summary = descriptions[0].get('value', '') if descriptions else ''
                
                # CVSS
                cvss_score = None
                cvss_vector = None
                
                if 'impact' in item and 'baseMetricV3' in item['impact']:
                    cvss_v3 = item['impact']['baseMetricV3'].get('cvssV3', {})
                    cvss_score = cvss_v3.get('baseScore')
                    cvss_vector = cvss_v3.get('vectorString')
                elif 'impact' in item and 'baseMetricV2' in item['impact']:
                    cvss_v2 = item['impact']['baseMetricV2'].get('cvssV2', {})
                    cvss_score = cvss_v2.get('baseScore')
                    cvss_vector = cvss_v2.get('vectorString')
                
                # CPE и affected versions
                cpe_list = []
                affected_versions = []
                
                if 'configurations' in item:
                    for config in item['configurations'].get('nodes', []):
                        for cpe_match in config.get('cpe_match', []):
                            cpe = cpe_match.get('cpe23Uri')
                            if cpe:
                                cpe_list.append(cpe)
                            
                            version_start = cpe_match.get('versionStartIncluding')
                            version_end = cpe_match.get('versionEndExcluding')
                            if version_start:
                                affected_versions.append(f">={version_start}")
                            if version_end:
                                affected_versions.append(f"<{version_end}")
                
                # References
                references = []
                if 'references' in item.get('cve', {}):
                    for ref in item['cve']['references'].get('reference_data', []):
                        references.append(ref.get('url', ''))
                
                # Даты
                published_date = item.get('publishedDate', '')
                modified_date = item.get('lastModifiedDate', '')
                
                # Сохранение каждой CPE отдельно
                if cpe_list:
                    for cpe in cpe_list:
                        self.db.insert_vuln(
                            cve_id=cve_id,
                            cpe=cpe,
                            summary=summary,
                            cvss_score=cvss_score,
                            cvss_vector=cvss_vector,
                            affected_versions=affected_versions if affected_versions else None,
                            references=references if references else None,
                            published_date=published_date,
                            modified_date=modified_date,
                            source='nvd'
                        )
                else:
                    # Сохраняем без CPE
                    self.db.insert_vuln(
                        cve_id=cve_id,
                        cpe=None,
                        summary=summary,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        affected_versions=affected_versions if affected_versions else None,
                        references=references if references else None,
                        published_date=published_date,
                        modified_date=modified_date,
                        source='nvd'
                    )
                
                count += 1
                
            except Exception as e:
                self._log(f"Ошибка при обработке CVE: {e}", "warning")
                continue
        
        return count
    
    def fetch_vulners_data(self, api_key: Optional[str] = None) -> int:
        """Загрузка данных из Vulners API"""
        if not api_key:
            self._log("API ключ Vulners не указан, пропуск", "warning")
            return 0
        
        # TODO: Реализовать запросы к Vulners API
        # Vulners API требует регистрации и имеет ограничения
        self._log("Интеграция с Vulners API будет реализована позже", "info")
        return 0
    
    def update_cpe_mappings(self):
        """Обновление CPE mappings"""
        # TODO: Загрузка официального CPE dictionary
        # Пока создаём mappings на основе собранных данных
        self._log("Обновление CPE mappings...")
        
        # Извлекаем уникальные CPE из уязвимостей
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT cpe FROM vulns WHERE cpe IS NOT NULL")
            rows = cursor.fetchall()
            
            for row in rows:
                cpe = row[0]
                # Парсинг CPE: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else None
                    
                    self.db.insert_cpe_mapping(
                        cpe=cpe,
                        product_name=product,
                        vendor=vendor,
                        version_pattern=version
                    )
        
        self._log("CPE mappings обновлены")
    
    def update_all(self, force: bool = False):
        """Обновление всех данных"""
        self._log("Начало обновления базы данных...")
        
        # Загрузка NVD
        count = self.download_nvd_feeds(force=force)
        self._log(f"Всего обработано CVE: {count}")
        
        # Обновление CPE mappings
        self.update_cpe_mappings()
        
        # Загрузка Vulners (если есть API key)
        # vulners_count = self.fetch_vulners_data()
        
        total = self.db.get_vuln_count()
        self._log(f"Всего уязвимостей в БД: {total}")
