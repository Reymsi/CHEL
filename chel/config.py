"""
Конфигурация приложения
"""
import os
from pathlib import Path

# Пути
BASE_DIR = Path(__file__).parent.parent
DB_DIR = BASE_DIR / "db"
DB_PATH = DB_DIR / "chel_vulns.sqlite"

# NVD feeds
# Примечание: NVD требует задержку 6 секунд между запросами
# Для получения API ключа: https://nvd.nist.gov/developers/request-an-api-key
NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
NVD_FEED_PATTERN = "nvdcve-1.1-{year}.json"
NVD_MODIFIED_FEED = "nvdcve-1.1-modified.json"
NVD_META_PATTERN = "nvdcve-1.1-{year}.meta"
NVD_RATE_LIMIT_DELAY = 6  # Минимальная задержка между запросами в секундах

# Vulners API
VULNERS_API_URL = "https://vulners.com/api/v3"

# Порты для сканирования
CRITICAL_PORTS = [445, 3389, 5985, 5986, 80, 443, 22, 21, 25, 1433, 3306, 5432]

# Таймауты
BANNER_TIMEOUT = 2.0
SCAN_TIMEOUT = 30.0
REQUEST_TIMEOUT = 30.0

# Fuzzy matching
FUZZY_THRESHOLD = 0.8

# Приоритеты уязвимостей
PRIORITY_HIGH = 7.0
PRIORITY_MEDIUM = 4.0

# Множители экспозиции
EXPOSURE_EXTERNAL = 1.2  # Порт доступен извне
EXPOSURE_LOCAL = 0.8     # Только локальный доступ
