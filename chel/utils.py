"""
Вспомогательные функции
"""
import re
import sys
import platform
from typing import Optional, List, Dict, Any


def is_admin() -> bool:
    """Проверка прав администратора на Windows"""
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def normalize_ip(ip: str) -> Optional[str]:
    """Валидация и нормализация IP-адреса"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return None
    
    parts = ip.split('.')
    if all(0 <= int(p) <= 255 for p in parts):
        return ip
    return None


def normalize_product_name(name: str) -> str:
    """
    Нормализация названия продукта для сопоставления
    - Удаление версий
    - Удаление скобок и содержимого
    - Удаление префиксов (Microsoft, MS)
    - Приведение к нижнему регистру
    """
    if not name:
        return ""
    
    # Удаление версий (например, "Product 1.2.3" -> "Product")
    name = re.sub(r'\s+\d+\.\d+.*$', '', name)
    name = re.sub(r'\s+v?\d+.*$', '', name)
    
    # Удаление содержимого в скобках
    name = re.sub(r'\([^)]*\)', '', name)
    name = re.sub(r'\[[^\]]*\]', '', name)
    
    # Удаление префиксов
    name = re.sub(r'^Microsoft\s+', '', name, flags=re.IGNORECASE)
    name = re.sub(r'^MS\s+', '', name, flags=re.IGNORECASE)
    
    # Удаление лишних пробелов
    name = re.sub(r'\s+', ' ', name).strip()
    
    # Приведение к нижнему регистру
    return name.lower()


def extract_version(text: str) -> Optional[str]:
    """Извлечение версии из текста"""
    # Паттерны для версий: 1.2.3, v1.2.3, 1.2.3.4, etc.
    patterns = [
        r'v?(\d+\.\d+\.\d+\.\d+)',  # 1.2.3.4
        r'v?(\d+\.\d+\.\d+)',       # 1.2.3
        r'v?(\d+\.\d+)',            # 1.2
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    
    return None


def parse_modules(modules_str: str) -> List[str]:
    """Парсинг списка модулей из строки"""
    if modules_str.lower() == "all":
        return ["discovery", "fingerprint", "os_software", "vuln_lookup"]
    
    return [m.strip() for m in modules_str.split(",") if m.strip()]


def safe_get(d: Dict[str, Any], *keys, default=None):
    """Безопасное получение значения из вложенного словаря"""
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return default
    return d if d is not None else default
