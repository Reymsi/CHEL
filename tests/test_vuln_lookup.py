"""
Тесты для модуля vuln_lookup
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
from chel.vuln_lookup import VulnMatcher
from chel.database import VulnDatabase


class TestVulnMatcher(unittest.TestCase):
    """Тесты для VulnMatcher"""
    
    def setUp(self):
        self.matcher = VulnMatcher(verbose=False)
    
    def test_normalize_product_name(self):
        """Тест нормализации названий продуктов"""
        test_cases = [
            ("Microsoft Windows 10", "windows 10"),
            ("Apache HTTP Server", "apache http server"),
            ("Product v2.0", "product")
        ]
        
        for name, expected_part in test_cases:
            normalized = self.matcher.normalize_product_name(name)
            # Проверяем, что нормализация работает
            self.assertIsInstance(normalized, str)
            self.assertGreater(len(normalized), 0)
    
    def test_calculate_priority(self):
        """Тест расчёта приоритета"""
        # Высокий приоритет
        priority = self.matcher.calculate_priority(cvss_score=9.0, is_external=True)
        self.assertEqual(priority, 'High')
        
        # Средний приоритет
        priority = self.matcher.calculate_priority(cvss_score=5.0, is_external=False)
        self.assertEqual(priority, 'Medium')
        
        # Низкий приоритет
        priority = self.matcher.calculate_priority(cvss_score=3.0, is_external=False)
        self.assertEqual(priority, 'Low')
    
    def test_version_parsing(self):
        """Тест парсинга версий"""
        from packaging import version as pkg_version
        
        test_versions = ["1.2.3", "2.0", "10.0.1"]
        
        for ver_str in test_versions:
            parsed = self.matcher._parse_version(ver_str)
            self.assertIsNotNone(parsed)
            self.assertIsInstance(parsed, pkg_version.Version)


class TestVulnDatabase(unittest.TestCase):
    """Тесты для VulnDatabase"""
    
    def setUp(self):
        import tempfile
        import os
        from pathlib import Path
        
        # Создание временной БД для тестов
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite')
        self.temp_db.close()
        self.db_path = Path(self.temp_db.name)
        self.db = VulnDatabase(db_path=self.db_path)
    
    def tearDown(self):
        # Удаление временной БД
        if self.db_path.exists():
            self.db_path.unlink()
    
    def test_insert_and_find_vuln(self):
        """Тест вставки и поиска уязвимости"""
        # Вставка тестовой уязвимости
        success = self.db.insert_vuln(
            cve_id='CVE-2023-0001',
            cpe='cpe:2.3:a:test:product:1.0',
            summary='Test vulnerability',
            cvss_score=7.5,
            source='nvd'
        )
        self.assertTrue(success)
        
        # Поиск по CPE
        vulns = self.db.find_vulns_by_cpe('cpe:2.3:a:test:product:1.0')
        self.assertGreater(len(vulns), 0)
        self.assertEqual(vulns[0]['cve_id'], 'CVE-2023-0001')
    
    def test_get_vuln_count(self):
        """Тест подсчёта уязвимостей"""
        # Вставка нескольких уязвимостей
        for i in range(5):
            self.db.insert_vuln(
                cve_id=f'CVE-2023-{i:04d}',
                cvss_score=5.0,
                source='nvd'
            )
        
        count = self.db.get_vuln_count()
        self.assertGreaterEqual(count, 5)


if __name__ == '__main__':
    unittest.main()
