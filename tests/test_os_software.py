"""
Тесты для модуля os_software
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys

# Пропуск тестов на не-Windows системах
if sys.platform != 'win32':
    import unittest
    class TestWindowsInventory(unittest.TestCase):
        def test_skip_on_non_windows(self):
            self.skipTest("Windows-only tests")
else:
    from chel.os_software import WindowsInventory


class TestWindowsInventory(unittest.TestCase):
    """Тесты для WindowsInventory"""
    
    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    def setUp(self):
        self.inventory = WindowsInventory(verbose=False)
    
    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    def test_get_installed_software(self):
        """Тест получения установленного ПО"""
        software = self.inventory.get_installed_software()
        
        # Проверяем, что возвращается список
        self.assertIsInstance(software, list)
        
        # Если есть ПО, проверяем структуру
        if software:
            item = software[0]
            self.assertIn('name', item)
            self.assertIn('normalized_name', item)
    
    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    @patch('chel.os_software.subprocess.run')
    def test_get_hotfixes_mock(self, mock_subprocess):
        """Тест получения hotfixes с моком"""
        # Мокирование вывода wmic
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="Node,HotFixID,InstalledOn,Description\n"
                   "TEST,KB123456,2023-01-01,Test update\n"
        )
        
        hotfixes = self.inventory.get_hotfixes()
        self.assertIsInstance(hotfixes, list)


if __name__ == '__main__':
    unittest.main()
