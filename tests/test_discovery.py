"""
Тесты для модуля discovery
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
from chel.discovery import PortScanner


class TestPortScanner(unittest.TestCase):
    """Тесты для PortScanner"""
    
    def setUp(self):
        self.scanner = PortScanner(verbose=False)
    
    @patch('chel.discovery.nmap.PortScanner')
    def test_scan_tcp_ports_success(self, mock_nmap_class):
        """Тест успешного TCP сканирования"""
        # Мокирование nmap
        mock_nm = MagicMock()
        mock_nmap_class.return_value = mock_nm
        
        # Настройка моков
        mock_nm.all_hosts.return_value = ['192.168.1.1']
        mock_nm.__getitem__.return_value = {
            'state': lambda: 'up',
            'all_protocols': lambda: ['tcp'],
            'tcp': {
                80: {
                    'state': 'open',
                    'name': 'http',
                    'version': '1.1',
                    'product': 'Apache'
                }
            }
        }
        
        result = self.scanner.scan_tcp_ports('192.168.1.1', [80])
        
        self.assertIn('target', result)
        self.assertIn('open_ports', result)
        self.assertEqual(result['target'], '192.168.1.1')
    
    def test_scan_tcp_ports_invalid_target(self):
        """Тест с невалидной целью"""
        result = self.scanner.scan_tcp_ports('invalid', [80])
        
        self.assertIn('error', result)


class TestDiscoveryIntegration(unittest.TestCase):
    """Интеграционные тесты discovery"""
    
    def test_port_scanner_initialization(self):
        """Тест инициализации сканера"""
        scanner = PortScanner(verbose=True)
        self.assertIsNotNone(scanner)


if __name__ == '__main__':
    unittest.main()
