"""
Модуль сканирования сети и портов
"""
import logging
import nmap
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from chel.config import CRITICAL_PORTS, SCAN_TIMEOUT

logger = logging.getLogger(__name__)


class PortScanner:
    """Класс для сканирования портов"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.nm = nmap.PortScanner()
    
    def _log(self, message: str, level: str = "info"):
        """Логирование с учётом verbose"""
        if self.verbose or level in ["warning", "error"]:
            if level == "info":
                logger.info(message)
            elif level == "warning":
                logger.warning(message)
            elif level == "error":
                logger.error(message)
    
    def scan_tcp_ports(self, target: str, ports: Optional[List[int]] = None, 
                      quick: bool = False) -> Dict[str, Any]:
        """
        TCP сканирование портов
        
        Args:
            target: IP-адрес или хост
            ports: Список портов для сканирования (None = все стандартные)
            quick: Быстрое сканирование (SYN scan без version detection)
        """
        if ports is None:
            ports = CRITICAL_PORTS
        
        ports_str = ','.join(map(str, ports))
        
        self._log(f"Сканирование TCP портов {ports_str} на {target}...")
        
        try:
            if quick:
                # Быстрое SYN сканирование
                self.nm.scan(target, ports_str, arguments='-sS -T4 --max-retries 1')
            else:
                # Полное сканирование с определением версий
                self.nm.scan(target, ports_str, arguments='-sS -sV -T4')
            
            result = {
                'target': target,
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                result['host_status'] = host.state()
                
                # Обработка протоколов
                for proto in host.all_protocols():
                    ports_info = host[proto]
                    
                    for port, port_info in ports_info.items():
                        port_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        if port_info['state'] == 'open':
                            result['open_ports'].append(port_data)
                        elif port_info['state'] == 'closed':
                            result['closed_ports'].append(port_data)
                        elif port_info['state'] == 'filtered':
                            result['filtered_ports'].append(port_data)
            
            self._log(f"Найдено открытых портов: {len(result['open_ports'])}")
            return result
            
        except nmap.PortScannerError as e:
            self._log(f"Ошибка nmap: {e}", "error")
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
        except Exception as e:
            self._log(f"Неожиданная ошибка при сканировании: {e}", "error")
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
    
    def scan_udp_ports(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        UDP сканирование портов (только ключевые порты)
        
        Args:
            target: IP-адрес или хост
            ports: Список портов для сканирования
        """
        if ports is None:
            # Ключевые UDP порты
            ports = [53, 137, 138, 161, 500, 4500]
        
        ports_str = ','.join(map(str, ports))
        
        self._log(f"Сканирование UDP портов {ports_str} на {target}...")
        
        try:
            # UDP сканирование медленнее, используем более агрессивные таймауты
            self.nm.scan(target, ports_str, arguments='-sU -T4 --max-retries 1')
            
            result = {
                'target': target,
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                result['host_status'] = host.state()
                
                if 'udp' in host.all_protocols():
                    ports_info = host['udp']
                    
                    for port, port_info in ports_info.items():
                        port_data = {
                            'port': port,
                            'protocol': 'udp',
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        
                        if port_info['state'] == 'open':
                            result['open_ports'].append(port_data)
                        elif port_info['state'] == 'closed':
                            result['closed_ports'].append(port_data)
                        elif port_info['state'] == 'filtered':
                            result['filtered_ports'].append(port_data)
            
            self._log(f"Найдено открытых UDP портов: {len(result['open_ports'])}")
            return result
            
        except nmap.PortScannerError as e:
            self._log(f"Ошибка nmap UDP: {e}", "error")
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
        except Exception as e:
            self._log(f"Неожиданная ошибка при UDP сканировании: {e}", "error")
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'host_status': 'unknown'
            }
    
    def scan_with_os_detection(self, target: str) -> Dict[str, Any]:
        """Сканирование с определением ОС"""
        self._log(f"Определение ОС для {target}...")
        
        try:
            # OS detection требует root/админ прав
            self.nm.scan(target, arguments='-O -sV')
            
            result = {
                'target': target,
                'os_matches': [],
                'os_accuracy': 0
            }
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                if 'osmatch' in host:
                    for osmatch in host['osmatch']:
                        result['os_matches'].append({
                            'name': osmatch.get('name', ''),
                            'accuracy': int(osmatch.get('accuracy', 0))
                        })
                    
                    if result['os_matches']:
                        result['os_accuracy'] = max(m['accuracy'] for m in result['os_matches'])
            
            return result
            
        except Exception as e:
            self._log(f"Ошибка при определении ОС: {e}", "warning")
            return {
                'target': target,
                'os_matches': [],
                'os_accuracy': 0,
                'error': str(e)
            }
    
    def scan_range(self, target_range: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Сканирование диапазона хостов
        
        Args:
            target_range: Диапазон IP (например, "192.168.1.0/24")
            ports: Список портов
        """
        if ports is None:
            ports = CRITICAL_PORTS
        
        ports_str = ','.join(map(str, ports))
        
        self._log(f"Сканирование диапазона {target_range}...")
        
        try:
            # Быстрое сканирование для диапазона
            self.nm.scan(target_range, ports_str, arguments='-sS -T4 --max-retries 1')
            
            results = []
            for host in self.nm.all_hosts():
                host_result = {
                    'target': host,
                    'host_status': self.nm[host].state(),
                    'open_ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    for port, port_info in ports_info.items():
                        if port_info['state'] == 'open':
                            host_result['open_ports'].append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown')
                            })
                
                results.append(host_result)
            
            self._log(f"Найдено активных хостов: {len(results)}")
            return results
            
        except Exception as e:
            self._log(f"Ошибка при сканировании диапазона: {e}", "error")
            return []
