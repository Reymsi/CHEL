"""
Главный класс Scanner для координации всех модулей
"""
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from chel.discovery import PortScanner
from chel.fingerprint import BannerGrabber, SpecializedScanner
from chel.os_software import WindowsInventory
from chel.vuln_lookup import VulnMatcher
from chel.assistant import SecurityAssistant
from chel.utils import is_admin

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Scanner:
    """Главный класс для сканирования безопасности"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        # Инициализация модулей
        self.port_scanner = PortScanner(verbose=verbose)
        self.banner_grabber = BannerGrabber(verbose=verbose)
        self.specialized_scanner = SpecializedScanner(verbose=verbose)
        self.windows_inventory = WindowsInventory(verbose=verbose)
        self.vuln_matcher = VulnMatcher(verbose=verbose)
        self.assistant = SecurityAssistant(verbose=verbose)
        
        # Настройка уровня логирования
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
    
    def scan(self, target: str, modules: List[str]) -> Dict[str, Any]:
        """
        Выполнение сканирования
        
        Args:
            target: IP-адрес или хост для сканирования
            modules: Список модулей для выполнения
        
        Returns:
            Словарь с результатами сканирования
        """
        results = {
            'scan_info': {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'modules': modules
            },
            'discovery': {},
            'fingerprint': {},
            'os_software': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        logger.info(f"Начало сканирования {target} с модулями: {', '.join(modules)}")
        
        try:
            # Модуль discovery
            if 'discovery' in modules:
                logger.info("Выполнение модуля discovery...")
                results['discovery'] = self.run_discovery(target)
            
            # Модуль fingerprint
            if 'fingerprint' in modules:
                logger.info("Выполнение модуля fingerprint...")
                results['fingerprint'] = self.run_fingerprint(target, results.get('discovery', {}))
            
            # Модуль os_software (только локально на Windows)
            if 'os_software' in modules:
                if target in ['localhost', '127.0.0.1', '::1'] or self._is_local_target(target):
                    logger.info("Выполнение модуля os_software...")
                    if not is_admin():
                        logger.warning("Модуль os_software требует прав администратора")
                    results['os_software'] = self.run_os_software()
                else:
                    logger.warning(f"Модуль os_software работает только локально, пропуск для {target}")
            
            # Модуль vuln_lookup
            if 'vuln_lookup' in modules:
                logger.info("Выполнение модуля vuln_lookup...")
                results['vulnerabilities'] = self.run_vuln_lookup(results)
            
            # Генерация рекомендаций
            logger.info("Генерация рекомендаций...")
            results['recommendations'] = self.assistant.generate_recommendations(results)
            
            logger.info("Сканирование завершено успешно")
        
        except Exception as e:
            logger.error(f"Ошибка при сканировании: {e}", exc_info=self.verbose)
            results['error'] = str(e)
        
        return results
    
    def run_discovery(self, target: str) -> Dict[str, Any]:
        """Выполнение модуля discovery"""
        try:
            # TCP сканирование
            tcp_result = self.port_scanner.scan_tcp_ports(target)
            
            # UDP сканирование (опционально, медленнее)
            udp_result = {}
            # udp_result = self.port_scanner.scan_udp_ports(target)
            
            return {
                'tcp': tcp_result,
                'udp': udp_result,
                'open_ports': tcp_result.get('open_ports', [])
            }
        except Exception as e:
            logger.error(f"Ошибка в модуле discovery: {e}", exc_info=self.verbose)
            return {'error': str(e)}
    
    def run_fingerprint(self, target: str, discovery_data: Dict[str, Any]) -> Dict[str, Any]:
        """Выполнение модуля fingerprint"""
        try:
            banners = []
            specialized = {}
            
            open_ports = discovery_data.get('open_ports', [])
            
            # Banner grabbing для открытых портов
            for port_info in open_ports:
                port = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                
                if port:
                    try:
                        banner = self.banner_grabber.grab_banner(target, port, protocol)
                        if banner.get('banner') or banner.get('product'):
                            banners.append(banner)
                    except Exception as e:
                        logger.debug(f"Ошибка при получении баннера {target}:{port}: {e}")
            
            # Специализированные проверки
            for port_info in open_ports:
                port = port_info.get('port')
                
                if port == 445:  # SMB
                    try:
                        specialized['smb'] = self.specialized_scanner.scan_smb(target, port)
                    except Exception as e:
                        logger.debug(f"Ошибка при SMB сканировании: {e}")
                
                elif port == 3389:  # RDP
                    try:
                        specialized['rdp'] = self.specialized_scanner.scan_rdp(target, port)
                    except Exception as e:
                        logger.debug(f"Ошибка при RDP сканировании: {e}")
                
                elif port in [5985, 5986]:  # WinRM
                    try:
                        specialized[f'winrm_{port}'] = self.specialized_scanner.scan_winrm(target, port)
                    except Exception as e:
                        logger.debug(f"Ошибка при WinRM сканировании: {e}")
            
            return {
                'banners': banners,
                'specialized': specialized
            }
        except Exception as e:
            logger.error(f"Ошибка в модуле fingerprint: {e}", exc_info=self.verbose)
            return {'error': str(e)}
    
    def run_os_software(self) -> Dict[str, Any]:
        """Выполнение модуля os_software"""
        try:
            installed_software = self.windows_inventory.get_installed_software()
            hotfixes = self.windows_inventory.get_hotfixes()
            services = self.windows_inventory.get_services()
            processes = self.windows_inventory.get_processes()
            security_policies = self.windows_inventory.check_security_policies()
            shares = self.windows_inventory.check_shares()
            admin_ports = self.windows_inventory.check_admin_ports()
            
            return {
                'installed_software': installed_software,
                'hotfixes': hotfixes,
                'services': services,
                'processes': processes,
                'security_policies': security_policies,
                'shares': shares,
                'admin_ports': admin_ports
            }
        except Exception as e:
            logger.error(f"Ошибка в модуле os_software: {e}", exc_info=self.verbose)
            return {'error': str(e)}
    
    def run_vuln_lookup(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Выполнение модуля vuln_lookup"""
        try:
            vulnerabilities = []
            
            # Поиск уязвимостей для установленного ПО
            os_software = scan_data.get('os_software', {})
            installed_software = os_software.get('installed_software', [])
            
            if installed_software:
                # Получение списка открытых портов для определения экспозиции
                discovery = scan_data.get('discovery', {})
                open_ports = discovery.get('open_ports', [])
                
                # Поиск уязвимостей
                software_vulns = self.vuln_matcher.find_vulnerabilities_for_software_list(
                    installed_software,
                    open_ports
                )
                vulnerabilities.extend(software_vulns)
            
            # Поиск уязвимостей для обнаруженных сервисов
            fingerprint = scan_data.get('fingerprint', {})
            banners = fingerprint.get('banners', [])
            
            for banner in banners:
                product = banner.get('product')
                version = banner.get('version')
                port = banner.get('port')
                
                if product:
                    # Определение экспозиции (упрощённо: все открытые порты считаем внешними)
                    is_external = port is not None
                    
                    vulns = self.vuln_matcher.find_vulnerabilities(
                        product_name=product,
                        product_version=version,
                        port=port,
                        is_external=is_external
                    )
                    vulnerabilities.extend(vulns)
            
            # Удаление дубликатов и приоритизация
            unique_vulns = []
            seen_cves = set()
            
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_vulns.append(vuln)
            
            # Приоритизация
            prioritized = self.assistant.prioritize_vulnerabilities(unique_vulns)
            
            return prioritized
        
        except Exception as e:
            logger.error(f"Ошибка в модуле vuln_lookup: {e}", exc_info=self.verbose)
            return []
    
    def _is_local_target(self, target: str) -> bool:
        """Проверка, является ли цель локальной"""
        local_targets = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        return target.lower() in local_targets
    
    def run_module(self, module_name: str, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Запуск отдельного модуля
        
        Args:
            module_name: Имя модуля
            target: Целевой хост
            context: Контекст из предыдущих модулей
        
        Returns:
            Результаты модуля
        """
        context = context or {}
        
        module_map = {
            'discovery': lambda: self.run_discovery(target),
            'fingerprint': lambda: self.run_fingerprint(target, context.get('discovery', {})),
            'os_software': lambda: self.run_os_software(),
            'vuln_lookup': lambda: self.run_vuln_lookup(context)
        }
        
        if module_name in module_map:
            try:
                return module_map[module_name]()
            except Exception as e:
                logger.error(f"Ошибка в модуле {module_name}: {e}", exc_info=self.verbose)
                return {'error': str(e)}
        else:
            logger.warning(f"Неизвестный модуль: {module_name}")
            return {'error': f'Unknown module: {module_name}'}
