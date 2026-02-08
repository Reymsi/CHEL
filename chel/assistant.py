"""
Модуль ИИ-помощника для генерации рекомендаций
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class SecurityAssistant:
    """Класс для генерации рекомендаций по безопасности"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def _log(self, message: str, level: str = "info"):
        """Логирование с учётом verbose"""
        if self.verbose or level in ["warning", "error"]:
            if level == "info":
                logger.info(message)
            elif level == "warning":
                logger.warning(message)
            elif level == "error":
                logger.error(message)
    
    def generate_recommendations(self, scan_data: Dict[str, Any]) -> List[str]:
        """
        Генерация рекомендаций на основе результатов сканирования
        
        Args:
            scan_data: Данные сканирования
        
        Returns:
            Список рекомендаций
        """
        recommendations = []
        
        # Анализ уязвимостей
        vulnerabilities = scan_data.get('vulnerabilities', [])
        if vulnerabilities:
            recommendations.extend(self._recommendations_for_vulnerabilities(vulnerabilities))
        
        # Анализ открытых портов
        discovery = scan_data.get('discovery', {})
        if discovery:
            recommendations.extend(self._recommendations_for_ports(discovery))
        
        # Анализ конфигурации безопасности
        os_software = scan_data.get('os_software', {})
        if os_software:
            recommendations.extend(self._recommendations_for_security_config(os_software))
        
        # Удаление дубликатов
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _recommendations_for_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Рекомендации на основе уязвимостей"""
        recommendations = []
        
        # Группировка по продуктам
        products_vulns = {}
        for vuln in vulnerabilities:
            product = vuln.get('product', 'Unknown')
            if product not in products_vulns:
                products_vulns[product] = []
            products_vulns[product].append(vuln)
        
        # Рекомендации для каждого продукта
        for product, vulns in products_vulns.items():
            high_priority = [v for v in vulns if v.get('priority') == 'High']
            
            if high_priority:
                # Находим максимальный CVSS для определения критичности
                max_cvss = max((v.get('cvss_score', 0) or 0 for v in high_priority))
                
                if max_cvss >= 9.0:
                    recommendations.append(
                        f"КРИТИЧНО: Немедленно обновить {product} до последней версии. "
                        f"Обнаружены критические уязвимости (CVSS >= 9.0)"
                    )
                elif max_cvss >= 7.0:
                    recommendations.append(
                        f"Высокий приоритет: Обновить {product} до последней версии. "
                        f"Обнаружены уязвимости высокого приоритета"
                    )
                else:
                    recommendations.append(
                        f"Рекомендуется обновить {product} для устранения обнаруженных уязвимостей"
                    )
        
        # Рекомендации по портам
        port_vulns = {}
        for vuln in vulnerabilities:
            port = vuln.get('port')
            if port:
                if port not in port_vulns:
                    port_vulns[port] = []
                port_vulns[port].append(vuln)
        
        for port, vulns in port_vulns.items():
            external_vulns = [v for v in vulns if v.get('is_external')]
            if external_vulns:
                recommendations.append(
                    f"Ограничить доступ к порту {port} извне или закрыть его, "
                    f"если он не используется. Обнаружены уязвимости на открытом порту"
                )
        
        return recommendations
    
    def _recommendations_for_ports(self, discovery: Dict[str, Any]) -> List[str]:
        """Рекомендации на основе открытых портов"""
        recommendations = []
        
        open_ports = discovery.get('open_ports', [])
        
        # Проверка критических портов
        critical_ports = {
            23: "Telnet - небезопасный протокол, рекомендуется отключить",
            3389: "RDP - убедитесь, что включён Network Level Authentication (NLA)",
            5985: "WinRM HTTP - рекомендуется использовать HTTPS (5986)",
            445: "SMB - проверьте настройки безопасности и доступность извне",
            135: "RPC - рекомендуется ограничить доступ",
            139: "NetBIOS - устаревший протокол, рекомендуется отключить"
        }
        
        for port_info in open_ports:
            port = port_info.get('port')
            if port in critical_ports:
                recommendations.append(f"Порт {port}: {critical_ports[port]}")
        
        # Проверка версий сервисов
        for port_info in open_ports:
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '')
            
            if not version:
                continue
            
            # Проверка устаревших версий
            if 'apache' in service and version:
                try:
                    major = int(version.split('.')[0])
                    if major < 2:
                        recommendations.append(
                            f"Apache версии {version} устарела. Рекомендуется обновить до версии 2.4+"
                        )
                except:
                    pass
            
            if 'iis' in service and version:
                try:
                    major = float(version)
                    if major < 10:
                        recommendations.append(
                            f"IIS версии {version} устарела. Рекомендуется обновить до версии 10.0+"
                        )
                except:
                    pass
        
        return recommendations
    
    def _recommendations_for_security_config(self, os_software: Dict[str, Any]) -> List[str]:
        """Рекомендации на основе конфигурации безопасности"""
        recommendations = []
        
        # Проверка учётных записей без пароля
        security_policies = os_software.get('security_policies', {})
        accounts_without_password = security_policies.get('accounts_without_password', [])
        if accounts_without_password:
            recommendations.append(
                f"Обнаружены учётные записи без пароля: {', '.join(accounts_without_password)}. "
                f"Рекомендуется установить пароли для всех учётных записей"
            )
        
        # Проверка общих папок
        shares = os_software.get('shares', [])
        if shares:
            public_shares = [s for s in shares if 'public' in s.get('name', '').lower() or 
                           'everyone' in s.get('description', '').lower()]
            if public_shares:
                recommendations.append(
                    f"Обнаружены публичные общие папки. Проверьте права доступа и ограничьте доступ, "
                    f"если это возможно"
                )
        
        # Проверка открытых админ-портов
        admin_ports = os_software.get('admin_ports', [])
        if admin_ports:
            port_list = ', '.join(str(p.get('port', '')) for p in admin_ports)
            recommendations.append(
                f"Обнаружены открытые административные порты: {port_list}. "
                f"Убедитесь, что доступ к ним ограничен"
            )
        
        return recommendations
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Приоритизация уязвимостей
        
        Args:
            vulnerabilities: Список уязвимостей
        
        Returns:
            Отсортированный список уязвимостей
        """
        # Группировка по типу доступа
        remote_vulns = [v for v in vulnerabilities if v.get('is_external')]
        local_vulns = [v for v in vulnerabilities if not v.get('is_external')]
        
        # Сортировка: сначала удалённые, затем локальные
        # Внутри каждой группы - по приоритету и CVSS
        def sort_key(v):
            priority_order = {'High': 0, 'Medium': 1, 'Low': 2}
            return (
                0 if v.get('is_external') else 1,  # Удалённые сначала
                priority_order.get(v.get('priority', 'Low'), 2),
                -(v.get('cvss_score') or 0)
            )
        
        return sorted(vulnerabilities, key=sort_key)
    
    def generate_summary(self, scan_data: Dict[str, Any]) -> str:
        """
        Генерация краткого резюме на русском языке
        
        Args:
            scan_data: Данные сканирования
        
        Returns:
            Текстовое резюме
        """
        lines = []
        
        scan_info = scan_data.get('scan_info', {})
        target = scan_info.get('target', 'N/A')
        
        lines.append(f"Результаты сканирования безопасности для {target}")
        lines.append("")
        
        # Статистика уязвимостей
        vulnerabilities = scan_data.get('vulnerabilities', [])
        if vulnerabilities:
            high = sum(1 for v in vulnerabilities if v.get('priority') == 'High')
            medium = sum(1 for v in vulnerabilities if v.get('priority') == 'Medium')
            low = sum(1 for v in vulnerabilities if v.get('priority') == 'Low')
            
            lines.append(f"Найдено уязвимостей:")
            lines.append(f"  - Высокий приоритет: {high}")
            lines.append(f"  - Средний приоритет: {medium}")
            lines.append(f"  - Низкий приоритет: {low}")
            lines.append(f"  - Всего: {len(vulnerabilities)}")
        else:
            lines.append("Уязвимости не обнаружены")
        
        lines.append("")
        
        # Статистика портов
        discovery = scan_data.get('discovery', {})
        if discovery:
            open_ports = discovery.get('open_ports', [])
            lines.append(f"Открытых портов: {len(open_ports)}")
        
        # Статистика ПО
        os_software = scan_data.get('os_software', {})
        if os_software:
            installed = os_software.get('installed_software', [])
            lines.append(f"Установлено программ: {len(installed)}")
        
        lines.append("")
        
        # Критичные рекомендации
        recommendations = scan_data.get('recommendations', [])
        if recommendations:
            critical = [r for r in recommendations if 'КРИТИЧНО' in r or 'критично' in r.lower()]
            if critical:
                lines.append("Критичные рекомендации:")
                for rec in critical[:3]:  # Первые 3
                    lines.append(f"  - {rec}")
        
        return "\n".join(lines)
