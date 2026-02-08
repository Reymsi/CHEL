"""
Модуль генерации отчётов
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Template

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Класс для генерации отчётов"""
    
    def __init__(self):
        pass
    
    def generate_json(self, scan_data: Dict[str, Any]) -> str:
        """Генерация JSON отчёта"""
        return json.dumps(scan_data, ensure_ascii=False, indent=2)
    
    def generate_text(self, scan_data: Dict[str, Any]) -> str:
        """Генерация текстового отчёта"""
        lines = []
        
        # Заголовок
        lines.append("=" * 80)
        lines.append("ОТЧЁТ О СКАНИРОВАНИИ БЕЗОПАСНОСТИ")
        lines.append("=" * 80)
        lines.append("")
        
        # Информация о сканировании
        scan_info = scan_data.get('scan_info', {})
        lines.append(f"Целевой хост: {scan_info.get('target', 'N/A')}")
        lines.append(f"Дата сканирования: {scan_info.get('timestamp', 'N/A')}")
        lines.append(f"Модули: {', '.join(scan_info.get('modules', []))}")
        lines.append("")
        
        # Discovery результаты
        if 'discovery' in scan_data:
            discovery = scan_data['discovery']
            lines.append("-" * 80)
            lines.append("ОТКРЫТЫЕ ПОРТЫ")
            lines.append("-" * 80)
            
            open_ports = discovery.get('open_ports', [])
            if open_ports:
                for port_info in open_ports:
                    port = port_info.get('port', 'N/A')
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    product = port_info.get('product', '')
                    
                    line = f"  Порт {port}/{port_info.get('protocol', 'tcp')}: {service}"
                    if version:
                        line += f" версия {version}"
                    if product:
                        line += f" ({product})"
                    lines.append(line)
            else:
                lines.append("  Открытых портов не найдено")
            lines.append("")
        
        # Fingerprint результаты
        if 'fingerprint' in scan_data:
            fingerprint = scan_data['fingerprint']
            lines.append("-" * 80)
            lines.append("ОПРЕДЕЛЁННЫЕ СЕРВИСЫ")
            lines.append("-" * 80)
            
            banners = fingerprint.get('banners', [])
            if banners:
                for banner_info in banners:
                    port = banner_info.get('port', 'N/A')
                    product = banner_info.get('product', 'N/A')
                    version = banner_info.get('version', 'N/A')
                    lines.append(f"  {product} {version} на порту {port}")
            else:
                lines.append("  Сервисы не определены")
            lines.append("")
        
        # OS Software результаты
        if 'os_software' in scan_data:
            os_software = scan_data['os_software']
            lines.append("-" * 80)
            lines.append("УСТАНОВЛЕННОЕ ПО")
            lines.append("-" * 80)
            
            installed_software = os_software.get('installed_software', [])
            if installed_software:
                lines.append(f"  Всего установлено: {len(installed_software)} программ")
                # Показываем первые 10
                for software in installed_software[:10]:
                    name = software.get('name', 'N/A')
                    ver = software.get('version', 'N/A')
                    lines.append(f"    - {name} {ver}")
                if len(installed_software) > 10:
                    lines.append(f"    ... и ещё {len(installed_software) - 10}")
            else:
                lines.append("  Информация о ПО не собрана")
            lines.append("")
        
        # Уязвимости
        if 'vulnerabilities' in scan_data:
            vulnerabilities = scan_data['vulnerabilities']
            lines.append("=" * 80)
            lines.append("НАЙДЕННЫЕ УЯЗВИМОСТИ")
            lines.append("=" * 80)
            lines.append("")
            
            if vulnerabilities:
                # Группировка по приоритету
                high_vulns = [v for v in vulnerabilities if v.get('priority') == 'High']
                medium_vulns = [v for v in vulnerabilities if v.get('priority') == 'Medium']
                low_vulns = [v for v in vulnerabilities if v.get('priority') == 'Low']
                
                # Высокий приоритет
                if high_vulns:
                    lines.append("ВЫСОКИЙ ПРИОРИТЕТ:")
                    lines.append("-" * 80)
                    for vuln in high_vulns:
                        lines.append(f"  [{vuln.get('cve_id', 'N/A')}] {vuln.get('product', 'N/A')} {vuln.get('version', 'N/A')}")
                        lines.append(f"    CVSS: {vuln.get('cvss_score', 'N/A')}")
                        lines.append(f"    Описание: {vuln.get('summary', 'N/A')[:100]}...")
                        if vuln.get('port'):
                            lines.append(f"    Порт: {vuln.get('port')}")
                        lines.append("")
                
                # Средний приоритет
                if medium_vulns:
                    lines.append("СРЕДНИЙ ПРИОРИТЕТ:")
                    lines.append("-" * 80)
                    for vuln in medium_vulns[:10]:  # Ограничиваем вывод
                        lines.append(f"  [{vuln.get('cve_id', 'N/A')}] {vuln.get('product', 'N/A')} {vuln.get('version', 'N/A')}")
                        lines.append(f"    CVSS: {vuln.get('cvss_score', 'N/A')}")
                        lines.append("")
                
                # Низкий приоритет
                if low_vulns:
                    lines.append(f"НИЗКИЙ ПРИОРИТЕТ: {len(low_vulns)} уязвимостей")
                    lines.append("")
                
                # Статистика
                lines.append("-" * 80)
                lines.append("СТАТИСТИКА:")
                lines.append(f"  Высокий приоритет: {len(high_vulns)}")
                lines.append(f"  Средний приоритет: {len(medium_vulns)}")
                lines.append(f"  Низкий приоритет: {len(low_vulns)}")
                lines.append(f"  Всего: {len(vulnerabilities)}")
            else:
                lines.append("Уязвимости не найдены")
            lines.append("")
        
        # Рекомендации
        if 'recommendations' in scan_data:
            recommendations = scan_data.get('recommendations', [])
            if recommendations:
                lines.append("=" * 80)
                lines.append("РЕКОМЕНДАЦИИ")
                lines.append("=" * 80)
                lines.append("")
                for i, rec in enumerate(recommendations, 1):
                    lines.append(f"{i}. {rec}")
                lines.append("")
        
        # Итог
        lines.append("=" * 80)
        lines.append(f"Отчёт сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def generate_html(self, scan_data: Dict[str, Any]) -> str:
        """Генерация HTML отчёта"""
        template_str = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт о сканировании безопасности</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        .info {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .info p {
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .priority-high {
            background-color: #ffebee;
            color: #c62828;
            font-weight: bold;
        }
        .priority-medium {
            background-color: #fff3e0;
            color: #e65100;
        }
        .priority-low {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
        }
        .stat-box {
            text-align: center;
            padding: 20px;
            border-radius: 5px;
            background-color: #f5f5f5;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #4CAF50;
        }
        .stat-label {
            color: #666;
            margin-top: 10px;
        }
        .recommendations {
            background-color: #fff9c4;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчёт о сканировании безопасности</h1>
        
        <div class="info">
            <p><strong>Целевой хост:</strong> {{ scan_info.target }}</p>
            <p><strong>Дата сканирования:</strong> {{ scan_info.timestamp }}</p>
            <p><strong>Модули:</strong> {{ ', '.join(scan_info.modules) }}</p>
        </div>
        
        {% if vulnerabilities %}
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{{ high_count }}</div>
                <div class="stat-label">Высокий приоритет</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ medium_count }}</div>
                <div class="stat-label">Средний приоритет</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ low_count }}</div>
                <div class="stat-label">Низкий приоритет</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ total_count }}</div>
                <div class="stat-label">Всего</div>
            </div>
        </div>
        
        <h2>Уязвимости</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Продукт</th>
                    <th>Версия</th>
                    <th>CVSS</th>
                    <th>Приоритет</th>
                    <th>Описание</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulnerabilities %}
                <tr class="priority-{{ vuln.priority.lower() }}">
                    <td><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ vuln.cve_id }}" target="_blank">{{ vuln.cve_id }}</a></td>
                    <td>{{ vuln.product }}</td>
                    <td>{{ vuln.version or 'N/A' }}</td>
                    <td>{{ vuln.cvss_score or 'N/A' }}</td>
                    <td>{{ vuln.priority }}</td>
                    <td>{{ vuln.summary[:100] }}{% if vuln.summary|length > 100 %}...{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="info">
            <p>Уязвимости не найдены</p>
        </div>
        {% endif %}
        
        {% if discovery and discovery.open_ports %}
        <h2>Открытые порты</h2>
        <table>
            <thead>
                <tr>
                    <th>Порт</th>
                    <th>Протокол</th>
                    <th>Сервис</th>
                    <th>Версия</th>
                    <th>Продукт</th>
                </tr>
            </thead>
            <tbody>
                {% for port in discovery.open_ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version or 'N/A' }}</td>
                    <td>{{ port.product or 'N/A' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
        
        {% if recommendations %}
        <h2>Рекомендации</h2>
        <div class="recommendations">
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Отчёт сгенерирован: {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        
        # Подготовка данных
        scan_info = scan_data.get('scan_info', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        high_count = sum(1 for v in vulnerabilities if v.get('priority') == 'High')
        medium_count = sum(1 for v in vulnerabilities if v.get('priority') == 'Medium')
        low_count = sum(1 for v in vulnerabilities if v.get('priority') == 'Low')
        total_count = len(vulnerabilities)
        
        return template.render(
            scan_info=scan_info,
            vulnerabilities=vulnerabilities,
            discovery=scan_data.get('discovery'),
            recommendations=scan_data.get('recommendations', []),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_count=total_count,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
