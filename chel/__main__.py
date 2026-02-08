"""
Точка входа CLI приложения CHEL
"""
import click
import json
import sys
from pathlib import Path

from chel.utils import is_admin, normalize_ip, parse_modules
from chel.scanner import Scanner
from chel.updater import VulnUpdater
from chel.report import ReportGenerator


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """CHEL - Сканер безопасности для Windows"""
    pass


@cli.command()
@click.option('--target', '-t', required=True, help='IP-адрес или хост для сканирования')
@click.option('--modules', '-m', default='all', 
              help='Список модулей через запятую (discovery, fingerprint, os_software, vuln_lookup) или "all"')
@click.option('--output', '-o', default='scan_result.json', 
              help='Путь к файлу для сохранения результатов')
@click.option('--verbose', '-v', is_flag=True, help='Подробный вывод')
def scan(target, modules, output, verbose):
    """Сканирование хоста на уязвимости"""
    # Валидация IP
    ip = normalize_ip(target)
    if not ip:
        click.echo(f"Ошибка: некорректный IP-адрес: {target}", err=True)
        sys.exit(1)
    
    # Парсинг модулей
    module_list = parse_modules(modules)
    
    # Проверка прав администратора для os_software
    if 'os_software' in module_list and not is_admin():
        click.echo("Предупреждение: модуль os_software требует прав администратора", err=True)
        click.echo("Продолжаю без модуля os_software...", err=True)
        module_list = [m for m in module_list if m != 'os_software']
    
    click.echo(f"Начинаю сканирование {ip}...")
    click.echo(f"Модули: {', '.join(module_list)}")
    
    try:
        scanner = Scanner(verbose=verbose)
        results = scanner.scan(target=ip, modules=module_list)
        
        # Сохранение результатов
        output_path = Path(output)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        click.echo(f"\nРезультаты сохранены в {output_path}")
        
        # Краткая статистика
        if 'vulnerabilities' in results:
            vulns = results['vulnerabilities']
            high = sum(1 for v in vulns if v.get('priority') == 'High')
            medium = sum(1 for v in vulns if v.get('priority') == 'Medium')
            low = sum(1 for v in vulns if v.get('priority') == 'Low')
            
            click.echo(f"\nНайдено уязвимостей:")
            click.echo(f"  Высокий приоритет: {high}")
            click.echo(f"  Средний приоритет: {medium}")
            click.echo(f"  Низкий приоритет: {low}")
        
    except Exception as e:
        click.echo(f"Ошибка при сканировании: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--force', '-f', is_flag=True, 
              help='Принудительное обновление (игнорировать метаданные)')
@click.option('--verbose', '-v', is_flag=True, help='Подробный вывод')
@click.option('--api-key', help='NVD API ключ (получите на https://nvd.nist.gov/developers/request-an-api-key)')
def update_db(force, verbose, api_key):
    """Обновление базы данных уязвимостей"""
    click.echo("Обновление базы данных уязвимостей...")
    
    if not api_key:
        click.echo("Примечание: Без API ключа NVD может блокировать запросы (403 Forbidden)")
        click.echo("Получите бесплатный API ключ: https://nvd.nist.gov/developers/request-an-api-key")
        click.echo("Используйте: python -m chel update-db --api-key YOUR_KEY\n")
    
    try:
        updater = VulnUpdater(verbose=verbose, api_key=api_key)
        
        if force:
            click.echo("Принудительное обновление...")
        
        updater.update_all(force=force)
        
        click.echo("\nБаза данных успешно обновлена!")
        
    except Exception as e:
        click.echo(f"Ошибка при обновлении БД: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--input', '-i', required=True, 
              help='Путь к JSON файлу с результатами сканирования')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'html'], case_sensitive=False),
              default='text', help='Формат отчёта')
@click.option('--output', '-o', help='Путь для сохранения отчёта (по умолчанию: input.{format})')
def report(input, format, output):
    """Генерация отчёта из результатов сканирования"""
    input_path = Path(input)
    if not input_path.exists():
        click.echo(f"Ошибка: файл не найден: {input_path}", err=True)
        sys.exit(1)
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f"Ошибка: некорректный JSON: {e}", err=True)
        sys.exit(1)
    
    # Определение пути вывода
    if output:
        output_path = Path(output)
    else:
        output_path = input_path.with_suffix(f'.{format.lower()}')
    
    click.echo(f"Генерация {format.upper()} отчёта...")
    
    try:
        generator = ReportGenerator()
        
        if format.lower() == 'json':
            content = generator.generate_json(scan_data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        elif format.lower() == 'text':
            content = generator.generate_text(scan_data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        elif format.lower() == 'html':
            content = generator.generate_html(scan_data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        click.echo(f"Отчёт сохранён: {output_path}")
        
    except Exception as e:
        click.echo(f"Ошибка при генерации отчёта: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    cli()
