"""
Модуль сбора информации о ПО и системе на Windows
"""
import logging
import subprocess
import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from chel.utils import normalize_product_name, extract_version

logger = logging.getLogger(__name__)


class WindowsInventory:
    """Класс для сбора информации о системе Windows"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        if not WINDOWS:
            logger.warning("Модуль os_software работает только на Windows")
    
    def _log(self, message: str, level: str = "info"):
        """Логирование с учётом verbose"""
        if self.verbose or level in ["warning", "error"]:
            if level == "info":
                logger.info(message)
            elif level == "warning":
                logger.warning(message)
            elif level == "error":
                logger.error(message)
    
    def get_installed_software(self) -> List[Dict[str, Any]]:
        """Сбор установленного ПО из реестра"""
        if not WINDOWS:
            return []
        
        software_list = []
        
        # Ключи реестра для установленного ПО
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        
        for hkey, path in registry_paths:
            try:
                key = winreg.OpenKey(hkey, path)
                self._enumerate_registry_key(key, software_list)
                winreg.CloseKey(key)
            except Exception as e:
                self._log(f"Ошибка при чтении реестра {path}: {e}", "warning")
        
        self._log(f"Найдено установленного ПО: {len(software_list)}")
        return software_list
    
    def _enumerate_registry_key(self, key: winreg.HKEYType, software_list: List[Dict[str, Any]]):
        """Перечисление ключей в ветке реестра"""
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                
                try:
                    software = self._read_software_info(subkey, subkey_name)
                    if software:
                        software_list.append(software)
                except Exception as e:
                    self._log(f"Ошибка при чтении информации о ПО {subkey_name}: {e}", "warning")
                finally:
                    winreg.CloseKey(subkey)
                
                i += 1
            except OSError:
                break
    
    def _read_software_info(self, key: winreg.HKEYType, subkey_name: str) -> Optional[Dict[str, Any]]:
        """Чтение информации о ПО из ключа реестра"""
        try:
            display_name = winreg.QueryValueEx(key, "DisplayName")[0]
            if not display_name:
                return None
            
            software = {
                'name': display_name,
                'normalized_name': normalize_product_name(display_name),
                'version': None,
                'publisher': None,
                'install_date': None,
                'uninstall_string': None,
                'registry_key': subkey_name
            }
            
            # Версия
            try:
                version = winreg.QueryValueEx(key, "DisplayVersion")[0]
                software['version'] = version
            except:
                pass
            
            # Издатель
            try:
                publisher = winreg.QueryValueEx(key, "Publisher")[0]
                software['publisher'] = publisher
            except:
                pass
            
            # Дата установки
            try:
                install_date = winreg.QueryValueEx(key, "InstallDate")[0]
                software['install_date'] = install_date
            except:
                pass
            
            # Строка удаления
            try:
                uninstall_string = winreg.QueryValueEx(key, "UninstallString")[0]
                software['uninstall_string'] = uninstall_string
            except:
                pass
            
            return software
        
        except Exception:
            return None
    
    def get_software_powershell(self) -> List[Dict[str, Any]]:
        """Сбор ПО через PowerShell Get-Package"""
        if not WINDOWS:
            return []
        
        software_list = []
        
        try:
            ps_command = "Get-Package | Select-Object Name, Version, ProviderName | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                if not isinstance(packages, list):
                    packages = [packages]
                
                for pkg in packages:
                    software_list.append({
                        'name': pkg.get('Name', ''),
                        'normalized_name': normalize_product_name(pkg.get('Name', '')),
                        'version': pkg.get('Version', ''),
                        'provider': pkg.get('ProviderName', '')
                    })
        
        except Exception as e:
            self._log(f"Ошибка при получении ПО через PowerShell: {e}", "warning")
        
        return software_list
    
    def get_hotfixes(self) -> List[Dict[str, Any]]:
        """Сбор установленных обновлений Windows (KB)"""
        if not WINDOWS:
            return []
        
        hotfixes = []
        
        try:
            # Использование wmic
            result = subprocess.run(
                ["wmic", "qfe", "get", "HotFixID,InstalledOn,Description", "/format:csv"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Пропускаем заголовок
                    if not line.strip():
                        continue
                    
                    parts = line.split(',')
                    if len(parts) >= 4:
                        hotfix_id = parts[-3].strip() if len(parts) >= 3 else ''
                        installed_on = parts[-2].strip() if len(parts) >= 2 else ''
                        description = parts[-1].strip() if len(parts) >= 1 else ''
                        
                        if hotfix_id.startswith('KB'):
                            hotfixes.append({
                                'hotfix_id': hotfix_id,
                                'installed_on': installed_on,
                                'description': description
                            })
        
        except Exception as e:
            self._log(f"Ошибка при получении hotfixes: {e}", "warning")
        
        # Альтернативный метод через PowerShell
        if not hotfixes:
            try:
                ps_command = "Get-HotFix | Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json"
                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    fixes = json.loads(result.stdout)
                    if not isinstance(fixes, list):
                        fixes = [fixes]
                    
                    for fix in fixes:
                        hotfixes.append({
                            'hotfix_id': fix.get('HotFixID', ''),
                            'installed_on': str(fix.get('InstalledOn', '')),
                            'description': fix.get('Description', '')
                        })
            except Exception as e:
                self._log(f"Ошибка при получении hotfixes через PowerShell: {e}", "warning")
        
        self._log(f"Найдено установленных обновлений: {len(hotfixes)}")
        return hotfixes
    
    def get_services(self) -> List[Dict[str, Any]]:
        """Сбор информации о сервисах Windows"""
        if not WINDOWS:
            return []
        
        services = []
        
        try:
            # Использование sc query
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Парсинг вывода sc query (формат специфичный)
            current_service = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current_service:
                        services.append(current_service)
                    current_service = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith('DISPLAY_NAME:'):
                    current_service['display_name'] = line.split(':', 1)[1].strip()
                elif line.startswith('STATE:'):
                    current_service['state'] = line.split(':', 1)[1].strip()
                elif line.startswith('BINARY_PATH_NAME:'):
                    path = line.split(':', 1)[1].strip()
                    current_service['binary_path'] = path
                    # Попытка получить версию из бинарника
                    if PEFILE_AVAILABLE and Path(path).exists():
                        try:
                            version = self._get_file_version(path)
                            if version:
                                current_service['version'] = version
                        except:
                            pass
            
            if current_service:
                services.append(current_service)
        
        except Exception as e:
            self._log(f"Ошибка при получении сервисов: {e}", "warning")
        
        self._log(f"Найдено сервисов: {len(services)}")
        return services
    
    def get_processes(self) -> List[Dict[str, Any]]:
        """Сбор информации о запущенных процессах"""
        if not PSUTIL_AVAILABLE:
            return []
        
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                    }
                    
                    # Получение версии из исполняемого файла
                    if proc_info['exe'] and PEFILE_AVAILABLE:
                        try:
                            version = self._get_file_version(proc_info['exe'])
                            if version:
                                process_data['version'] = version
                        except:
                            pass
                    
                    processes.append(process_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            self._log(f"Ошибка при получении процессов: {e}", "warning")
        
        self._log(f"Найдено процессов: {len(processes)}")
        return processes
    
    def _get_file_version(self, file_path: str) -> Optional[str]:
        """Получение версии из PE файла"""
        if not PEFILE_AVAILABLE:
            return None
        
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, 'VS_VERSIONINFO'):
                for fileinfo in pe.FileInfo:
                    for entry in fileinfo:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for str_entry in st.entries.items():
                                    if str_entry[0] == 'FileVersion':
                                        return str_entry[1].decode('utf-8', errors='ignore')
        except Exception:
            pass
        
        return None
    
    def check_security_policies(self) -> Dict[str, Any]:
        """Проверка политик безопасности"""
        if not WINDOWS:
            return {}
        
        policies = {
            'min_password_length': None,
            'password_complexity': None,
            'accounts_without_password': [],
            'error': None
        }
        
        try:
            # Проверка учётных записей без пароля
            ps_command = "Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false } | Select-Object Name | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                users = json.loads(result.stdout)
                if not isinstance(users, list):
                    users = [users]
                policies['accounts_without_password'] = [u.get('Name', '') for u in users if u.get('Name')]
        
        except Exception as e:
            policies['error'] = str(e)
            self._log(f"Ошибка при проверке политик безопасности: {e}", "warning")
        
        return policies
    
    def check_shares(self) -> List[Dict[str, Any]]:
        """Проверка общих папок (shares)"""
        if not WINDOWS:
            return []
        
        shares = []
        
        try:
            ps_command = "Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                share_list = json.loads(result.stdout)
                if not isinstance(share_list, list):
                    share_list = [share_list]
                
                for share in share_list:
                    shares.append({
                        'name': share.get('Name', ''),
                        'path': share.get('Path', ''),
                        'description': share.get('Description', '')
                    })
        
        except Exception as e:
            self._log(f"Ошибка при проверке shares: {e}", "warning")
        
        return shares
    
    def check_admin_ports(self) -> List[Dict[str, Any]]:
        """Проверка открытых админ-портов локально"""
        if not WINDOWS:
            return []
        
        admin_ports = []
        critical_ports = [23, 3389, 5985, 5986, 445, 135, 139]
        
        try:
            # Использование netstat
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'LISTENING' in line:
                        # Парсинг строки netstat
                        parts = line.split()
                        if len(parts) >= 2:
                            addr_port = parts[1]
                            if ':' in addr_port:
                                port = int(addr_port.split(':')[-1])
                                if port in critical_ports:
                                    admin_ports.append({
                                        'port': port,
                                        'state': 'LISTENING',
                                        'address': addr_port
                                    })
        
        except Exception as e:
            self._log(f"Ошибка при проверке админ-портов: {e}", "warning")
        
        return admin_ports
