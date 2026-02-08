"""
Модуль определения сервисов и версий (fingerprinting)
"""
import socket
import ssl
import re
import logging
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from chel.config import BANNER_TIMEOUT

logger = logging.getLogger(__name__)


class BannerGrabber:
    """Класс для получения баннеров сервисов"""
    
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
    
    def grab_banner(self, host: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        """
        Получение баннера сервиса
        
        Args:
            host: IP-адрес или хост
            port: Порт
            protocol: Протокол (tcp/udp)
        """
        result = {
            'host': host,
            'port': port,
            'protocol': protocol,
            'banner': None,
            'version': None,
            'product': None,
            'error': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(BANNER_TIMEOUT)
            
            sock.connect((host, port))
            
            # Попытка получить баннер в зависимости от порта
            if port == 80:
                result = self._grab_http_banner(sock, host, port)
            elif port == 443:
                result = self._grab_https_banner(sock, host, port)
            elif port == 21:
                result = self._grab_ftp_banner(sock, host, port)
            elif port == 22:
                result = self._grab_ssh_banner(sock, host, port)
            elif port == 25:
                result = self._grab_smtp_banner(sock, host, port)
            elif port in [1433, 3306, 5432]:
                result = self._grab_db_banner(sock, host, port)
            else:
                # Общий метод для других портов
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    result['banner'] = banner.strip()
                    result['version'] = self._extract_version(banner)
                except:
                    pass
            
            sock.close()
            
        except socket.timeout:
            result['error'] = 'timeout'
        except ConnectionRefusedError:
            result['error'] = 'connection_refused'
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Ошибка при получении баннера {host}:{port}: {e}", "warning")
        
        return result
    
    def _grab_http_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение HTTP баннера"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None,
            'server_header': None
        }
        
        try:
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            result['banner'] = response[:500]  # Первые 500 символов
            
            # Извлечение Server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
            if server_match:
                server_header = server_match.group(1)
                result['server_header'] = server_header
                
                # Определение продукта и версии
                if 'Apache' in server_header:
                    result['product'] = 'Apache'
                    version = re.search(r'Apache[/\s](\d+\.\d+(?:\.\d+)?)', server_header)
                    if version:
                        result['version'] = version.group(1)
                elif 'IIS' in server_header or 'Microsoft-IIS' in server_header:
                    result['product'] = 'IIS'
                    version = re.search(r'IIS[/\s](\d+\.\d+)', server_header)
                    if version:
                        result['version'] = version.group(1)
                elif 'nginx' in server_header.lower():
                    result['product'] = 'nginx'
                    version = re.search(r'nginx[/\s](\d+\.\d+(?:\.\d+)?)', server_header, re.IGNORECASE)
                    if version:
                        result['version'] = version.group(1)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _grab_https_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение HTTPS баннера с SSL/TLS"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None,
            'ssl_version': None,
            'cipher': None
        }
        
        try:
            # Обёртка SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            
            # Получение SSL информации
            result['ssl_version'] = ssl_sock.version()
            result['cipher'] = ssl_sock.cipher()[0] if ssl_sock.cipher() else None
            
            # HTTP запрос через SSL
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            ssl_sock.send(request.encode())
            response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
            
            result['banner'] = response[:500]
            
            # Извлечение Server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
            if server_match:
                server_header = server_match.group(1)
                if 'Apache' in server_header:
                    result['product'] = 'Apache'
                elif 'IIS' in server_header or 'Microsoft-IIS' in server_header:
                    result['product'] = 'IIS'
                elif 'nginx' in server_header.lower():
                    result['product'] = 'nginx'
                
                version = re.search(r'(\d+\.\d+(?:\.\d+)?)', server_header)
                if version:
                    result['version'] = version.group(1)
            
            ssl_sock.close()
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _grab_ftp_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение FTP баннера"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None
        }
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['banner'] = banner.strip()
            
            # Извлечение версии FTP сервера
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
            if version_match:
                result['version'] = version_match.group(1)
            
            if 'FileZilla' in banner:
                result['product'] = 'FileZilla Server'
            elif 'vsftpd' in banner:
                result['product'] = 'vsftpd'
            elif 'Microsoft FTP' in banner:
                result['product'] = 'Microsoft FTP Service'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _grab_ssh_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение SSH баннера"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None
        }
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['banner'] = banner.strip()
            
            # SSH баннер обычно в формате: SSH-2.0-OpenSSH_7.4
            ssh_match = re.search(r'SSH-(\d+\.\d+)-([^\s]+)', banner)
            if ssh_match:
                result['version'] = ssh_match.group(1)
                product_str = ssh_match.group(2)
                
                if 'OpenSSH' in product_str:
                    result['product'] = 'OpenSSH'
                    version_match = re.search(r'OpenSSH[_-](\d+\.\d+(?:\.\d+)?)', product_str)
                    if version_match:
                        result['version'] = version_match.group(1)
                elif 'Microsoft' in product_str:
                    result['product'] = 'Microsoft SSH'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _grab_smtp_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение SMTP баннера"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None
        }
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['banner'] = banner.strip()
            
            # Извлечение версии
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
            if version_match:
                result['version'] = version_match.group(1)
            
            if 'Microsoft' in banner or 'Exchange' in banner:
                result['product'] = 'Microsoft Exchange'
            elif 'Postfix' in banner:
                result['product'] = 'Postfix'
            elif 'Sendmail' in banner:
                result['product'] = 'Sendmail'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _grab_db_banner(self, sock: socket.socket, host: str, port: int) -> Dict[str, Any]:
        """Получение баннера БД (MS-SQL, MySQL, PostgreSQL)"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'banner': None,
            'version': None,
            'product': None
        }
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['banner'] = banner.strip()
            
            if port == 1433:
                result['product'] = 'Microsoft SQL Server'
            elif port == 3306:
                result['product'] = 'MySQL'
            elif port == 5432:
                result['product'] = 'PostgreSQL'
            
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
            if version_match:
                result['version'] = version_match.group(1)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_version(self, text: str) -> Optional[str]:
        """Извлечение версии из текста"""
        patterns = [
            r'v?(\d+\.\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        
        return None
    
    def detect_ssl_tls(self, host: str, port: int) -> Dict[str, Any]:
        """Определение версии SSL/TLS и cipher suites"""
        result = {
            'host': host,
            'port': port,
            'ssl_version': None,
            'cipher': None,
            'supported_versions': [],
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(BANNER_TIMEOUT)
            sock.connect((host, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            
            result['ssl_version'] = ssl_sock.version()
            if ssl_sock.cipher():
                result['cipher'] = ssl_sock.cipher()[0]
            
            ssl_sock.close()
        
        except Exception as e:
            result['error'] = str(e)
        
        return result


class SpecializedScanner:
    """Класс для специализированных проверок (SMB, RDP, WinRM)"""
    
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
    
    def scan_smb(self, host: str, port: int = 445) -> Dict[str, Any]:
        """Сканирование SMB (порт 445)"""
        result = {
            'host': host,
            'port': port,
            'smb_version': None,
            'os_version': None,
            'shares': [],
            'anonymous_access': False,
            'error': None
        }
        
        try:
            from impacket.smbconnection import SMBConnection
            
            smb = SMBConnection(host, host)
            
            # Попытка анонимного подключения
            try:
                smb.login('', '')
                result['anonymous_access'] = True
            except:
                result['anonymous_access'] = False
            
            # Получение информации о версии
            result['smb_version'] = smb.getDialect()
            result['os_version'] = smb.getServerOS()
            
            # Перечисление шар (требует аутентификации)
            if result['anonymous_access']:
                try:
                    shares = smb.listShares()
                    result['shares'] = [share['shi1_netname'] for share in shares]
                except:
                    pass
            
            smb.close()
        
        except ImportError:
            result['error'] = 'impacket not available'
            self._log("impacket не установлен, пропуск SMB сканирования", "warning")
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Ошибка при SMB сканировании {host}: {e}", "warning")
        
        return result
    
    def scan_rdp(self, host: str, port: int = 3389) -> Dict[str, Any]:
        """Сканирование RDP (порт 3389)"""
        result = {
            'host': host,
            'port': port,
            'rdp_version': None,
            'nla_enabled': None,
            'encryption_level': None,
            'error': None
        }
        
        try:
            import nmap
            
            nm = nmap.PortScanner()
            # Использование nmap скрипта для RDP
            nm.scan(host, str(port), arguments='--script rdp-enum-encryption,rdp-ntlm-info')
            
            if host in nm.all_hosts():
                host_data = nm[host]
                if 'tcp' in host_data and port in host_data['tcp']:
                    port_data = host_data['tcp'][port]
                    if 'script' in port_data:
                        scripts = port_data['script']
                        if 'rdp-enum-encryption' in scripts:
                            result['encryption_level'] = scripts['rdp-enum-encryption']
                        if 'rdp-ntlm-info' in scripts:
                            result['nla_enabled'] = 'NLA' in scripts['rdp-ntlm-info']
        
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Ошибка при RDP сканировании {host}: {e}", "warning")
        
        return result
    
    def scan_winrm(self, host: str, port: int = 5985) -> Dict[str, Any]:
        """Сканирование WinRM (порты 5985/5986)"""
        result = {
            'host': host,
            'port': port,
            'winrm_version': None,
            'auth_methods': [],
            'error': None
        }
        
        try:
            if not REQUESTS_AVAILABLE:
                result['error'] = 'requests not available'
                return result
            
            url = f"http://{host}:{port}/wsman" if port == 5985 else f"https://{host}:{port}/wsman"
            
            # Попытка подключения
            response = requests.get(url, timeout=5, verify=False)
            
            if 'WWW-Authenticate' in response.headers:
                auth_header = response.headers['WWW-Authenticate']
                if 'Basic' in auth_header:
                    result['auth_methods'].append('Basic')
                if 'Negotiate' in auth_header:
                    result['auth_methods'].append('Negotiate')
                if 'Kerberos' in auth_header:
                    result['auth_methods'].append('Kerberos')
        
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Ошибка при WinRM сканировании {host}: {e}", "warning")
        
        return result
