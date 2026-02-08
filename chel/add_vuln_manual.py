"""
Скрипт для ручного добавления уязвимостей в базу данных
"""
import sys
from chel.database import VulnDatabase

def add_vuln_manual():
    """Интерактивное добавление уязвимости"""
    db = VulnDatabase()
    
    print("=== Добавление уязвимости в базу данных ===\n")
    
    # Ввод данных
    cve_id = input("CVE ID (например, CVE-2023-1234): ").strip()
    if not cve_id:
        print("Ошибка: CVE ID обязателен")
        return
    
    cpe = input("CPE (опционально, например, cpe:2.3:a:apache:http_server:2.4.41): ").strip() or None
    
    summary = input("Описание уязвимости: ").strip() or None
    
    cvss_str = input("CVSS Score (опционально, например, 7.5): ").strip()
    cvss_score = float(cvss_str) if cvss_str else None
    
    cvss_vector = input("CVSS Vector (опционально): ").strip() or None
    
    affected_versions_str = input("Уязвимые версии через запятую (опционально, например, <2.4.50,>=2.4.0): ").strip()
    affected_versions = [v.strip() for v in affected_versions_str.split(',')] if affected_versions_str else None
    
    references_str = input("Ссылки через запятую (опционально): ").strip()
    references = [r.strip() for r in references_str.split(',')] if references_str else None
    
    published_date = input("Дата публикации (опционально, формат YYYY-MM-DD): ").strip() or None
    
    source = input("Источник (по умолчанию 'manual'): ").strip() or "manual"
    
    # Добавление в БД
    success = db.insert_vuln(
        cve_id=cve_id,
        cpe=cpe,
        summary=summary,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        affected_versions=affected_versions,
        references=references,
        published_date=published_date,
        source=source
    )
    
    if success:
        print(f"\n[OK] Уязвимость {cve_id} успешно добавлена в базу данных!")
    else:
        print(f"\n[ERROR] Ошибка при добавлении уязвимости {cve_id}")


def add_example_vulns():
    """Добавление примеров уязвимостей для тестирования"""
    db = VulnDatabase()
    
    examples = [
        {
            'cve_id': 'CVE-2021-44228',
            'cpe': 'cpe:2.3:a:apache:log4j:2.14.1',
            'summary': 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints',
            'cvss_score': 10.0,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'affected_versions': ['>=2.0.0', '<2.15.0'],
            'references': [
                'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
                'https://logging.apache.org/log4j/2.x/security.html'
            ],
            'published_date': '2021-12-10',
            'source': 'nvd'
        },
        {
            'cve_id': 'CVE-2017-0144',
            'cpe': 'cpe:2.3:o:microsoft:windows:*:*:*:*:*',
            'summary': 'Windows SMB Remote Code Execution Vulnerability',
            'cvss_score': 9.3,
            'cvss_vector': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H',
            'affected_versions': ['Windows 7', 'Windows Server 2008'],
            'references': [
                'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
                'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144'
            ],
            'published_date': '2017-03-14',
            'source': 'nvd'
        },
        {
            'cve_id': 'CVE-2020-1472',
            'cpe': 'cpe:2.3:a:microsoft:windows:*:*:*:*:*',
            'summary': 'Netlogon Elevation of Privilege Vulnerability',
            'cvss_score': 10.0,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'affected_versions': ['Windows Server 2016', 'Windows Server 2019'],
            'references': [
                'https://nvd.nist.gov/vuln/detail/CVE-2020-1472'
            ],
            'published_date': '2020-08-17',
            'source': 'nvd'
        }
    ]
    
    print("Добавление примеров уязвимостей...")
    for vuln in examples:
        success = db.insert_vuln(**vuln)
        if success:
            print(f"[OK] Добавлена {vuln['cve_id']}")
        else:
            print(f"[ERROR] Ошибка при добавлении {vuln['cve_id']}")
    
    print(f"\nВсего уязвимостей в БД: {db.get_vuln_count()}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--examples':
        add_example_vulns()
    else:
        add_vuln_manual()
