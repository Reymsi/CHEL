# Cybersecurity Host Evaluation Logger (CHEL) - Сканер безопасности для Windows

CLI-приложение для сканирования безопасности Windows-хостов с обнаружением уязвимостей, анализом установленного ПО и генерацией отчётов.

## Возможности

- **Discovery**: Сканирование сети и открытых портов (TCP/UDP)
- **Fingerprint**: Определение сервисов и версий (banner grabbing, SMB, RDP, WinRM)
- **OS Software**: Сбор установленного ПО из реестра Windows, hotfixes, сервисов
- **Vuln Lookup**: Поиск уязвимостей в локальной базе CVE (NVD, Vulners)
- **Report**: Генерация отчётов
- **Updater**: Обновление базы данных уязвимостей из NVD/Vulners
- **Assistant**: Типо ИИшки но фактически просто шаблонизатор создаёт человеко-читаемые отчёты

## Требования

- Python 3.8+
- Windows 10+ (для модулей os_software требуется запуск с правами администратора)
- nmap (должен быть установлен и доступен в PATH)
- Права администратора (для локального сканирования Windows)

## Установка

1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd Project_Scaner
```

2. Создайте виртуальное окружение:
```bash
python -m venv venv
venv\Scripts\activate
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

4. Установите nmap (если ещё не установлен):
   - Скачайте с https://nmap.org/download.html
   - Добавьте в PATH

5. Инициализируйте базу данных уязвимостей:
```bash
python -m chel update-db
```

## Использование

### Сканирование хоста

```bash
# Быстрое сканирование портов и ПО
python -m chel scan --target 192.168.56.101 --modules discovery,fingerprint,os_software --output report.json

# Только сетевые модули (без прав админа)
python -m chel scan --target 192.168.56.101 --modules discovery,fingerprint --output scan.json

# Все модули
python -m chel scan --target 192.168.56.101 --modules all --output full_report.json
```

### Обновление базы данных

```bash
# Обновить базу уязвимостей
python -m chel update-db

# Принудительное обновление
python -m chel update-db --force
```
# Проверьте количество уязвимостей
python -c "from chel.database import VulnDatabase; print('Уязвимостей:', VulnDatabase().get_vuln_count())"
```

**Примечание**: Первое обновление может занять много времени, так как загружаются все CVE за последние 5 лет. Если обновление не работает или вы хотите протестировать с примерами, используйте скрипт для добавления тестовых данных (см. ниже).

### Генерация отчёта

```bash
# JSON формат
python -m chel report --input report.json --format json

# Текстовый формат
python -m chel report --input report.json --format text

# HTML формат
python -m chel report --input report.json --format html
```

## Структура проекта

```
chel/
├── chel/                    # Основной пакет
│   ├── __init__.py
│   ├── __main__.py          # Точка входа CLI
│   ├── scanner.py           # Главный класс Scanner
│   ├── discovery.py         # Сканирование сети/портов
│   ├── fingerprint.py       # Определение сервисов и версий
│   ├── os_software.py       # Сбор ПО на Windows
│   ├── vuln_lookup.py       # Поиск уязвимостей в БД
│   ├── report.py            # Генерация отчётов
│   ├── updater.py           # Обновление БД уязвимостей
│   ├── assistant.py         # ИИ-помощник (базовый)
│   ├── database.py          # Работа с SQLite БД
│   ├── utils.py             # Вспомогательные функции
│   └── config.py            # Конфигурация
├── db/                      # База данных
│   └── chel_vulns.sqlite    # SQLite БД уязвимостей
└── tests/                   # Тесты
```

## Создание тестовой VM

Для тестирования рекомендуется использовать Windows 10 VM:

1. Создайте виртуальную машину (VirtualBox/VMware)
2. Установите Windows 10
3. Настройте сеть (NAT или Host-only adapter)
4. Установите Python и зависимости
5. Запустите сканер с правами администратора

## Сборка в исполняемый файл (EXE)

Для создания standalone исполняемого файла используйте PyInstaller:

1. Установите PyInstaller:
```bash
pip install pyinstaller
```

2. Соберите exe файл:
```bash
pyinstaller chel.spec
```

Или используйте команду напрямую:
```bash
pyinstaller --name chel --onefile --console chel/__main__.py
```

3. Исполняемый файл будет создан в директории `dist/chel.exe`

4. **Важно**: Для работы модуля `os_software` запускайте `chel.exe` с правами администратора:
   - Правый клик на `chel.exe` → "Запуск от имени администратора"

## Ручное добавление уязвимостей

Если база данных пуста или вы хотите добавить уязвимости вручную:

### Интерактивное добавление

```bash
python -m chel.add_vuln_manual
```

Скрипт попросит ввести:
- CVE ID
- CPE (опционально)
- Описание
- CVSS Score
- Уязвимые версии
- Ссылки
- Дату публикации

### Добавление примеров для тестирования

```bash
python -m chel.add_vuln_manual --examples
```


Это добавит несколько известных уязвимостей (Log4j, EternalBlue, Zerologon) для тестирования.


```bash
# С API ключом (если есть)
python -m chel update-db --api-key YOUR_KEY

1. Получите бесплатный API ключ:
   - Перейдите на https://nvd.nist.gov/developers/request-an-api-key
   - Заполните форму и получите ключ

### Программное добавление

Вы также можете добавить уязвимости программно:

```python
from chel.database import VulnDatabase

db = VulnDatabase()
db.insert_vuln(
    cve_id='CVE-2023-1234',
    cpe='cpe:2.3:a:vendor:product:1.0',
    summary='Описание уязвимости',
    cvss_score=7.5,
    affected_versions=['<1.1.0'],
    references=['https://example.com/cve-2023-1234'],
    source='manual'
)
```

## Ограничения

- Модуль `os_software` требует прав администратора на целевом хосте
- Некоторые проверки (SMB enumeration) могут детектироваться EDR
- Первое обновление БД может занять значительное время (загрузка всех CVE)
- Nmap должен быть установлен отдельно (даже при использовании exe)
- При использовании exe файла, nmap должен быть доступен в системном PATH

## Лицензия

[тут могла быть ваша реклама]

## Автор

[В.E.С.]
