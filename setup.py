"""
Setup script for CHEL scanner
"""
from setuptools import setup, find_packages
from pathlib import Path

# Чтение README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ""

setup(
    name="chel-scanner",
    version="0.1.0",
    description="CLI-приложение для сканирования безопасности Windows-хостов",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="BEC",
    author_email="janevas2007@gmail.com",
    url="https://github.com/Reymsi/CHEL",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "python-nmap>=0.7.1",
        "impacket>=0.11.0",
        "requests>=2.31.0",
        "pefile>=2023.2.7",
        "psutil>=5.9.0",
        "packaging>=23.0",
        "rapidfuzz>=3.0.0",
        "jinja2>=3.1.2",
    ],
    extras_require={
        "windows": ["pywin32>=306"],
    },
    entry_points={
        "console_scripts": [
            "chel=chel.__main__:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: Microsoft :: Windows",
    ],
)
