from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="sentient-ai",
    version="1.0.0",
    author="x0as",
    author_email="muhammadhuzaifakhalidaziz@gmail.com",
    description="AI-powered cybersecurity and automation toolkit",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/x0as/Sentient",
    project_urls={
        "Bug Reports": "https://github.com/x0as/Sentient/issues",
        "Source": "https://github.com/x0as/Sentient",
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.25.1",
        "google-generativeai>=0.3.0",
        "pymongo>=4.0.0",
        "beautifulsoup4>=4.9.3",
        "tabulate>=0.8.9",
        "fuzzywuzzy>=0.18.0",
        "python-Levenshtein>=0.12.2",
        "dnspython>=2.1.0",
        "python-whois>=0.7.3",
        "cryptography>=3.4.8",
        "scapy>=2.4.5",
        "colorama>=0.4.4",
        "google-search-results>=2.4.0",
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "whois>=0.9.13",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentient=sentient.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    keywords="cybersecurity, automation, ai, hacking, penetration-testing, osint",
)