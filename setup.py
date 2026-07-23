from setuptools import setup, find_packages

setup(
    name="containerguard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1",
	"docker>=7.2.0",
        "rich>=13.0",
        "reportlab>=4.0",
    ],
    entry_points={
        "console_scripts": [
            "containerguard=containerguard.cli:cli",
        ],
    },
)
