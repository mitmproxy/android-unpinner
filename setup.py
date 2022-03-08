import re
from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

long_description = (here / "README.md").read_text("utf8")

VERSION = re.search(
    r'__version__ = "(.+?)"', (here / "android_unpinner" / "__init__.py").read_text("utf8")
).group(1)

setup(
    name="android-unpinner",
    author="Maximilian Hils",
    author_email="android-unpinner@maximilianhils.com",
    version=VERSION,
    license="MIT",
    description="Android Certificate Pinning Unpinner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mitmproxy/android-unpinner",
    project_urls={
        "Source": "https://github.com/mitmproxy/android-unpinner",
        "Documentation": "https://github.com/mitmproxy/android-unpinner",
        "Issues": "https://github.com/mitmproxy/android-unpinner/issues",
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Testing",
        "Typing :: Typed",
    ],
    packages=find_packages(
        include=[
            "android_unpinner",
            "android_unpinner.*",
        ]
    ),
    include_package_data=True,
    entry_points={"console_scripts": [
        "android-unpinner = android_unpinner.__main__:cli",
        "aup = android_unpinner.__main__:cli",
    ]},
    python_requires=">=3.10",
    install_requires=[
        "rich_click",
    ],
)
