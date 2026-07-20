"""setup.py fallback for old pip (< 10) that cannot build from
pyproject.toml -- e.g. pip 9.0.3 on Python 3.6 (RHEL/CentOS 7 era)."""
from setuptools import setup, find_packages

setup(
    name="wavescope",
    version="0.13.0",
    description=("Extract PC/clock from RTL waveforms and generate "
                 "callgrind profiles using ELF debug symbols"),
    python_requires=">=3.6",
    packages=find_packages(include=["wavescope*"]),
    package_data={"wavescope": ["isa/*.json"]},
    entry_points={"console_scripts": ["wavescope=wavescope.cli:main"]},
)
