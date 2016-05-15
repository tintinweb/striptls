#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="striptls",
    version="0.4",
    packages=["striptls"],
    author="tintinweb",
    author_email="tintinweb@oststrom.com",
    description=(
        "poc implementation of STARTTLS stripping attacks"),
    license="GPLv2",
    keywords=["striptls", "starttls", "strip", "attack", "proxy"],
    url="https://github.com/tintinweb/striptls/",
    download_url="https://github.com/tintinweb/striptls/tarball/v0.4",
    #python setup.py register -r https://testpypi.python.org/pypi
    long_description=read("README.rst") if os.path.isfile("README.rst") else read("README.md"),
    install_requires=[],
    package_data={
                  'striptls': ['striptls'],
                  },
)
