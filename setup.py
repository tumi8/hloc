#!/usr/bin/env python3

from distutils.core import setup

install_requires = ['requests>=2.12.4', 'ripe.atlas.cousteau>=1.3', 'configargparse>=0.11']

setup(name='hloc',
      version='0.1',
      description='Hints based LOCation verification framework',
      author='Patrick Sattler',
      author_email='sattler@in.tum.de',
      packages=['hloc', 'hloc.scripts', 'hloc.models'],
      install_requires=install_requires,
     )