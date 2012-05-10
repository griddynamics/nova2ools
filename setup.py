from glob import glob
from setuptools import setup, find_packages

from nova2ools import VERSION

setup(
    name='nova2ools',
    version=VERSION,
    license='GNU GPL v3.0',
    description='Utilities to work with OpenStack',
    author='Dmitry Maslennikov (GridDynamics Openstack Core Team)',
    author_email='openstack@griddynamics.com',
    url='http://www.griddynamics.com/openstack',
    packages=find_packages(),
    scripts=glob("nova2ools-*"),
    py_modules=[],
    data_files=[('/etc/bash_completion.d', ['bash_compl/nova2ools-completion'])]
)
