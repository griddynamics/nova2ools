from glob import glob
from setuptools import setup, find_packages

setup(
    name='nova2ools',
    version='0.0.1',
    license='GNU GPL v3.0',
    description='Utilities to work with OpenStack',
    author='Dmitry Maslennikov (GridDynamics Openstack Core Team)',
    author_email='openstack@griddynamics.com',
    url='http://www.griddynamics.com/openstack',
    packages=find_packages(),
    scripts=glob("nova2ools-*"),
    py_modules=[],
)
