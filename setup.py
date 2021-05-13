import setuptools
from setuptools import find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="casbin_pony_adapter",
    version="1.0.0",
    author="Dror A. Vinkler",
    description="Pony ORM Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/drorvinkler/pycasbin-pony-adapter",
    packages=find_packages(),
    install_requires=[
        'pony',
        'casbin'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    license='MIT',
)
