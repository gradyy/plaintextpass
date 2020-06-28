from setuptools import find_packages, setup

setup(
    name='plaintextpass',
    version='1.0.2',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask',
        'flask-sqlalchemy',
        'flask-limiter',
        'flask-login',
        'psycopg2',
        'webauthn',
    ],
)


