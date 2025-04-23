from setuptools import setup, find_packages

setup(
    name='ckanext-pwaauth',
    version='0.1',
    description='CKAN extension for PWA authentication',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/ckanext-pwaauth',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests'
    ],
    entry_points={
        'ckan.plugins': [
            'pwaauth=ckanext.pwaauth.plugin:PwaauthAuthenticator',
        ],
    },
)