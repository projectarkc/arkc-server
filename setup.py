import codecs
import sys
from setuptools import setup


with codecs.open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

if str(sys.version_info.major) == '2':
    pkg_name = 'arkcserver'
    pkg = ['arkcserver', 'arkcserver.pyotp', 'arkcserver.twisted_connect_proxy']
    pkg_data = {
        'arkcclient': ['README.md', 'LICENSE'],
	'arkcserver.pytop': ['LICENSE'],
        'arkcserver.twisted_connect_proxy': ['LICENSE']
    }
    required = ['twisted','pycrypto','txsocksx','dnslib', 'psutil', 'ipaddress']
    entry = """
    [console_scripts]
    arkcserver = arkcserver.main:main
    """
    categories = [
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2 :: Only',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: Proxy Servers',
    ]
else:
    print("FATAL: ArkC Server 0.2 must be installed with Python2 for compatibility.")
    quit()

setup(
    name=pkg_name,
    version="0.2.2b1",
    license='https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt',
    description="A lightweight proxy designed to be proof to IP blocking measures",
    author='Noah, Teba, Ddeerreekk, Tsre',
    author_email='noah@arkc.org',
    url='https://arkc.org',
    packages=pkg,
    package_data=pkg_data,
    install_requires=required,
    entry_points=entry,
    classifiers=categories,
    long_description=long_description,
)

