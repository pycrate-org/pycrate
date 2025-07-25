# -*- coding: UTF−8 -*-

import os
import sys
from setuptools import setup, find_packages

# Pycrate Version
VERSION = "0.7.11"


# get long description from the README.md
with open(os.path.join(os.path.dirname(__file__), "README.md")) as fd:
    long_description = fd.read()


setup(
    name="pycrate",
    version=VERSION,
    
    #packages=find_packages(),
    packages=[
        "pycrate_core",
        "pycrate_ether",
        "pycrate_media",
        "pycrate_asn1c",
        "pycrate_asn1dir",
        "pycrate_asn1rt",
        "pycrate_csn1",
        "pycrate_csn1dir",
        "pycrate_mobile",
        "pycrate_diameter",
        "pycrate_corenet",
        "pycrate_sys",
        "pycrate_crypto",
        "pycrate_osmo",
        "pycrate_gmr1",
        "pycrate_gmr1_csn1",
        ],
    
    test_suite="test.test_pycrate",
    
    scripts=[
        "tools/pycrate_asn1compile.py",
        "tools/pycrate_berdecode.py",
        'tools/pycrate_certdecode.py',
        "tools/pycrate_showmedia.py",
        "tools/pycrate_shownas.py",
        "tools/pycrate_gtp_type_info.py",
        "tools/pycrate_map_op_info.py",
        "tools/pycrate_extnas_demo.py",
        ],
    
    # potential dependencies
    install_requires=[],
    
    # optional dependencies
    extras_require={
        "NASLTE"  : ["CryptoMobile"],
        "NAS5G"   : ["CryptoMobile"],
        "corenet" : ["pysctp", "CryptoMobile"],
        "diameter_dict" : ["lxml"],
        "SEDebugMux": ["crcmod"],
        },
    
    # for pycrate_asn1dir, pycrate_csn1dir, pycrate_gmr1_csn1:
    # .asn, .csn, .txt and .json files from asn1dir and csn1dir are not required to be installed 
    # only compiled .py modules are installed by default
    # 
    # for pycrate_diameter:
    # .xml files are converted to Python dicts and may be updated from time to time
    # 
    # for pycrate_corenet:
    # the AuC.db file is the mobile subscriber authentication database 
    # containing Ki and is required at runtime when using corenet
    #
    package_data={
        #"pycrate_asn1dir"   : ["*.asn", "*.json"],
        #"pycrate_csn1dir"   : ["*.csn"],
        #"pycrate_gmr1_csn1" : ["*.csn"],
        #"pycrate_diameter"  : ["*.xml"],
        "pycrate_corenet"   : ["AuC.db"],
        },
    #include_package_data=False,
    
    # include license file and remind the licensing here
    license_files=('license.txt', ),
    license="LGPL v2.1+",
    
    author="Benoit Michau",
    author_email="michau.benoit@gmail.com",
    description="A software suite to handle various data and protocol formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pycrate-org/pycrate/",
    keywords="protocol format ASN.1 CSN.1 compiler encoder decoder mobile core network Diameter NAS S1AP NGAP TCAP MAP GTP PFCP SCCP ISUP",
    )
