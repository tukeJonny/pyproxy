#-*- coding: utf-8 -*-
import os
import shutil
from pathlib import Path

# CA Settings
BASE_PATH = Path('/', 'tmp', 'proxy_ca')
try:
    shutil.rmtree(str(BASE_PATH))
except:
    pass
os.mkdir(str(BASE_PATH))
SSL_BITS = '2048'
SSL_DAYS = '365'

# Proxy Handler Settings
CACERT_DISTRIBUTOR='http://pyproxy.cacert/'
REQUEST_TIMEOUT = 1
PROTOCOL_VERSION = 'HTTP/1.1'

# Server Settings
HOST = 'localhost'
PORT = 24365
