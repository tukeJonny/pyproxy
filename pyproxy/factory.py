# -*- coding: utf-8 -*-
import sys
import ssl
import socket
import logging
from http.server import HTTPServer
from socketserver import ThreadingMixIn

import daiquiri
daiquiri.setup(level=logging.DEBUG)
logger = daiquiri.getLogger()

from pyproxy import settings

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls in (socket.error, ssl.SSLError):
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

class ProxyFactory:

    @staticmethod
    def create(handler):
        # handler.protocol_version = settings.PROTOCOL_VERSION
        http_server = ThreadingHTTPServer((settings.HOST, settings.PORT), handler)
        return http_server
