#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.cfg:

    console_scripts =
     fibonacci = pyproxy.skeleton:run

Then run `python setup.py install` which will install the command `fibonacci`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import
import logging

import daiquiri
daiquiri.setup(level=logging.DEBUG)
logger = daiquiri.getLogger()

from pyproxy.factory import ProxyFactory
from pyproxy.request import handler as proxy_handler

__author__ = "tukeJonny"
__copyright__ = "tukeJonny"
__license__ = "none"

class MyProxy(proxy_handler.ProxyRequestHandler):

    def __init__(self, *args, **kwargs):
        logger.info("Initialize MyProxy")

        super().__init__(*args, **kwargs)

    def request_handler(self, req, req_body):
        logger.info("Handle request with My Custom Request Handler")
        return req_body
    
    def response_handler(self, req, req_body, resp, resp_body):
        logger.info("Handle request with My Custom Response Handler")
        return resp_body

def main():
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    logger.info("Creating proxy...")
    proxy_server = ProxyFactory.create(MyProxy)
    logger.debug(proxy_server)

    proxy_socks = proxy_server.socket.getsockname()
    logger.info("Serving HTTP Proxy on {0}:{1}...".format(
        proxy_socks[0],
        proxy_socks[1],
    ))
    proxy_server.serve_forever()


def run():
    """Entry point for console_scripts
    """
    main()


if __name__ == "__main__":
    run()
