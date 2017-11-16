#-*- coding: utf-8 -*-
import os
import time
import ssl
import logging
import subprocess

import daiquiri
daiquiri.setup(level=logging.DEBUG)
logger = daiquiri.getLogger()

from pyproxy import settings
from pyproxy import exceptions as pyproxy_exceptions

class CAManager(object):

    def __init__(self):
        self.cakey   = str(settings.BASE_PATH/'ca.crt')
        self.cacert  = str(settings.BASE_PATH/'ca.crt')
        self.certkey = str(settings.BASE_PATH/'cert.key')
        self.certdir = str(settings.BASE_PATH/'certs/')

        self._initialize()

    def _initialize(self):
        logger.info("Initalize CA...")

        logger.debug("Create CA Key")
        cakey_proc = subprocess.Popen([
            'openssl',
            'genrsa',
            '-out', self.cakey,
            settings.SSL_BITS,
        ])
        cakey_proc.communicate()
        try:
            os.path.isfile(self.cakey)
        except Exception:
            raise pyproxy_exceptions.CAManagerInitializeException()

        logger.debug("Create CA Cert")
        cacert_proc = subprocess.Popen([
            'openssl',
            'req',
            '-new',
            '-x509',
            '-days', settings.SSL_DAYS,
            '-key', self.cakey,
            '-out', self.cacert,
            '-subj', '/CN=pyproxy CA',
        ])
        cacert_proc.communicate()
        try:
            os.path.isfile(self.cacert)
        except Exception:
            raise pyproxy_exceptions.CAManagerInitializeException()

        logger.debug("Create Cert Key")
        certkey_proc = subprocess.Popen([
            'openssl',
            'genrsa',
            '-out', self.certkey,
            settings.SSL_BITS,
        ])
        certkey_proc.communicate()
        try:
            os.path.isfile(self.certkey)
        except:
            raise pyproxy_exceptions.CAManagerInitializeException()

        logger.debug("Create Cert Directory")
        os.mkdir(self.certdir)
        try:
            os.path.isdir(self.certdir)
        except Exception:
            raise pyproxy_exceptions.CAManagerInitializeException()

        logger.info("CA Initialized.")

    def create_client_cert(self, hostname):
        """
        https GETリクエストを飛ばしてきたクライアントの証明書を作成
        """
        logger.info("Create Per Client Certificate...")

        logger.debug("Create CSR...")
        proc1 = subprocess.Popen([
            'openssl',
            'req',
            '-new',
            '-key', self.certkey,
            'subj', "/CN={0}".format(hostname),
        ], stdout=subprocess.PIPE)

        logger.debug("Create Certificate...")
        proc2 = subprocess.Popen([
            'openssl',
            'x509',
            '-req',
            '-days', '3650',
            '-CA', self.cacert,
            '-CAkey', self.cakey,
            '-set_serial', str(time.time()*1000),
            '-out', self.certdir/hostname,
        ], stdin=proc1.stdout, stderr=subprocess.PIPE)
        proc2.communicate()

        logger.info("Distribute")

    def get_ssl_socket(self, conn):
        return ssl.wrap_socket(conn, keyfile=self.certkey,\
                               certfile=self.cacert, server_side=True)

    def read_from_cacert(self):
        logger.info("Distribute CA Certification")
        with open(self.cacert, 'rb') as cacert:
            data = cacert.read()
            return data
