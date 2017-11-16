#-*- coding: utf-8 -*-
import os
import socket
import select
import logging
import urllib.parse
import threading
import http.client
from http.server import BaseHTTPRequestHandler

import daiquiri
daiquiri.setup(level=logging.DEBUG)
logger = daiquiri.getLogger()

from pyproxy import settings
from pyproxy import exceptions as pyproxy_exceptions
from pyproxy.ca import manager as ca_manager
from pyproxy.request import utils as pyproxy_req_utils 
from pyproxy.gzip.contentbody import ContentBodyEncoder as contentbody_encoder

CA = ca_manager.CAManager()

class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = settings.REQUEST_TIMEOUT

    def __init__(self, *args, **kwargs):
        logging.info("Start Proxy") 
        self.tls = threading.local() # Thread Local Storage
        self.tls.connections = dict()

        self.ca = CA

        super().__init__(*args, **kwargs)

    def _connect_intercept(self):
        """
        HTTP CONNECTメソッドに介入
        """
        hostname = self.path.split(':')[0]

        self.ca.create_client_cert(hostname)

        self.wfile.write("{0} {1:d} {2}\r\n"\
                         .format(
                             self.protocol_version,
                             200,
                             'Connection Established',
                        ))

        self.connection = self.ca.get_ssl_socket(self.connection)
        # このコネクションに対する読み書き用ファイルを作成
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == 'HTTP/1.1' and conntype.lower() != 'close':
            self.close_connection = 0 # connection
        else:
            self.close_connection = 1 # connection closed

    def _connect_relay(self):
        """
        HTTP CONNECTメソッドリクエストをそのまま受け流す
        """
        address, port = self.path.split(':', 1)
        try:
            port = int(port)
        except:
            port = 443

        # ソケットの作成
        try:
            sock = socket.create_connection((address, port), timeout=self.timeout)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        self.close_connection = 0 # connection
        while not self.close_connection:
            # while connection closed

            # Polling
            # rwx lists
            rlist, wlist, xlist = select.select(
                [self.connection, sock],
                [],
                [self.connection, sock],
                self.timeout,
            )

            if xlist or not rlist: # 読み込み、あるいは読み書きでなければスルー
                break

            for read_fd in rlist:
                # self.connectionとsockのどちらかになるが、
                # どちらか片方の読み込みであれば、
                # データを読み込んで、もう片方へ送りつける
                if read_fd is self.connection:
                    other = sock
                else:
                    other = self.connection

                data = read_fd.recv(8192)
                if not data: # データが受信できなかったらコネクション閉じてbreak
                    self.close_connection = 1
                    break

                other.sendall(data)

    def do_CONNECT(self):
        """
        HTTP CONNECTメソッドのハンドラ
        """
        logger.info("Handling HTTP CONNECT")
        if all(lambda f: os.path.isfile(f), [self.ca.cakey,self.ca.cacert,self.ca.certkey]) and os.path.isdir(self.certdir):
            self._connect_intercept()
        else:
            self._connect_relay()

    def _send_cacert(self):
        data = self.ca.read_from_cacert()

        self.wfile.write("{0} {1:d} {2}\r\n".format(self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def _relay_chunk_streaming(self, resp):
        """
        チャンク転送
        """
        # HTTP/1.1 200 OK
        self.wfile.write("{0} {1:d} {2}\r\n".format(self.protocol_version, \
                                                        resp.status, resp.reason))
        # ヘッダを書き出す
        for line in resp.headers.headers:
            self.wfile.write(line)

        self.end_headers()

        # チャンク転送
        try:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except socket.error:
            raise pyproxy_exceptions.RelayStreamingException()

    def _proxying(self, scheme, hostname, path, req_body):
        logger.debug("Proxying {0} request...".format(scheme))
        version_table = {
            10: 'HTTP/1.0',
            11: 'HTTP/1.1',
        }
        try:
            logger.info("Try proxying...")
            origin = (scheme, hostname)
            # プロキシーする対象ホストの管理情報更新
            if not origin in self.tls.connections:
                if 'https' in scheme:
                    self.tls.connections[origin] = \
                        http.client.HTTPSConnection(hostname, timeout=self.timeout)
                else:
                    self.tls.connections[origin] = \
                        http.client.HTTPConnection(hostname, timeout=self.timeout)

            connection = self.tls.connections[origin]
            connection.request(self.command, path, req_body, dict(self.headers))
            resp = connection.getresponse()
            setattr(resp, 'headers', resp.msg)
            setattr(resp, 'response_version', version_table[resp.version])

            # Content-Lengthがヘッダに含まれない場合や、
            # Cache-Controlにno-storeが指定されている場合、
            # チャンク転送を試みる
            if not 'Content-Length' in resp.headers and \
                    'no-store' in resp.headers.get('Cache-Control', ''):
                self._intercept_response(req_body, resp, '')
                setattr(resp, 'headers', pyproxy_req_utils.filter_headers(resp.headers))
                self.relay_streaming(resp)
                return None

            resp_body = resp.read()
        except Exception as e:
            logger.error(e)
            if origin in self.tls.connections:
                del self.tls.connections[origin]
            self.send_error(502)
            return None

        return resp, resp_body

    def _intercept_request(self, req_body):
        intercepted_req_body = self.request_handler(self, req_body)
        if intercepted_req_body is False:
            self.send_error(403) # 介入に失敗
            return None
        elif intercepted_req_body is not None:
            self.headers['Content-Length'] = str(len(req_body))
            return intercepted_req_body # interceptして書き換えたreq_body
        else:
            return req_body # 変化なし

    def _intercept_response(self, req_body, resp, resp_body):
        intercepted_resp_body = self.response_handler(self, req_body, resp, resp_body)
        if intercepted_resp_body is False:
            self.send_error(403)
            return None
        else:
            resp_body = contentbody_encoder.gzip_encode(
                intercepted_resp_body,
                resp.headers.get('Content-Encoding', 'identity'),
            )
            resp.headers['Content-Length'] = str(len(resp_body))
            return resp_body

    def do_GET(self):
        """
        HTTP GETメソッドのハンドラ
        """
        logger.info("Handling HTTP GET")
        # 設定したURLにアクセスすると、CAの証明書をブラウザにインストールできる
        if self.path == settings.CACERT_DISTRIBUTOR:
            logger.info("Distribute CA Certification!")
            self._send_cacert(self)
            logger.info("Respond.")
            return

        logger.debug("Reading Request data...")
        # ContentLengthを元に、リクエストデータを読み込む
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            req_body = self.rfile.read(content_length)
        else:
            req_body = None

        logger.info("Raw Request Information")
        logger.debug(self.__dict__)
        logger.debug(req_body)
        logger.info("----- req info end ----")

        logger.debug("Intercepting request...")
        # ここで、ユーザが定義するrequest_handlerにinterceptさせる
        req_body = self._intercept_request(req_body)

        # スキーム、ホスト名、パス+GETクエリパラメータを取得し、
        # スキームを検証、
        # ホスト名をヘッダに設定、
        url_parts = urllib.parse.urlsplit(self.path)
        scheme, hostname, path = \
            url_parts.scheme, \
            url_parts.netloc, \
            "{0}?{1}".format(url_parts.path, url_parts.query) \
                if url_parts.query else url_parts.path
        if hostname:
            self.headers['Host'] = hostname

        # 適切なヘッダを設定
        setattr(self, 'headers', pyproxy_req_utils.filter_headers(self.headers))

        logger.debug("Proxying...")
        # Proxying 処理
        resp, resp_body = self._proxying(scheme, hostname, path, req_body) \
                                                            or (None,None)
        if resp is None or resp_body is None:
            logger.info("Empty resp, resp_body. Ignore.")
            return

        logger.info("Raw Response Information")
        logger.debug(resp.__dict__)
        logger.debug(resp_body)
        logger.info("----- resp info end ----")

        logger.debug("Intercepting response...")
        decoded_resp_body = contentbody_encoder.gzip_decode(
            resp_body,
            encoding=resp.headers.get('Content-Encoding', 'identity'),
        )

        resp_body = self._intercept_response(req_body, resp, decoded_resp_body)

        setattr(resp, 'headers', pyproxy_req_utils.filter_headers(resp.headers))

        self.wfile.write("{0} {1:d} {2}\r\n".format(
            self.protocol_version,
            resp.status,
            resp.reason,
        ).encode())

        for line in resp.headers._headers:
            # self.wfile.write(line)
            self.send_header(*line)
        self.end_headers()

        logger.debug("Responding...")
        self.wfile.write(resp_body)
        self.wfile.flush()

    # CONNECT以外のHTTPメソッドをGETで処理
    do_HEAD    = do_GET
    do_POST    = do_GET
    do_PUT     = do_GET
    do_DELETE  = do_GET
    do_OPTIONS = do_GET

    def request_handler(self, req, req_body):
        raise NotImplementedError()

    def response_handler(self, req, req_body, resp, resp_body):
        raise NotImplementedError()
