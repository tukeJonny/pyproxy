#-*- coding: utf-8 -*-
import re

def filter_headers(headers):
    # http://tools.ietf.org/html/rfc2616#section-13.5.1
    # 不要なヘッダを取り除く
    for header in ('connection', 'keep-alive', 'proxy-authenticate',
                   'proxy-authorization', 'te', 'trailers',
                   'transfer-encoding', 'upgrade'):
        del headers[header]

        # Accept-Encodingを、有効なものだけに絞る
        if 'Accept-Encoding' in headers:
            filtered_encodings = \
                filter(lambda header: header in ['identity', 'gzip', 'x-gzip', 'deflate'], \
                       re.split(r',\s*', headers['Accept-Encoding']))
            headers['Accept-Encoding'] = ','.join(filtered_encodings)

    return headers
