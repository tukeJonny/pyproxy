#-*- coding: utf-8 -*-
import gzip
import zlib
from io import StringIO

class ContentBodyEncoder:

    @staticmethod
    def gzip_encode(content_body, encoding='gzip'):
        """
        ContentBodyのエンコードを行う
        :content_body: ContentBody
        :encoding: identity(そのまま), gzip, x-gzip, deflateをサポート
        """
        if 'identity' in encoding:
            encoded = content_body
        elif encoding in ('gzip', 'x-gzip'):
            inmem_gzip = StringIO()
            with gzip.GzipFile(inmem_gzip, 'wb') as f:
                f.write(content_body)
            encoded = inmem_gzip.getvalue()
        elif 'deflate' in encoding:
            encoded = zlib.compress(content_body)
        else:
            raise ValueError("Invalid encoding {0} for ContentBody {1}."\
                                .format(encoding, content_body))

        return encoded

    @staticmethod
    def gzip_decode(encoded, encoding='gzip'):
        """
        ContentBodyのデコードを行う
        :encoded: ContentBody
        :encoding: identity(そのまま), gzip, x-gzip, deflateをサポート
        """
        if 'identity' in encoding:
            decoded = encoded
        elif encoding in ('gzip', 'x-gzip'):
            inmem_decoded = StringIO()
            with gzip.GzipFile(inmem_decoded) as f:
                decoded = f.read()
        elif 'deflate' in encoding:
            try:
                decoded = gzip.decompress(encoded)
            except zlib.error:
                decoded = zlib.decompress(encoded, -zlib.MAX_WBITS)

        return decoded

