#!/usr/bin/env python3
#
# Author: Jianfei Wang <me@thinxer.com>
# License: MIT

''' Proxy Server based on tornado. '''

import struct
import socket
import logging
import tornado.ioloop
import tornado.netutil
from urllib.parse import urlparse, urlunparse
from collections import OrderedDict

logging.getLogger().setLevel(logging.INFO)


def header_parser(headers):
    for header in headers.split(b'\r\n'):
        i = header.find(b':')
        if i >= 0:
            yield header[:i], header[i+2:]


def hostport_parser(hostport, default_port):
    i = hostport.find(b':' if isinstance(hostport, bytes) else ':')
    if i >= 0:
        return hostport[:i], int(hostport[i+1:])
    else:
        return hostport, default_port


def write_to(stream):
    def on_data(data):
        if data == b'':
            stream.close()
        else:
            if not stream.closed():
                stream.write(data)
    return on_data


def pipe(stream_a, stream_b):
    writer_a = write_to(stream_a)
    writer_b = write_to(stream_b)
    stream_a.read_until_close(writer_b, writer_b)
    stream_b.read_until_close(writer_a, writer_a)


class Connector:
    def connect(self, host, port, callback):
        raise NotImplementedError()


class DirectConnector(Connector):

    def connect(self, host, port, callback):

        def on_close():
            callback(None)

        def on_connected():
            stream.set_close_callback(None)
            callback(stream)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.IOStream(s)
        stream.set_close_callback(on_close)
        stream.connect((host, port), on_connected)


class SocksConnector(Connector):

    def __init__(self, socks_server, socks_port):
        Connector.__init__(self)
        self.socks_server = socks_server
        self.socks_port = socks_port

    def connect(self, host, port, callback):

        def socks_close():
            callback(None)

        def socks_response(data):
            stream.set_close_callback(None)
            if data[1] == 0x5a:
                callback(stream)
            else:
                callback(None)

        def socks_connected():
            stream.write(b'\x04\x01' + struct.pack('>H', port) + b'\x00\x00\x00\x09userid\x00' + host + b'\x00')
            stream.read_bytes(8, socks_response)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.IOStream(s)
        stream.set_close_callback(socks_close)
        stream.connect((self.socks_server, self.socks_port), socks_connected)


class ProxyHandler:
    def __init__(self, stream, connector):
        self.connector = connector

        self.incoming = stream
        self.incoming.read_until(b'\r\n', self.on_method)

        self.method = None
        self.url = None
        self.ver = None
        self.headers = None

    def on_method(self, method):
        self.method, self.url, self.ver = method.strip().split(b' ')
        self.incoming.read_until(b'\r\n\r\n', self.on_headers)

    def on_connected(self, outgoing):
        if outgoing:
            path = urlunparse((b'', b'') + urlparse(self.url)[2:])
            outgoing.write(b' '.join((self.method, path, self.ver)) + b'\r\n')
            for k, v in self.headers.items():
                outgoing.write(k + b': ' + v + b'\r\n')
            outgoing.write(b'\r\n')
            writer_in = write_to(self.incoming)
            if b'Content-Length' in self.headers:
                self.incoming.read_bytes(int(self.headers[b'Content-Length']), outgoing.write, outgoing.write)
            outgoing.read_until_close(writer_in, writer_in)
        else:
            self.incoming.close()

    def on_connect_connected(self, outgoing):
        if outgoing:
            self.incoming.write(b'HTTP/1.0 200 Connection Established\r\n\r\n')
            pipe(self.incoming, outgoing)
        else:
            self.incoming.close()

    def on_headers(self, headers_buffer):
        self.headers = OrderedDict(header_parser(headers_buffer))
        logging.info('%s %s %s', self.method, self.url, self.ver)
        if self.method == b'CONNECT':
            host, port = hostport_parser(self.url, 443)
            self.outgoing = self.connector.connect(host, port, self.on_connect_connected)
        else:
            if b'Proxy-Connection' in self.headers:
                del self.headers[b'Proxy-Connection']
            self.headers[b'Connection'] = b'close'
            if b'Host' in self.headers:
                host, port = hostport_parser(self.headers[b'Host'], 80)
                self.outgoing = self.connector.connect(host, port, self.on_connected)
            else:
                self.incoming.close()


class ProxyServer(tornado.netutil.TCPServer):

    def __init__(self, connector = None):
        tornado.netutil.TCPServer.__init__(self)
        self.connector = connector or DirectConnector()

    def handle_stream(self, stream, address):
        ProxyHandler(stream, self.connector)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Simple proxy server based on tornado')
    parser.add_argument('-u', '--upstream', type=str, help='upstream proxy like socks://localhost:1080')
    parser.add_argument('-b', '--bind', type=str, default=':8000', help='bind address and port, default is :8000')
    args = parser.parse_args()

    if args.upstream:
        parts = urlparse(args.upstream)
        if parts.scheme == 'socks':
            logging.info('using socks proxy: %s', parts.netloc)
            connector = SocksConnector(*hostport_parser(parts.netloc, 1080))
        else:
            raise NotImplementedError('Unsupported scheme', parts.scheme)
    else:
        logging.info('using direct connection')
        connector = DirectConnector()

    host, port = hostport_parser(args.bind, 8000)
    server = ProxyServer(connector)
    logging.info('listening on %s', args.bind)
    server.listen(port, host)

    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__': main()
