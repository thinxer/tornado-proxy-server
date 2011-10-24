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

socks_server = None
#socks_server = 'localhost'
#socks_port = 2090

def header_parser(headers):
    for header in headers.split(b'\r\n'):
        i = header.find(b':')
        if i >= 0:
            yield header[:i], header[i+2:]

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

# TODO close the incoming connection if the connection failed.
def socks_connect(stream, host, port, on_connected):
    def socks_response(data):
        if data[1] == 0x5a:
            if on_connected: on_connected()
        else:
            raise Exception('socks failed')

    def socks_connected():
        stream.write(b'\x04\x01' + struct.pack('>H', port) + b'\x00\x00\x00\x09userid\x00' + host + b'\x00')
        stream.read_bytes(8, socks_response)

    stream.connect((socks_server, socks_port), socks_connected)

def tcp_client(host, port, on_connected = None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    stream = tornado.iostream.IOStream(s)
    if socks_server:
        socks_connect(stream, host, port, on_connected)
    else:
        stream.connect((host, port), on_connected)
    return stream

class ProxyHandler:
    def __init__(self, stream):
        self.incoming = stream
        self.incoming.read_until(b'\r\n', self.on_method)
        self.method = None
        self.outgoing = None

    def on_method(self, method):
        self.method = method
        self.incoming.read_until(b'\r\n\r\n', self.on_headers)

    def on_headers(self, headers):
        headers = OrderedDict(header_parser(headers))
        logging.info(self.method.decode('utf8'))
        method, url, ver = self.method.split(b' ')
        if method == b'CONNECT':
            host = url
            i = host.find(b':')
            if i >= 0:
                host, port = host[:i], int(host[i+1:])
            else:
                port = 443

            def on_connected():
                self.incoming.write(b'HTTP/1.0 200 Connection Established\r\n')
                self.incoming.write(b'\r\n')
                pipe(self.incoming, self.outgoing)

            self.outgoing = tcp_client(host, port, on_connected)
        else:
            if b'Proxy-Connection' in headers:
                del headers[b'Proxy-Connection']
            headers[b'Connection'] = b'close'
            if b'Host' in headers:
                host = headers[b'Host']
                i = host.find(b':')
                if i >= 0:
                    host, port = host[:i], int(host[i+1:])
                else:
                    port = 80

                def on_connected():
                    path = urlunparse((b'', b'') + urlparse(url)[2:])
                    write_to(self.outgoing)(b' '.join((method, path, ver)))
                    write_to(self.outgoing)(b'\r\n'.join(k + b': ' + v for k, v in headers.items()))
                    write_to(self.outgoing)(b'\r\n\r\n')
                    writer_in = write_to(self.incoming)
                    if b'Content-Length' in headers:
                        self.incoming.read_bytes(int(headers[b'Content-Length']), self.outgoing.write, self.outgoing.write)
                    self.outgoing.read_until_close(writer_in, writer_in)

                self.outgoing = tcp_client(host, port, on_connected)
            else:
                self.incoming.close()

class ProxyServer(tornado.netutil.TCPServer):
    def handle_stream(self, stream, address):
        ProxyHandler(stream)

server = ProxyServer()
server.listen(8000)

tornado.ioloop.IOLoop.instance().start()
