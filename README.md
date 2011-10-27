A simple proxy server with configurable upstream proxy support.

Usages
------

    ./server.py
    ./server.py -u socks://localhost:1080
    ./server.py -u rules:rules.lst

The rules file looks like the following:

    .*twitter\.com socks://localhost:2091
    .*twimg\.com socks://localhost:2091

    .*tsinghua\.edu\.cn direct:

    .* socks://localhost:2090

To Do
-----

    + HttpProxyConnector
    + Keep-alive connections (both proxy connection and outgoing connection)
    + Authentication
