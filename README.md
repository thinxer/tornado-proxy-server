A simple proxy server with SOCKS4a support.

Usages:

    ./server.py
    ./server.py -u socks://localhost:1080
    ./server.py -u rules:rules.lst

The rules file looks like the following:

    .*twitter\.com socks://localhost:2091
    .*twimg\.com socks://localhost:2091

    .*tsinghua\.edu\.cn direct:

    .* socks://localhost:2090
