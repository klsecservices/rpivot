RPIVOT - reverse socks 4 proxy for penetration tests
===================


RPIVOT allows to tunnel traffic into internal network via socks 4. It works like ssh dynamic port forwarding but in the opposite direction. 


----------


Description
-------------

This tool is Python 2.6-2.7 compatible and has no dependencies beyond the standard library. It has client-server architecture. Just run the client on the machine you want to tunnel the traffic through. Server should be started on pentester's machine and listen to incoming connections from the client.

Works on Kali Linux, Solaris 10, Windows, Mac OS.


Usage example
-------------

Start server listener on port 9999, which creates a socks 4 proxy on 127.0.0.1:1080 upon connection from client:

`python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080`

Connect to the server:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999`

To pivot through an NTLM proxy:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd`

Pass-the-hash is supported:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45`

You can use `proxychains` to tunnel traffic through socks proxy.

Edit /etc/proxychains.conf:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 1080
```

Using single zip file mode:

```
zip rpivot.zip -r *.py ./ntlm_auth/
python rpivot.zip server <server_options>
python rpivot.zip client <client_options> 
```

Pivot and have fun:

`proxychains <tool_name>`

Pre-built Windows client binary available in release section.

Author
------

Artem Kondratenko https://twitter.com/artkond
