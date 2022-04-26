# MITM_Intercept

A little bit less hackish way to intercept and modify non-HTTP protocols through Burp and others with SSL and TLS interception support.
This tool is for researchers and applicative penetration testers that perform thick clients security assesments.

An improved version of the fantastic [mitm_relay](https://github.com/jrmdev/mitm_relay) project.
 


## The Story

As part of our work in the research department of CyberArk Labs, we needed a way to inspect SSL and TLS communication over TCP and have the option to modify the content of packets on the fly. There are many ways to do so (for example, the known Burp Suite extension [NoPE](https://portswigger.net/bappstore/12e84399d46a408dbe970f181391f781)), but none of them worked for us in some cases. In the end we stumbled upon [mitm_relay](https://github.com/jrmdev/mitm_relay).

mitm_relay is a quick and easy way to perform MITM of any TCP-based protocol through existing HTTP interception software like Burp Suite’s proxy. It is particularly useful for thick clients security assessments. But it didn’t completely work for us, so we needed to customize it. After a lot of customizations, every new change required a lot of work, and we ended up rewriting everything in a more modular way.

We hope that others will find this script helpful, and we hope that adding functionality will be easy.



## How does it work

For a start, listeners’ addresses and ports need to be configured. For each listener, there also needs to be a target configured (address and port). Every data received from the listener will be wrapped into a body of an HTTP POST request with the URL containing “CLIENT_REQUEST”. Every data received from the target will be wrapped into a body of an HTTP POST request with the URL containing “SERVER_RESPONSE”. Those requests are sent to a local HTTP interception server.

There is the option to configure an HTTP proxy and use a tool like [burp suite](https://portswigger.net/burp) as an HTTP interception tool and view the messages there. This way, it is easy to modify the messages by using Burp’s “Match and Replace”, extensions or even manually (Remember, the timeout mechanism of the intercepted protocol can be very short).

Another way to modify the messages is by using a python script that the HTTP interception server will run when it receives messages.

The body of the messages sent to the HTTP interception server will be printed to the shell. The messages will be printed after the changes if the modification script is given. After all the modifications, the interception server will also echo back as an HTTP response body.

To decrypt the SSL/TLS communication, mitm_intercept need to be provided a certificate and a key that the client will accept when starting a handshake with the listener. If the target server requires a specific certificate for a handshake, there is an option to give a certificate and a key. 

A small chart to show the typical traffic flow:

![test](https://user-images.githubusercontent.com/28649672/162932536-c720802f-2523-4b62-902c-df0fa2a2ca0d.jpg)


## Differences from mitm_relay 

mitm_intercept is compatible with newer versions of python 3 (python 3.9) and is also compatible with windows (socket.MSG_DONTWAIT does not exist in windows, for example). We kept the option of using “STARTTLS,” and we called it “Mixed” mode. Using the SSL key log file is updated (the built-in option to use it is new from python 3.8), and we added the option to change the [sni header](https://en.wikipedia.org/wiki/Server_Name_Indication). Now, managing incoming and outgoing communication is done by [socketserver]( https://docs.python.org/3/library/socketserver.html), and all the data is sent to a subclass of [ThreadingHTTPServer](https://docs.python.org/3/library/http.server.html#http.server.ThreadingHTTPServer) that handle the data representation and modification. This way, it is possible to see the changes applied by the modification script in the response (convenient for using Burp). Also, we can now change the available ciphers that the script uses using the [OpenSSL cipher list format](https://www.openssl.org/docs/manmaster/man1/ciphers.html)


## Prerequisites

1. Python 3.9
2. [requests](https://docs.python-requests.org/en/latest/): `$ python -m pip install requests`


## Usage

```
usage: mitm_intercept.py [-h] [-m] -l [u|t:]<interface>:<port> [[u|t:]<interface>:<port> ...] -t
                         [u|t:]<addr>:<port> [[u|t:]<addr>:<port> ...] [-lc <cert_path>]
                         [-lk <key_path>] [-tc <cert_path>] [-tk <key_path>] [-w <interface>:<port>]
                         [-p <addr>:<port>] [-s <script_path>] [--sni <server_name>]
                         [-tv <defualt|tls12|tls11|ssl3|tls1|ssl2>] [-ci <ciphers>]

mitm_intercept version 1.6

options:
  -h, --help            show this help message and exit
  -m, --mix-connection  Perform TCP relay without SSL handshake. If one of the relay sides starts an
                        SSL handshake, wrap the connection with SSL, and intercept the
                        communication. A listener certificate and private key must be provided.
  -l [u|t:]<interface>:<port> [[u|t:]<interface>:<port> ...], --listen [u|t:]<interface>:<port> [[u|t:]<interface>:<port> ...]
                        Creates SSLInterceptServer listener that listens on the specified interface
                        and port. Can create multiple listeners with a space between the parameters.
                        Adding "u:" before the address will make the listener listen in UDP
                        protocol. TCP protocol is the default but adding "t:" for cleanliness is
                        possible. The number of listeners must match the number of targets. The i-th
                        listener will relay to the i-th target.
  -t [u|t:]<addr>:<port> [[u|t:]<addr>:<port> ...], --target [u|t:]<addr>:<port> [[u|t:]<addr>:<port> ...]
                        Directs each SSLInterceptServer listener to forward the communication to a
                        target address and port. Can create multiple targets with a space between
                        the parameters. Adding "u:" before the address will make the target
                        communicate in UDP protocol.TCP protocol is the default but adding "t:" for
                        cleanliness is possible. The number of listeners must match the number of
                        targets. The i-th listener will relay to the i-th target.
  -lc <cert_path>, --listener-cert <cert_path>
                        The certificate that the listener uses when a client contacts him. Can be a
                        self-sign certificate if the client will accept it.
  -lk <key_path>, --listener-key <key_path>
                        The private key path for the listener certificate.
  -tc <cert_path>, --target-cert <cert_path>
                        The certificate that used to create a connection with the target. Can be a
                        self-sign certificate if the target will accept it. Doesn't necessary if the
                        target doesn't require a specific certificate.
  -tk <key_path>, --target-key <key_path>
                        The private key path for the target certificate.
  -w <interface>:<port>, --webserver <interface>:<port>
                        Specifies the interface and the port the InterceptionServer webserver will
                        listens on. If omitted the default is 127.0.0.1:49999
  -p <addr>:<port>, --proxy <addr>:<port>
                        Specifies the address and the port of a proxy between the InterceptionServer
                        webserver and the SSLInterceptServer. Can be configured so the communication
                        will go through a local proxy like Burp. If omitted, the communication will
                        be printed in the shell only.
  -s <script_path>, --script <script_path>
                        A path to a script that the InterceptionServer webserver executes. Must
                        contain the function handle_request(message) that will run before sending it
                        to the target or handle_response(message) after receiving a message from the
                        target. Can be omitted if doesn't necessary.
  --sni <server_name>   If there is a need to change the server name in the SSL handshake with the
                        target. If omitted, it will be the server name from the handshake with the
                        listener.
  -tv <defualt|tls12|tls11|ssl3|tls1|ssl2>, --tls-version <defualt|tls12|tls11|ssl3|tls1|ssl2>
                        If needed can be specified a specific TLS version.
  -ci <ciphers>, --ciphers <ciphers>
                        Sets different ciphers than the python defaults for the TLS handshake. It
                        should be a string in the OpenSSL cipher list format
                        (https://www.openssl.org/docs/manmaster/man1/ciphers.html).

For dumping SSL (pre-)master secrets to a file, set the environment variable SSLKEYLOGFILE with a
file path. Useful for Wireshark.
```

The communication needs to be directed to the listener for intercepting arbitrary protocols. The way to do so depends on how the client operates. Sometimes it uses a DNS address, and changing the hosts file will be enough to resolve the listener address. If the address is hard-coded, then more creative ways need to be applied (usually some modifications of the routing table, patching the client, or [using VM and iptables](https://github.com/jrmdev/mitm_relay#host-configuration)).

## Modification Script

The HTTP interception server can run a script given to it with the flag `-s`. This script runs when the HTTP requests are received. The response from the HTTP interception server is the received request after running the script.

When a proxy is configured (like Burp), modifications of the request will happen before the script runs, and modifications on the response will be after that. Alterations on the request and the response by the proxy or the modification script will change the original message before going to the destination.

The script must contain the functions `handle_request(message)` and `handle_response(message)`. The HTTP interception server will call `handle_request(message)` when the message is from the client to the server and `handle_response(message)` when the message is from the server to the client.

An example of a script that adds a null byte at the end of the message:
```python
def handle_request(message):
    return message + b"\x00"

def handle_response(message):
    # Both functions must return a message.
    return message
```

## Certificates

The tool requires a server certificate and a private key for SSL interception. Information about generating a self-signed certificate or Burp’s certificate can be found [here](https://github.com/jrmdev/mitm_relay#certificates).

If the server requires a specific certificate, a certificate and a key can be provided to the tool.


## Demo

The demo below shows how to intercept a connection with MSSQL (this demo was performed on [DVTA](https://github.com/srini0x00/dvta)):

https://user-images.githubusercontent.com/28649672/162933166-21c1f37d-ee6c-4162-8c00-2bc724cc10a7.mp4


Connection to MSSQL is made by [TDS protocl](https://en.wikipedia.org/wiki/Tabular_Data_Stream) on top of TCP. The authentication itself is performed with TLS on top of the TDS protocol. To see intercept that TLS process, we will need two patchy modification scripts.

demo_script.py:
```python
from time import time
from struct import pack
from pathlib import Path


def handle_request(message):

    if message.startswith(b"\x17\x03"):
        return message

    with open("msg_req" + str(time()), "wb") as f:
        f.write(message[:8])

    return message[8:]


def handle_response(message):

    if message.startswith(b"\x17\x03"):
        return message

    path = Path(".")
    try:
        msg_res = min(i for i in path.iterdir() if i.name.startswith("msg_res"))
        data = msg_res.read_bytes()
        msg_res.unlink()
    except ValueError:
        data = b'\x12\x01\x00\x00\x00\x00\x01\x00'

    return data[:2] + pack(">h", len(message)+8) + data[4:] + message
```

demo_script2.py:
```python
from time import time
from struct import pack
from pathlib import Path

def handle_request(message):

    if message.startswith(b"\x17\x03"):
        return message

    path = Path(".")
    try:
        msg_req = min(i for i in path.iterdir() if i.name.startswith("msg_req"))
        data = msg_req.read_bytes()
        msg_req.unlink()
    except ValueError:
        data = b'\x12\x01\x00\x00\x00\x00\x01\x00'


    return data[:2] + pack(">h", len(message)+8) + data[4:] + message


def handle_response(message):

    if message.startswith(b"\x17\x03"):
        return message

    with open("msg_res" + str(time()), "wb") as f:
        f.write(message[:8])

    return message[8:]
```

We will see some of the TLS communication with those patchy scripts, but then the client will fail (because with those hacky scripts, we badly alter the TDS communication except the TLS part).


https://user-images.githubusercontent.com/28649672/162976250-75f2e3c5-f328-4bcc-ad49-a9561d493cb1.mp4


## License
Copyright (c) 2022 CyberArk Software Ltd. All rights reserved  
This repository is licensed under Apache-2.0 License - see [`LICENSE`](LICENSE) for more details.
