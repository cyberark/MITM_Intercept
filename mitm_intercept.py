#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# Name:        mitm_intercept.py
# Purpose:     Performs SSL interception and forwards it to a local proxy server
#              for inspection.
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

# Imports.
import os
import ssl
import sys
import time
import socket
import requests
import argparse
from select import select
from threading import Thread, Event
from importlib.machinery import SourceFileLoader
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from socketserver import StreamRequestHandler, DatagramRequestHandler, \
                         ThreadingTCPServer, ThreadingUDPServer


# Consts.
BUFSIZE = 4096
BIND_WEBSERVER = ('127.0.0.1', 49999)
HEX_TRNS = b'................................ !"#$%&\'()*+,-./0123456789:;<=>?'\
           b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.'\
           b'.................................................................'\
           b'...............................................................'
TLS_VERSIONS = {"defualt": ssl.PROTOCOL_TLS,
                "ssl2": ssl.PROTOCOL_SSLv23,
                "ssl3": ssl.PROTOCOL_SSLv23,
                "tls1": ssl.PROTOCOL_TLSv1,
                "tls11": ssl.PROTOCOL_TLSv1_1,
                "tls12": ssl.PROTOCOL_TLSv1_2}


__prog_name__ = "mitm_intercept"
__version__ = 1.6


class _SSLHelper:
    """Class that helps perform a variety of actions regarding SSL."""

    @classmethod
    def create_context(cls, protocol, ciphers = None):
        """Creates SSLContext."""

        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if ciphers:
            context.set_ciphers(ciphers)

        if hasattr(context, 'keylog_filename'):
            keylogfile = os.environ.get('SSLKEYLOGFILE')
        if keylogfile and not sys.flags.ignore_environment:
            context.keylog_filename = keylogfile
        return context


    @classmethod
    def wrap_socket(cls, sock, ctx, **kwargs):
        """Wraps socket with context and handle the handshake. Can use all the
        parameters of SSLContext.wrap_socket."""

        if sock.getblocking():
            return ctx.wrap_socket(sock, **kwargs)

        wrapped = ctx.wrap_socket(sock, do_handshake_on_connect=False, **kwargs)
        cls.do_nonblocking_handshake(wrapped)
        return wrapped


    @classmethod
    def do_nonblocking_handshake(cls, sock):
        """Preforms SSL handshake on non-blocking socket."""

        while True:
            try:
                sock.do_handshake()
                break
            except ssl.SSLWantReadError:
                select([sock], [], [])
            except ssl.SSLWantWriteError:
                select([], [sock], [])


    @classmethod
    def set_sni_callback(cls, ctx):
        """Sets the sni_callback of the context to a function that adds to the
        socket the attribute sni that will contain the SNI value."""

        def callback(sslobj, server_name, context):
            sslobj.sni = server_name

        ctx.sni_callback = callback


class _UDPSocket(socket.socket):
    """A small subclass of socket to handle UDP sockets as if they are stream
    sockets."""

    def __init__(self, sock, event_udp_sent):
        """Initialize."""

        self.sock = sock
        self.event_udp_sent = event_udp_sent


    def connect(self, addr):
        """Mimic connection but actually only set an attribute for basic socket
        operations."""

        self.target_addr = addr


    def send(self, data):
        """Mimic send with sendto."""

        ret = self.sock.sendto(data, self.target_addr)
        self.event_udp_sent.set()
        return ret

    def recv(self, buf):
        """Mimic recv with recvfrom."""

        return self.sock.recvfrom(buf)[0]


    def fileno(self):
        """Mimic fileno for select()."""

        return self.sock.fileno()


    def setblocking(self, flag):
        """Mimic setblocking."""

        self.sock.setblocking(flag)


    def getpeername(self):
        """Mimic getpeername."""

        return self.target_addr


class NonBlockingServerMixIn:
    """A mixin class that adds a non-blocking capability to a server. Must be
    inherited with another server class."""

    def __init__(self, server_address, request_handler,
                 bind_and_activate = True, sock = None):
        """Initialize non-blocking server."""

        # Initialize the server class that is inherited with this mixin.
        super().__init__(server_address, request_handler, False)

        # If needed, set a new socket instance (like SSLSocket).
        self.socket = sock if sock else self.socket

        # Set socket to non-blocking.
        self.socket.setblocking(0)

        # bind the socket and start the server.
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except Exception as e:
                print(e)
                self.server_close()


class RelayRequstHandlerMixIn:
    """A mixin request handler that performs a relay. Must be inherited with
    another request handler class"""

    def setup(self):
        """Sets up the handler and creates a connection with the target."""

        super().setup()
        self.event_k = self.server.event_k
        self.event_udp_sent = Event()

        # Create a connection with target.
        if hasattr(self, "connection"):
            self.t_sock = socket.create_connection(self.server.target_addr)
        else:
            self.connection = _UDPSocket(self.socket, self.event_udp_sent)
            self.connection.connect(self.client_address)
            self.t_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.t_sock.connect(self.server.target_addr)

        self.t_sock.setblocking(False)
        self.connection.setblocking(False)

        # Get peers names.
        self.server_peer = self.t_sock.getpeername()
        self.client_peer = self.connection.getpeername()

        # Set proxy parameters.
        self.proxy = self.server.proxy

        # In UDP we already receive the first packet so we need to forward it to
        # the target.
        if hasattr(self, "packet"):
            data = self._proxify(self.packet, True)
            self.t_sock.send(data)


    def finish(self):
        """Finish request handalling and close TCP connections."""

        super().finish()
        self.t_sock.close()


    def handle(self):
        """Handles stream and forward through the interception server."""

        while not self.event_k.is_set() and not self.event_udp_sent.is_set():
            receiving,_,_ = select([self.t_sock, self.connection], [], [], 0.1)

            try:
                if self.connection in receiving:
                    if not self.forward(self.connection, self.t_sock, True):
                        break

                if self.t_sock in receiving:
                    if not self.forward(self.t_sock, self.connection, False):
                        break

            except Exception as e:
                print(e)
                break


    def forward(self, recv_sock, send_sock, to_server):
        """Receiving data from recv_sock and send it to send_sock."""

        data  = recv_sock.recv(BUFSIZE)
        if not data:
            return False

        data = self._proxify(data, to_server)
        send_sock.send(data)
        return True


    def _data_repr(self, data):
        """Represent the data as ascii or in hex view."""

        try:
            data = data.decode("ascii")
            return '\n'+data

        # The new format string form is complicated like the old form :(.
        except:
            res = "\n"
            for i in range(0, len(data), 16):
                res += (f"{i:08x}: {data[i:+i+16].hex(' '):<48} |"
                       f"{data[i:i+16].translate(HEX_TRNS).decode('ascii'):<16}"
                       "|\n")
        return res


    def _proxify(self, message, to_server):
        """Send a message through the defined proxies using the webserver
        forwarder."""

        # Set variables for requests.
        server_str = "{}:{}".format(*self.server_peer)
        client_str = "{}:{}".format(*self.client_peer)
        date_str = time.strftime("%a %d %b %H:%M:%S", time.gmtime())

        # Set headers for interception server.
        headers = {u'User-Agent':None, u'Accept':None, u'Accept-Encoding':None,
                   u'Connection':None}
        headers['X-Mitm_Intercept-To'] = server_str if to_server else client_str
        headers['X-Mitm_Intercept-From'] = client_str if to_server else server_str
        headers["To-Server"] = str(to_server)
        url = "http://{0}:{1}/{2}/{3}/{4}".format(*self.server.webserver_addr,
              ('CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'),
              *self.server_peer)
        proxies = {'http':"http://" + self.proxy} if self.proxy else None

        # Try to send data through the proxy.
        modified = ""
        try:
            new_message =  requests.post(url, proxies = proxies,
                                         headers=headers,data=message).content
            if new_message != message:
                message = new_message
                modified = "(modified!)"

        except requests.exceptions.ProxyError:
            print("[!] error: can't connect to proxy!")

        # Print message.
        msg_str = self._data_repr(message)
        if to_server:
            direction = "C >> S", client_str, server_str
        else:
            direction = "S >> C", server_str, client_str

        print(f"{direction[0]} [ {direction[1]} >> {direction[2]} ] ",
              f"[ {date_str} ] [ {len(message)} ] {modified}\n{msg_str}\n")

        return message


class TCPRelayRequstHandler(RelayRequstHandlerMixIn, StreamRequestHandler):
    pass

class UDPRelayRequstHandler(RelayRequstHandlerMixIn, DatagramRequestHandler):
    pass


class RelayServerMixIn(NonBlockingServerMixIn):
    """Relay server mixin class that adds the capability to receive connections
    and forwards them to a target address. Must be inherited with another server
    class."""

    def __init__(self, server_address, request_handler, target_addr,
                 webserver_addr, proxy, event_k, *args,
                 bind_and_activate = True):
        """Initialize realy server mix in."""

        # Initialize target address, InterceptionServer address and proxy.
        self.target_addr = target_addr
        self.webserver_addr = webserver_addr
        self.proxy = proxy

        # An event for making sure no thread hangs.
        self.event_k = event_k

        # Initialize the NonBlockingServerMixIn and inherited with this mix in.
        NonBlockingServerMixIn.__init__(self, server_address, request_handler,
                                        bind_and_activate)


class TCPRelayServer(RelayServerMixIn, ThreadingTCPServer):
    pass

class UDPRelayServer(RelayServerMixIn, ThreadingUDPServer):
    pass


class SSLInterceptRequestHandler(RelayRequstHandlerMixIn, StreamRequestHandler):
    """Request handler that performs SSL interception. Works the same as
    TCPRelayServer but wrapping the socket in SSL context and change the
    forwarding method."""

    def setup(self):
        """Set up the handler and create an SSL connection with the target."""

        # Create TCP realy connection and wrap it with ssl.
        super().setup()
        self._wrap_target_connection()


    def _wrap_target_connection(self):
        """Wrap the target connection with SSL."""

        # Create a SSL Context.
        ctx = _SSLHelper.create_context(self.server.tls_ver,self.server.ciphers)
        if self.server.client_cert and self.server.client_key:
            ctx.load_cert_chain(self.server.client_cert, self.server.client_key)

        # Wrap socket with SSL Context and do handshake.
        hostname = self.server.sni if self.server.sni else self.connection.sni
        self.t_sock = _SSLHelper.wrap_socket(self.t_sock, ctx,
                                             server_hostname = hostname)


    def forward(self, recv_sock, send_sock, to_server):
        """Receiving data from recv_sock and send it to send_sock."""

        data  = self._ssl_recv(recv_sock)
        if not data:
            return False
        if data == "SSLWantReadError":
            return True
        data = self._proxify(data, to_server)
        self._ssl_send(send_sock, data)

        return True


    def _ssl_recv(self, sock):
        """Receives available data from SSLSocket and handle with
        SSLWantReadError."""

        try:
            data  = sock.recv(BUFSIZE)
        except ssl.SSLWantReadError:
            return "SSLWantReadError"

        return data


    def _ssl_send(self, sock, data):
        """Sends data with SSLSocket (sock)."""

        while True:
            try:
                sock.send(data)
            except ssl.SSLWantWriteError:
                continue
            break


class SSLServer(NonBlockingServerMixIn, ThreadingTCPServer):
    """SSLServer that receives SSL Connections."""

    def __init__(self, server_address, request_handler, server_cert, server_key,
                 tls_ver = ssl.PROTOCOL_TLS, sni = None, ciphers = None,
                 bind_and_activate=True):
        """Initialize the SSL server."""

        self.tls_ver = tls_ver
        self.sni = sni
        self.ciphers = ciphers
        sock = socket.socket(self.address_family, self.socket_type)

        # Adding SSL context and wraping the server's socket with it.
        ctx = _SSLHelper.create_context(self.tls_ver, self.ciphers)
        ctx.load_cert_chain(server_cert, server_key)
        _SSLHelper.set_sni_callback(ctx)
        sock = _SSLHelper.wrap_socket(sock, ctx, server_side=True)

        # Initialize NonBlockingServerMixIn and ThreadingTCPServer.
        super().__init__(server_address, request_handler,bind_and_activate,sock)


class SSLInterceptServer(RelayServerMixIn, SSLServer):
    """SSL intercept server that receives SSL connections and forwards them to
    a target address."""

    def __init__(self, server_address, request_handler, target_addr,
                 webserver_addr, proxy, event_k, server_cert, server_key,
                 tls_ver, sni, client_cert, client_key, bind_and_activate=True):
        """Initialize SSL intercept server."""

        self.client_cert = client_cert
        self.client_key = client_key

        RelayServerMixIn.__init__(self, server_address, request_handler,
                                  target_addr, webserver_addr, proxy, event_k,
                                  bind_and_activate = False)
        SSLServer.__init__(self, server_address, request_handler, server_cert,
                           server_key, tls_ver, sni, bind_and_activate)


class MixedInterceptRequestHandler(SSLInterceptRequestHandler):
    """Request handler that handles connections that changes from plain TCP to
    SSL."""

    def setup(self):
        """Setup handler like TCPRelayRequestHandler."""

        super(SSLInterceptRequestHandler, self).setup()
        self.is_ssl = False


    def forward(self, recv_sock, send_sock, to_server):
        """Receiving data from recv_sock and send it to send_sock."""

        if self.is_ssl:
            return super().forward(recv_sock, send_sock, to_server)


        data  = recv_sock.recv(BUFSIZE, socket.MSG_PEEK)
        if data.startswith(b"\x16\x03"):
            self.is_ssl = True
            self._wrap_ssl()
            return True

        return super(SSLInterceptRequestHandler, self).forward(recv_sock,
                                                               send_sock,
                                                               to_server)


    def _wrap_ssl(self):
        """Wrap the connection from both side of the relay with SSL."""

        # Wrap SSL with incoming connection.
        ctx = _SSLHelper.create_context(self.server.tls_ver,self.server.ciphers)
        _SSLHelper.set_sni_callback(ctx)
        ctx.load_cert_chain(self.server.server_cert, self.server.server_key)
        self.connection = _SSLHelper.wrap_socket(self.connection, ctx,
                                                 server_side=True)

        # Wrap the connection with the target with SSL.
        self._wrap_target_connection()


class MixedInteceptServer(RelayServerMixIn, ThreadingTCPServer):
    """TCP relay server that handles connections that change from TCP to SSL in
    the middle of the connection."""

    def __init__(self, server_address, request_handler, target_addr,
                 webserver_addr, proxy, event_k, server_cert, server_key,
                 tls_ver, sni, ciphers, client_cert, client_key,
                 bind_and_activate=True):
        """Initialize nixed intercept server."""

        # Setting certificates, sni and, TLS version for connection changes.
        self.sni = sni
        self.ciphers = ciphers
        self.tls_ver = tls_ver
        self.server_cert = server_cert
        self.server_key = server_key
        self.client_cert = client_cert
        self.client_key = client_key

        # Set TCPRelayServer.
        super().__init__(server_address, request_handler, target_addr,
                         webserver_addr, proxy, event_k,
                         bind_and_activate = bind_and_activate)


class ModificationHandler(BaseHTTPRequestHandler):
    """Handle interception requests and modify them if needed."""

    def setup(self):
        """Set up the handler and create an SSL connection with the target."""

        super().setup()

        # Add script.
        self.script = self.server.script


    def do_POST(self):
        content_length = int(self.headers.get('content-length'))
        to_server = self.headers.get("To-Server") == "True"
        body = self.rfile.read(content_length)

        # Run modification script if exists.
        if self.script:
            body = self._run_script(body, to_server)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
        return


    # All the methods will act the same as do_POST.
    do_GET = do_POST
    do_PUT = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST


    def log_message(self, format, *args):
        return


    def _run_script(self, message, to_server):
        """Run a script to modify the request to the server or the response from
        the server."""

        new_message = None

        if to_server and hasattr(self.script, 'handle_request'):
            new_message = self.script.handle_request(message)

        if not to_server and hasattr(self.script, 'handle_response'):
            new_message = self.script.handle_response(message)

        if not new_message:
            print("[!] Error: make sure handle_request and handle_response",
                  "both return a message.")
            new_message = message

        return new_message


class InterceptionServer(ThreadingHTTPServer):
    """HTTP server that receive interceptd SSL communication and modify it if
    needed."""

    def __init__(self, server_address, request_handler, script = None,
                 bind_and_activate=True):
        """Initialize interception server."""

        # Load script if exists.
        self.script = None
        if script:
            loader = SourceFileLoader(script, script)
            self.script = loader.load_module()

        super().__init__(server_address, request_handler, bind_and_activate)


def _set_args():
    """Sets argument parser."""

    # Parser for address:port format.
    parse_addr = lambda addr: (*addr.split(":")[:-1],int(addr.split(":")[-1]))

    # Parser for file path
    def file_path(path):
        if os.path.exists(path):
            return path
        raise ValueError(f"{path} is not exists.")

    # Parser for TLS version.
    parse_tls = lambda k: TLS_VERSIONS[k]

    parser = argparse.ArgumentParser(description = f"""{__prog_name__} version
                                                       {__version__}""",
                                     epilog = """For dumping SSL (pre-)master
                                                 secrets to a file, set the
                                                 environment variable
                                                 SSLKEYLOGFILE with a file path.
                                                 Useful for Wireshark.""")

    parser.add_argument("-m", "--mix-connection",
                        action = "store_true",
                        dest = "mix",
                        help = """Perform TCP relay without SSL handshake. If
                                  one of the relay sides starts an SSL handshake,
                                  wrap the connection with SSL, and intercept
                                  the communication. A listener certificate
                                  and private key must be provided.""")

    parser.add_argument("-l", "--listen",
                        action = "extend",
                        nargs = "+",
                        metavar = "[u|t:]<interface>:<port>",
                        type = parse_addr,
                        dest = "servers",
                        help = """Creates SSLInterceptServer listener that
                                  listens on the specified interface and port.
                                  Can create multiple listeners with a space
                                  between the parameters. Adding "u:" before the
                                  address will make the listener listen in UDP
                                  protocol. TCP protocol is the default but
                                  adding "t:" for cleanliness is possible. The
                                  number of listeners must match the number of
                                  targets. The i-th listener will relay to the
                                  i-th target.""",
                        required = True)

    parser.add_argument("-t", "--target",
                        action = "extend",
                        nargs = "+",
                        metavar = "[u|t:]<addr>:<port>",
                        type = parse_addr,
                        dest = "targets",
                        help = """Directs each SSLInterceptServer listener to
                                  forward the communication to a target address
                                  and port. Can create multiple targets with a
                                  space between the parameters. Adding "u:"
                                  before the address will make the target
                                  communicate in UDP protocol.TCP protocol is
                                  the default but adding "t:" for cleanliness is
                                  possible. The number of listeners must match
                                  the number of targets. The i-th listener will
                                  relay to the i-th target.""",
                        required = True)

    parser.add_argument("-lc", "--listener-cert",
                        action = "store",
                        metavar = "<cert_path>",
                        type = file_path,
                        dest = "server_cert",
                        help = """The certificate that the listener uses when a
                                  client contacts him. Can be a self-sign
                                  certificate if the client will accept it.""",
                        default = None)

    parser.add_argument("-lk", "--listener-key",
                        action = "store",
                        metavar = "<key_path>",
                        type = file_path,
                        dest = "server_key",
                        help = """The private key path for the listener
                                  certificate.""",
                        default = None)

    parser.add_argument("-tc", "--target-cert",
                        action = "store",
                        metavar = "<cert_path>",
                        type = file_path,
                        dest = "client_cert",
                        help = """The certificate that used to create a
                                  connection with the target. Can be a
                                  self-sign certificate if the target will
                                  accept it. Doesn't necessary if the target
                                  doesn't require a specific certificate.""",
                        default = None)

    parser.add_argument("-tk", "--target-key",
                        action = "store",
                        metavar = "<key_path>",
                        type = file_path,
                        dest = "client_key",
                        help = """The private key path for the target
                                  certificate.""",
                        default = None)

    parser.add_argument("-w", "--webserver",
                        action = "store",
                        metavar = "<interface>:<port>",
                        type = parse_addr,
                        dest = "bind_webserver",
                        help = f"""Specifies the interface and the port the
                                   InterceptionServer webserver will listens
                                   on. If omitted the default is
                                   {BIND_WEBSERVER[0]}:{BIND_WEBSERVER[1]}""",
                        default = BIND_WEBSERVER)

    parser.add_argument("-p", "--proxy",
                        action = "store",
                        metavar = "<addr>:<port>",
                        dest = "proxy",
                        help = """Specifies the address and the port of a proxy
                                  between the InterceptionServer webserver and
                                  the SSLInterceptServer. Can be configured so
                                  the communication will go through a local
                                  proxy like Burp. If omitted, the communication
                                  will be printed in the shell only.""",
                        default = None)

    parser.add_argument("-s", "--script",
                        action = "store",
                        metavar = "<script_path>",
                        type = file_path,
                        dest = "script",
                        help = """A path to a script that the InterceptionServer
                                  webserver executes. Must contain the function
                                  handle_request(message) that will run before
                                  sending it to the target or
                                  handle_response(message) after receiving a
                                  message from the target. Can be omitted if
                                  doesn't necessary.""",
                        default = None)

    parser.add_argument("--sni",
                        action = "store",
                        metavar = "<server_name>",
                        dest = "sni",
                        help = """If there is a need to change the server name
                                  in the SSL handshake with the target. If
                                  omitted, it will be the server name from the
                                  handshake with the listener.""",
                        default = None)

    parser.add_argument("-tv", "--tls-version",
                        metavar=f"<{'|'.join(set(TLS_VERSIONS)-{'default'})}>",
                        choices = TLS_VERSIONS.values(),
                        type = parse_tls,
                        dest = "tls_ver",
                        help = """If needed can be specified a specific TLS
                                  version.""",
                        default = "defualt")

    parser.add_argument("-ci", "--ciphers",
                        action = "store",
                        metavar = "<ciphers>",
                        dest = "ciphers",
                        help = """Sets different ciphers than the python
                                  defaults for the TLS handshake. It should be a
                                  string in the OpenSSL cipher list format (https://www.openssl.org/docs/manmaster/man1/ciphers.html).""",
                        default = None)


    return parser


def main():

    # Parse command-line arguments.
    parser = _set_args()
    try:
        args = parser.parse_args()
    except ValueError:
        print(f"[!] error: Invalid options. please try \"{__prog_name__} -h\".")
        sys.exit(1)

    # Verify mix parameter.
    if args.mix and not (args.server_cert and args.server_key):
        print(f"[!] error: mix connection with certificate or private key.",
              f"please try \"{__prog_name__} -h\".")
        sys.exit(1)

    # Choose the right server type for the listener.
    if args.mix:
        server_class = MixedInteceptServer
        handler_class = MixedInterceptRequestHandler
    elif args.server_cert and args.server_key:
        server_class = SSLInterceptServer
        handler_class = SSLInterceptRequestHandler
    else:
        print("[!] Certificate or private key not provided! Forwarding without",
              "SSL interception!")
        server_class = TCPRelayServer
        handler_class = TCPRelayRequstHandler

    # Set an event for keyboard interrupt.
    event_k = Event()

    # Start listeners.
    listeners = []
    for addr, target in zip(args.servers, args.targets):

        # Start UDPRelayServer for UDP
        if addr[0] == target[0] == "u":
            addr, target = addr[1:], target[1:]
            server = UDPRelayServer
            handler = UDPRelayRequstHandler
        else:
            server = server_class
            handler = handler_class

        if len(addr) == len(target) == 3:
            addr, target = addr[1:], target[1:]

        listener = server(addr, handler, target, args.bind_webserver,
                          args.proxy, event_k, args.server_cert,
                          args.server_key, args.tls_ver, args.sni, args.ciphers,
                          args.client_cert, args.client_key)
        listeners.append(listener)
        Thread(target = listener.serve_forever, daemon = True).start()

    # Start interception server.
    print("[+] Modification webserver is listening on ",
          f"{args.bind_webserver[0]}:{args.bind_webserver[1]}")
    webserver = InterceptionServer(args.bind_webserver, ModificationHandler,
                                   args.script)

    try:
        webserver.serve_forever()
    except KeyboardInterrupt:
        event_k.set()
        [listener.shutdown() for listener in listeners]


if __name__ == '__main__':
    main()
