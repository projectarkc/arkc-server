#! /usr/bin/env python3

import socket


class SingleClientHandler:

    def __init__(self, client_host, client_port):
        self.client_host = client_host
        self.client_port = client_port
        self.bufsize = 4096
        self.listen = True

    @staticmethod
    def connect_target(target_host, target_port):
        target_socket = socket.socket()
        target_socket.connect((target_host, target_port))
        return target_socket

    def forward_request(self, target_host, target_port, request):
        target_socket = SingleClientHandler.connect_target(
            target_host, target_port)
        target_socket.send(request)
        response = b""
        response_segment = target_socket.recv(self.bufsize)
        while len(response_segment) > 0:
            response += response_segment
            response_segment = target_socket.recv(self.bufsize)
        target_socket.close()
        self.client_socket.send(response)
        # return response

    def http_request_handler(self, request):
        """Translate HTTP proxy request to standart HTTP request,
        parse host and port from HTTP Header and send the request to `forward_request`."""
        r_str = request.decode("UTF-8")

        # split request line and headers
        request_line, headers = r_str.split("\n", 1)
        # TODO: potential bug with Windows/*nix line ending issue

        # translate proxy request to stadard HTTP request
        # TODO: ugly hack. re solution for this?
        host_port, path = request_line.split("/", 3)[-2:]
        request_line = r_str.split(" ", 1)[0] + " /" + path
        headers = headers.replace("Proxy-connection", "Connection")
        request = bytes(request_line + "\n" + headers, "UTF-8")

        # Parse host and port
        try:
            host, port_str = host_port.split(":")
            port = int(port_str)
        except ValueError:
            host = host_port
            port = 80
        self.forward_request(host, port, request)
        # return self.forward_request(host, port, request)
        # return (host, port, request)

    def client_listener(self):
        """Emulate the 'listen' behavior. Receive requests from the client constantly."""
        while self.listen:
            self.client_socket = socket.socket()
            self.client_socket.connect((self.client_host, self.client_port))
            request = b""
            request_segment = self.client_socket.recv(self.bufsize)
            while len(request_segment) > 0:
                request += request_segment
                request_segment = self.client_socket.recv(self.bufsize)
            self.http_request_handler(request)
            self.client_socket.close()
        # TODO: async operation?
        # TODO: Is it possible to reuse existing connections?

    def terminate(self):
        self.listen = False

if __name__ == "__main__":
    h = SingleClientHandler("127.0.0.1", 80)
    print(h.http_request_handler(
        b'GET http://www.example.com/ HTTP/1.1\nHost: www.example.com\nProxy-Connection: keep-alive\n\n'))


# TODO: seems slow. Is there any performance bottleneck?

# TODO: support multiple clients
# TODO: support other protocols
