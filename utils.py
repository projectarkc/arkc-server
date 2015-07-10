def http_proxy_request_parser(proxy_request):
    """Parse host, port and request from an HTTP proxy request."""
    # split request line and headers
    request_line, headers = proxy_request.split("\n", 1)
    # TODO: potential bug with Windows/*nix line ending issue

    # translate proxy request to stadard HTTP request
    # TODO: ugly hack. re solution for this?
    host_port, path = request_line.split("/", 3)[-2:]
    # TODO: issue with requests without "/" after hostname in request line
    request_line = request_line.split(" ", 1)[0] + " /" + path
    headers = headers.replace("Proxy-connection", "Connection")
    request = request_line + "\n" + headers + "\n\n"

    # Parse host and port
    try:
        host, port_str = host_port.split(":")
        port = int(port_str)
    except ValueError:
        host = host_port
        port = 80
    return (host, port, request)
