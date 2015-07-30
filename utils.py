def addr_to_str(addr):
    """Convert a Twisted IAddress object to readable string."""
    return addr.host + ":" + str(addr.port)