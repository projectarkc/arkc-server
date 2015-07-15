def decrypt_udp_msg(msg, pri, client_pub):
    """Return (salt, client_sha1, string).

    The encrypted message should be
        server_pub(
            salt +
            sha1(local_pub) +
            local_pri(salt + string)
            )
    """
    decrypted_msg = pri.decrypt(msg)
    salt = decrypted_msg[:16]
    client_sha1 = decrypted_msg[16: 36]
    salt_string = client_pub.decrypt(decrypted_msg[36:])
    salt1, string = salt_string[:16], salt_string[16:]
    assert salt == salt1
    assert len(string) == 16
    return salt, client_sha1, string


def generate_auth_msg(salt, string, pri, client_pub):
    """Generate encrypted message.

    The message is in the form
        server_pri(salt + local_pub(string))
    """
    encrypted_string = client_pub.encrypt(string, "r")
    return pri.encrypt(salt + encrypted_string, "r")
