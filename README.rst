ArkC-Server V0.2
================

ArkC is a lightweight proxy designed to be proof to IP blocking measures
and offer high proxy speed via multi-connection transmission and
swapping connections.

ArkC-Server is the server-side utility.

Setup and Requirement
---------------------

Running ArkC-Server requires Python 2.7 and Twisted (Python 3 is
currently not supported for compatibility issues) and txsocksx. A
virtual environment is generally recommended.

::

    sudo pip install arkcserver

You may need python development environment.

Debian/Ubuntu users:

::

    sudo apt-get install python python-pip python-dev

Fedora users:

::

    sudo yum python python-pip python-devel

You may also install ArkC Server from source.

Privilege
---------

By default ArkC Server needs to listen to port 53 to support DNS relay
function (client may connect to server through multiple steps of DNS
queries). Usually this requires pre-configuration or root privillege.

Usage
-----

Run

::

    arkcserver [-h] [-v] [-ep (use external proxy)] [-c <Path of the config Json file, default = config.json>]

In this version, any private certificate should be in the form of PEM
without encryption, while any public certificate should be in the form
of ssh-rsa.

For the configuration file, you can find an example here:

::

    {
        "local_cert_path": "testfiles/server",
        "clients": [
            ["testfiles/client1.pub", <sha1 of client1's private key>],
            ["testfiles/client2.pub", <sha1 of client2's private key>]
        ]
    }

For a full list of settings:

+---------------------+--------------------------------------------------------+---------------------------------------+
| Index name          | Value Type & Description                               | Required / Default                    |
+=====================+========================================================+=======================================+
| udp\_port           | int, udp listening port                                | (0.0.0.0:)53                          |
+---------------------+--------------------------------------------------------+---------------------------------------+
| proxy\_port         | int, local/ext proxy port                              | 8100(local)/8123(ext)                 |
+---------------------+--------------------------------------------------------+---------------------------------------+
| local\_cert\_path   | str, path of server pri                                | REQUIRED                              |
+---------------------+--------------------------------------------------------+---------------------------------------+
| clients             | list, (path of client pub, sha1 of client pri) pairs   | REQUIRED                              |
+---------------------+--------------------------------------------------------+---------------------------------------+
| pt\_exec            | str, command line of pluggable transport executable    | "obfs4proxy"                          |
+---------------------+--------------------------------------------------------+---------------------------------------+
| obfs\_level         | integer, obfs level 0~3                                | 0                                     |
+---------------------+--------------------------------------------------------+---------------------------------------+
| meek\_url           | str, URL of meek's GAE destination                     | "https://arkc-reflect.appspot.com/"   |
+---------------------+--------------------------------------------------------+---------------------------------------+
| socks\_proxy        | list, (host, port)                                     | None (Unused)                         |
+---------------------+--------------------------------------------------------+---------------------------------------+

Note: if obfs\_level is set to a non-zero value, obfs4\_exec must be
appropriate set. Obfs4 will use an IAT mode of (obfs\_level - 1), which
means if obfs\_level is set to 2 or 3, the connection speed may be
affected.

Acknowledgements
----------------

The http proxy part is based on
`twisted-connect-proxy <https://github.com/fmoo/twisted-connect-proxy>`__
by Peter Ruibal, released under BSD License.

The server-end software adapted part of the pyotp library created by
Mark Percival m@mdp.im. His code is reused under Python Port copyright,
license attached.

File arkcserver/ptserver.py is based on ptproxy by Dingyuan Wang. Code reused and
edited under MIT license, attached in file.

License
-------

Copyright 2015 ArkC Technology.

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2.
You should obtain a copy of the license with the software.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
