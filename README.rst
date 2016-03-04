ArkC-Server V0.2
================

ArkC is a lightweight proxy designed to be proof to IP blocking measures
and offer high proxy speed via multi-connection transmission and
swapping connections.

ArkC-Server is the server-side utility.

What is ArkC?
-------------

ArkC allows users to enjoy free web browsing without worrying about censorship measures like IP blacklists. For VPS owners they are better equipped to share their VPS to people around them, or share online, the proxy hosted on their VPS.

For a more detailed description, please visit our website and read our page `Understand ArkC <https://arkc.org/understand-arkc/>`__. 中文版本的介绍在这一页面 `ArkC的原理 <https://arkc.org/understand_arkc_zh_cn/>`__。

Setup and Requirement
---------------------

For a probably more detailed guide: `Deployment and Installation <https://arkc.org/12-2/deployment-and-installation/>`__. 对于安装与部署的中文说明在 `部署与安装ArkC <https://arkc.org/12-2/deployment_install_zh_cn/>`__
这一页面。

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

If you need to support portable proxy function, like MEEK (required to integrate with GAE) or obfs4proxy, please follow the above link to arkc.org.

Privilege
---------

By default ArkC Server needs to listen to port 53 to support DNS relay
function (client may connect to server through multiple steps of DNS
queries). Usually this requires pre-configuration or root privillege.

Usage
-----

For detailed documentation, please visit our `Documentation page <https://arkc.org/documentation/>`__.

中文版本的使用文档，请参见 `如何使用ArkC <https://arkc.org/documentation_zh_cn/>`__。

Run

::

    arkcserver [-h] [-v] [-ep (use external proxy)] [-t (use transmit mode)] [-c <Path of the config Json file, default = config.json>]

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

+---------------------+---------------------------------------------------------------+------------------------------------------+
| Index name          | Value Type & Description                                      | Required / Default                       |
+=====================+===============================================================+==========================================+
| udp\_port           | int, udp listening port                                       | (0.0.0.0:)53                             |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| proxy\_port         | int, local/ext proxy port                                     | 8100(local)/8123(ext)                    |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| local\_cert\_path   | str, path of server pri                                       | REQUIRED                                 |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| central\_cert\_path | str, path of central server pub                               | REQUIRED if using transmit mode          |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| clients             | list, (path of client pub, sha1 of client pri) pairs          | REQUIRED unless "clients_db" is set      |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| clients_db          | str, path of the sqlite db where keys are stored or updated   | REQUIRED unless "clients" is set         |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| pt\_exec            | str, command line of pluggable transport executable           | "obfs4proxy"                             |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| obfs\_level         | integer, obfs level 0~3                                       | 0                                        |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| meek\_url           | str, URL of meek's GAE destination                            | "https://arkc-reflect1.appspot.com/"     |
+---------------------+---------------------------------------------------------------+------------------------------------------+
| socks\_proxy        | list, (host, port)                                            | None (Unused)                            |
+---------------------+---------------------------------------------------------------+------------------------------------------+

Note: if obfs\_level is set to a non-zero value, obfs4\_exec must be
appropriate set. Obfs4 will use an IAT mode of (obfs\_level - 1), which
means if obfs\_level is set to 2 or 3, the connection speed may be
affected.

Join our "Shared Server Plan"
-----------------------------

We want to provide free proxy service for netizens behind censorship firewalls, thus may we invite you to join our "Shared Server Plan" and add your VPS to our server pool, open for all ArkC users.

We are raising fund to provide rewards for VPS owners in this plan via Google Play / iTunes gift cards. Read the `Plan homepage <https://arkc.org/shared-server-plan/>`__ for more information.

Questions | 使用或安装时遇到问题
--------------------------------------------------

Go to our `FAQ page <https://arkc.org/faq/>`__.

常见问题请参考 `FAQ <https://arkc.org/faq_zh_cn/>`__。

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
