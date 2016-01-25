#ArkC-server

ArkC is a lightweight proxy based on Python and Twisted, and uses PyCrypto for encryption. It is designed to be proof to IP blocking measures.

ArkC-Server is the server-side utility.

##Setup and Requirement

Running ArkC-Server requires Python 2.7 and Twisted (Python 3 is currently not supported for compatibility issues) and txsocksx. A virtual environment is generally recommended.

For Debian or Ubuntu users:

```
sudo apt-get install python-virtualenv python-dev python-psutil obfs4proxy
virtualenv ~/virtualenvs/arkc-server
. ~/virtualenvs/arkc-server/bin/activate
pip install -r requirements.txt
chmod +x install.sh
./install.sh
```

##Usage

Run

```
python main.py [-h] [-v] [-ep (use external proxy)] [-c <Path of the config Json file, default = config.json>]
```

In this version, any private certificate should be in the form of PEM without encryption, while any public certificate should be in the form of ssh-rsa. Note that ssh-rsa files should not include extra blank lines because they are used for hash.

For the configuration file, you can find an example here:

```
{
    "local_cert_path": "/home/tony/arkc/testfiles/server",
    "clients": [
        ["/home/tony/arkc/testfiles/client1.pub", "<sha1 of client1's private key>"],
        ["/home/tony/arkc/testfiles/client2.pub", "<sha1 of client2's private key>"]
    ]
}
```

For a full list of settings:

| Index name            | Value Type & Description | Required / Default   |
| ----------------------|:------------------------:| --------------------:|
| udp_port              | int, udp listening port  | (0.0.0.0:)53       |
| proxy_port            | int, local/ext proxy port| 8100(local)/8123(ext)|
| local_cert_path       | str, path of server pri  | REQUIRED             |
| clients       | list, (path of client pub, sha1 of client pri) pairs  | REQUIRED             |
| pt_exec		| str, command line of pluggable transport executable | "obfs4proxy" |
| obfs_level		| integer, obfs level 0~3 | 0 |
| meek_url   | str, URL of meek's GAE destination| "https://arkc-reflect.appspot.com/"|
| socks_proxy | list, (host, port)      | None (Unused)           |

Note: if obfs_level is set to a non-zero value, obfs4_exec must be appropriate set. Obfs4 will use an IAT mode of (obfs_level - 1), which means if obfs_level is set to 2 or 3, the connection speed may be affected.

##Acknowledgements

The http proxy part is based on [twisted-connect-proxy](https://github.com/fmoo/twisted-connect-proxy) by Peter Ruibal, released under BSD License.

The server-end software adapted part of the pyotp library created by Mark Percival <m@mdp.im>. His code is reused under Python Port copyright, license attached.

File ptclient.py is based on ptproxy by Dingyuan Wang. Code reused and edited under MIT license, attached in file.

##License

Copyright 2015 ArkC Technology.

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2. You should obtain a copy of the license with the software.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
