#ArkC-server

ArkC is a lightweight proxy based on Python and Twisted, and uses PyCrypto for encryption. It is designed to be proof to IP blocking measures.

ArkC-Server is the server-side utility.

##Setup and Requirement

Running ArkC-Server requires Python 2.7 and Twisted (Python 3 is currently not supported for compatibility issues) and txsocksx. A virtual environment is generally recommended.

For Debian or Ubuntu users:

    sudo apt-get install virtualenv python-dev
    virtualenv ~/virtualenvs/arkc-server
    . ~/virtualenvs/arkc-server/bin/activate
    pip install -r requirements.txt
    chmod +x install.sh
    ./install.sh

##Usage

Run

	python main.py [-h] [-v] [-up UDP_PORT] [-ep (use external proxy)] 
		[-pp PROXY_PORT (local, HTTP)] [-tp TOR_PORT (local, SOCKS4)]
               [-rp REMOTE_PORT (remote host listens on)] -rc REMOTE_CERT_PATH -lc LOCAL_CERT_PATH

In this version, any private certificate should be in the form of PEM without encryption, while any public certificate should be in the form of ssh-rsa. Note that ssh-rsa files should not include extra blank lines because they are used for hash.

##Acknowledgements

The http proxy part is based on [twisted-connect-proxy](https://github.com/fmoo/twisted-connect-proxy) by Peter Ruibal, released under BSD License.

##License

Copyright 2015 ArkC contributers

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2. You should obtain a copy of th
e license with the software.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
