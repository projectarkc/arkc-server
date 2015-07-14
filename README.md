#ArkC-server

ArkC is a lightweight proxy based on Python and Twisted. It is designed to be proof to IP blocking m
easures.

ArkC-Server is the server-side utility.

##Setup and Requirement

Running ArkC-Server requires Python 2 and Twisted (Python 3 is currently not supported for compatibility issues). A virtual environment is generally recommended.

For Debian or Ubuntu users:

    sudo apt-get install virtualenv python-dev
    virtualenv ~/virtualenvs/arkc-server
    . ~/virtualenvs/arkc-server/bin/activate
    pip install -r requirements.txt
    chmod +x install.sh
    ./install.sh

##Usage

Run

	python main.py

##License

Copyright 2015 ArkC contributers

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2. You should obtain a copy of th
e license with the software.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
