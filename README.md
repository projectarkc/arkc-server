#ArkC-server

ArkC is a lightweight proxy based on Python 3 and Twisted. It is designed to be proof to IP blocking m
easures.

ArkC-Server is the server-side utility.

##Setup and Requirement

Running ArkC-Server requires Python 3 and Twisted. A virtual environment is generally recommended.

For Debian or Ubuntu users:

    sudo apt-get install python3 python3-dev python3-pip virtualenv
    virtualenv -p python3 ~/virtualenvs/arkc-server
    . ~/virtualenvs/arkc-server/bin/activate
    pip install -r requirements.txt

##Usage

Run

	python3 main.py

##License

Copyright 2015 ArkC contributers

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2. You should obtain a copy of th
e license with the software.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
