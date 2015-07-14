pip install -r requirements.txt
wget http://twistedmatrix.com/Releases/Web/15.2/TwistedWeb-15.2.1.tar.bz2
tar -xf TwistedWeb-15.2.1.tar.bz2
cd TwistedWeb-15.2.1 && python setup.py install
cd ..
rm TwistedWeb-15.2.1.tar.bz2
rm -fr TwistedWeb-15.2.1
