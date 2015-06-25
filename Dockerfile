FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y gzip wget python-cherrypy3 libxml-security-c-dev libxmlsec1 libxmlsec1-openssl libxmlsec1-dev libxml2 python-libxml2 python-libxml2-dbg  libxml2-dev libxslt-dev libltdl-dev python-dev libssl-dev openssl-* libssl-dev  python-dev build-essential

WORKDIR /tmp

RUN wget http://labs.libre-entreprise.org/frs/download.php/897/pyxmlsec-0.3.1.tar.gz
RUN tar -zxvf pyxmlsec-0.3.1.tar.gz
RUN cd pyxmlsec-0.3.1 && sed -i 's/reply = raw_input(msg)/reply = [1]/'  ./setup.py && ./setup.py build && ./setup.py install

ADD . /app/
WORKDIR /app

EXPOSE 28080
ENTRYPOINT ["python", "apps.py"]