FROM ubuntu:16.04

RUN apt-get clean && apt-get install -f && dpkg --configure -a && apt-get update
RUN apt-get install -y gzip wget python-flask libxml-security-c-dev libxmlsec1 libxmlsec1-openssl libxmlsec1-dev libxml2 python-libxml2 python-libxml2-dbg  libxml2-dev libxslt-dev libltdl-dev python-dev libssl-dev openssl-* libssl-dev  python-dev build-essential python-pip

WORKDIR /tmp

RUN wget http://labs.libre-entreprise.org/frs/download.php/897/pyxmlsec-0.3.1.tar.gz
RUN tar -zxvf pyxmlsec-0.3.1.tar.gz
RUN cd pyxmlsec-0.3.1 && sed -i 's/reply = raw_input(msg)/reply = [1]/'  ./setup.py && ./setup.py build && ./setup.py install

ADD . /app/
WORKDIR /app

EXPOSE 28080
ENTRYPOINT ["python", "saml_idp_gsuites.py"]
