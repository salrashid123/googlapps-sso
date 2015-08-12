#!/usr/bin/python

import base64
import datetime
import getopt
import getpass
import md5
import random
import sys
import time
import urllib
from urlparse import urlparse
import xml.dom.minidom
import zlib
import cherrypy
from xml.sax.saxutils import escape
from socket import gethostname
import libxml2
import xmlsec
import cgi
import urllib2
import httplib, ssl, urllib2, socket

"""

Sample app for SSO between google apps domains.

This demonstrates SAML SSO with google properties and is is intended for *testing/POC only*
The script basically runs a SAML IDP within a docker container.


To use:
  1. Create public/private keypair
      --> remember to set the CN= to your domain
      --> the certificates provided in github is set for sso.yourdomain.com
  2. Login to your google apps admin console (admin.google.com/a/yourdomain.com)
      --> Navigate to https://admin.google.com/AdminHome?fral=1#SecuritySettings:flyout=sso
      --> set following config:
          Login:  https://sso.yourdomain.com:28080/login
          Logout: https://sso.yourdomain.com:28080/logout
          Change Password: https://sso.yourdomain.com:28080/passwd
      --> upload the public cert (ssl.crt)
  3. If you are running the docker container on your laptop, you need to speicfy the host where your IdP is running,
      --> On your laptop edit
          /etc/hosts
          127.0.0.1 localhost sso.yourdomain.com
  4. Install docker.io
  5. make a folder called sso and copy all the files from the github repo into it.
  6. Create the docker container
          docker build -t sso .
  7. Copy the certificates to /tmp/certs (for example) so that the local certs are visible to the container.        
  8. Run the container
          docker run -t -p 28080:28080 -v /tmp/certs/:/certs/:ro salrashid123/appssso --debug --use_ssl --cert_file=/certs/ssl.crt --key_file=/certs/ssl.key --key_blank_pwd
  9. At this point, the IDP is running locally on port sso.yourdomain.com:28080
  10. If you attempt a new login to https://mail.google.com/a/yourdomain.com, you will get redirected to a login screen on your IDP
  11. The IDP will authenticate **ANY** user in your apps domain so if you have a user called user1@yourdomain.com, enter in 'user1', any password
      and yourdomain.com in the IDP login screen
  12. If successful, you will get redirected to the SAML POST binding screen so  you can see the actual XML signed POST text.
  13. Click continue and if the sigatures and validUntil= parameters are ok, you will be logged in as user1


If you want to generate your own keypairs:
openssl req -x509 -newkey rsa:2048 -keyout ssl.key -out ssl.crt -days 365 -nodes


------------------------------------------------------------------------------------------------------------------------

Dockerfile
================================================
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

================================================


docker build -t sso .


================================================

./apps.py --debug --use_ssl --cert_file=ssl.crt --key_file=ssl.key --key_blank_pwd

"""
class SignatureError(Exception):
  pass

class AuthN(object):

  def __init__(self, port, debug_flag, protocol, 
               saml_issuer, cert_file, key_file, key_pwd):
    self.realm = "authn"
    self.debug_flag = debug_flag
    self.key_file = key_file
    self.key_pwd = key_pwd
    self.cert_file = cert_file
    self.protocol = protocol

    self.log ('--------------------------------')
    self.log ('-----> Starting authn.py <------')
    self.log ('--------------------------------')

    # stores the authenticated sessions
    self.authnsessions = {}
    self.recipients = {}
    self.saml_issuer = saml_issuer
    self.passwd_db = {}     

  #Main landing page
  def index(self):
    indexHTML = ('<html><title>Authn Landing Page</title>'
                 '<body><center>'
                 '<h3>Landing page for SPI authn.py</h3>'
                 '<p><a href="/login">/login</a><br/>'
                 '<p><a href="/checksession">/checksession</a><br/>'
                 '<p><a href="/logout">/logout</a><br/>'
                 '</p>'
              '</body></html>')
    return indexHTML
  index.exposed = True

  def logout(self): 
    user = cherrypy.session.get('user')
    cherrypy.lib.sessions.expire()
    ret = ('<html><title>Logout Page</title>'
           '<body><center>'
           '<h3>%s logged out</h3>'
           '<p><a href="/login">/login</a><br/>'
           '<p><a href="/checksession">/checksession</a><br/>'
           '</p>'
           '</body></html>') % str(user)
    return ret
  logout.exposed = True

  def checksession(self): 
    user = cherrypy.session.get('user')
    if user == None:
     return ('<html><body><center>'
             '<li>Not logged in</li>'
             '<p><a href="/login">/login</a><br/>'
             '<p><a href="/checksession">/checksession</a><br/>'
             '</p></center></body></html>')
    else:
     return ('<html><body><center>'
             '<li>Logged in as: %s</li>'
             '<p><a href="/checksession">/checksession</a><br/>'
             '<p><a href="/logout">/logout</a><br/>'
             '</p></center></body></html>') %str(user)
  checksession.exposed = True

  def default(self, attr='abc'):
    cherrypy.response.status = 404
    return "Page not Found"
  default.exposed = True


  def authenticate(self, username=None, password=None, domain=None):
    self.log('-----------  Authenticate -----------') 
    if (username == None or password == None or username == '' or password == '' or domain=='' or domain==None):
      cherrypy.response.status = 302
      cherrypy.response.headers['location'] = '/login?error=specify username+password+domain'
      return     

    login_result = True

    if (login_result==None):
      cherrypy.response.status = 302
      cherrypy.response.headers['location'] = '/login?error=unable to login to username@domain with provided password'
      return
    cherrypy.session['user'] = username
    cherrypy.session['domain'] = domain
    self.log('-----------  Authentication Successful [' + username + '] -----------')

    return self.__postResponse(domain)

  authenticate.exposed = True
  
  def __postResponse(self,domain=None):
    RelayState = cherrypy.session.get('RelayState')
    SAMLRequest = cherrypy.session.get('SAMLRequest')
    
    self.log('SAMLRequest  =----> ' + str(SAMLRequest))

    if (RelayState is None or SAMLRequest is None and domain is not None):
      return """<html><body>
              <center>
              <font color=green>login successful</font></br>
                 proceed to <a href='http://mail.google.com/a/%s'>http://mail.google.com/a/%s</a>
                 </center></body></html>""" %(domain,domain)

    decoded_saml = self.decode_base64_and_inflate(SAMLRequest)
    xmldoc = xml.dom.minidom.parseString(decoded_saml)
    # Try to get the issuer and request id of the saml request
    saml_oissuer = None
    req_id = None
    samlpnode = xmldoc.getElementsByTagName('samlp:AuthnRequest')
    for node in samlpnode:
      if node.nodeName == 'samlp:AuthnRequest':
        if samlpnode[0].hasAttribute('ID'):
          req_id = samlpnode[0].attributes['ID'].value
        samliss = node.getElementsByTagName('saml:Issuer')
        for n_issuer in samliss:
          cnode = n_issuer.childNodes[0]
          if cnode.nodeType == node.TEXT_NODE:
            saml_oissuer = cnode.nodeValue

    if not req_id:
      self.log('Error: could not parse request SAML request ID')
      return 'Error: could not parse request SAML request ID'

    if self.debug_flag:
      self.log('Attempting to parse SAML AssertionConsumerServiceURL')
    acs_url = None
    for node in samlpnode:
      if node.nodeName == 'samlp:AuthnRequest':
        if samlpnode[0].hasAttribute('AssertionConsumerServiceURL'):
          acs_url = samlpnode[0].attributes \
                        ['AssertionConsumerServiceURL'].value
        else:
          self.log('NO AssertionConsumerServiceURL sent in saml request')
          return ('<html><title>Error</title><body>'
                  'No AssertionConsumerServiceURL provided in'
                  ' SAMLRequest</body></html>')
        if self.debug_flag:
          self.log('login Parsed AssertionConsumerServiceURL: %s' %(acs_url))
        samliss = node.getElementsByTagName('saml:Issuer')
        for n_issuer in samliss:
          cnode = n_issuer.childNodes[0]
          if cnode.nodeType == node.TEXT_NODE:
            saml_oissuer = cnode.nodeValue

    domain = cherrypy.session.get('domain')
    domain_as_acs = 'https://www.google.com/a/' + domain.lower() + '/acs'
    if (acs_url.lower() != domain_as_acs):
      self.log('Login Domain mismatched with AssertionConsumerServiceURL')
      return 'Login domain and ACS domain mismatched ' + 'loginDomain : ' + domain + '  acs:' + acs_url

    if acs_url:
      location = acs_url
    if self.debug_flag:
      self.log('Redirecting to: %s' %(location))
      self.log('-----------  LOGIN END  -----------')

    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    
    five_sec_from_now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()+30))
    samlresp = self._generate_response(now, five_sec_from_now, cherrypy.session['user'],
                                       req_id, location,
                                       saml_oissuer)

    self.log(xml.dom.minidom.parseString(samlresp).toprettyxml())
   
    if (self.debug_flag):
      onload_action = '<body>'
    else:
      onload_action = '<body onload="document.forms[0].submit()">'
    
    resp = ('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"'
            'http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'
            '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">'
         '<head>'
         '<script>'
         '</script>'
         '</head>'
         '<body>'
            '%s'
         '<p>Login Successful</p>'
            '<p>'
            '<strong>Note:</strong> Users do not see the encoded SAML response.  This page is'
            ' normally posted immediately <em>body onload=document.forms[0].submit()</em>'
            '</p>'
            '<form action="%s" method="post">'
            '<div>'
            '<li>RelayState: <input type="text" name="RelayState" value="%s"/></li>'
            '<li>SAMLResponse: <input type="text" name="SAMLResponse" value="%s"/></li>'
            '</div>'
            '<div>'
         '<p><em>click continue within  30 seconds of ' +  now + ' to complete the SSO login</em><br/></p>'
            '<input type="submit" value="Continue"/>'
            '</div>'
            '</form>'
         '<br/>'
            '<p>Decoded SAMLResponse</p>'
         '<textarea rows="75" cols="120" style="font-size:10px">%s</div>'
            '</body></html>') % (onload_action,location, RelayState, base64.encodestring(samlresp),cgi.escape(xml.dom.minidom.parseString(samlresp).toprettyxml()))
    return resp  


  # Generates SAML 2.0 IDs randomly.
  def getrandom_samlID(self):
    return random.choice('abcdefghijklmnopqrstuvwxyz') + hex(random.getrandbits(160))[2:-1]

  def login(self,error = None, RelayState=None, SAMLRequest = None):
    self.log('-----------  LOGIN -----------')   
    if error == None:
     error = ""

    if not( RelayState is None):
      cherrypy.session['RelayState'] = RelayState
      self.log(' RelayState' + str(RelayState))
    if not (SAMLRequest is None):
      cherrypy.session['SAMLRequest'] = SAMLRequest
      self.log(' SAMLRequest' + str(SAMLRequest))

    user = cherrypy.session.get('user')
    if (user != None and RelayState != None and SAMLRequest != None):
     return self.__postResponse()


    return """<html><body>
            <center>
            <font color=red>%s</font></br>
               <form method="post" action="/authenticate">
            <table>
               <tr><td>Username:</td> <td><input type="text" name="username" value="" /></td></tr>
               <tr><td>Password:</td> <td><input type="password" name="password" /></td></tr>
               <tr><td>Domain:</td> <td><input type="domain" name="domain" /></td></tr>
            </table>
            <input type="submit" value="Log in" />
            </form>
            <p><a href='/checksession'>/checksession</a><br/>
               </center></body></html>""" %error
  login.exposed = True


  def _generate_response(self, now, later, username, login_req_id, recipient, audience):
    resp_rand_id = self.getrandom_samlID()
    rand_id_assert = self.getrandom_samlID()
    sigtmpl = ''
    key_info = ''

    # if the response is to be signed, create a signature template
    sigtmpl = ('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
               '<ds:SignedInfo>'
               '<ds:CanonicalizationMethod '
               'Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />'
               '<ds:SignatureMethod '
               'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />'
               '<ds:Reference URI="#%s">'
               '<ds:Transforms>'
               '<ds:Transform Algorithm='
               '"http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
               '</ds:Transforms>'
               '<ds:DigestMethod Algorithm='
               '"http://www.w3.org/2000/09/xmldsig#sha1" />'
               '<ds:DigestValue></ds:DigestValue>'
               '</ds:Reference>'
               '</ds:SignedInfo>'
               '<ds:SignatureValue/>'
               '<ds:KeyInfo>'
            '<ds:X509Data>'
            '<ds:X509Certificate></ds:X509Certificate>'
            '</ds:X509Data>'
               '</ds:KeyInfo>'
               '</ds:Signature>') % (resp_rand_id)
    resp = ('<samlp:Response '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">'
            '<saml:Issuer>%s</saml:Issuer>'
            '%s'
            '<samlp:Status>'
            '<samlp:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</samlp:Status>'
            '<saml:Assertion '
            'Version="2.0" ID="%s" IssueInstant="%s">'
            '<saml:Issuer>%s</saml:Issuer>'
            '<saml:Subject>'
            '<saml:NameID>%s</saml:NameID>'
            '<saml:SubjectConfirmation '
            'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData '
            'InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/>'
            '</saml:SubjectConfirmation>'
            '</saml:Subject>'
            '<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">'
            '<saml:AudienceRestriction>'
            '<saml:Audience>%s</saml:Audience>'
            '</saml:AudienceRestriction>'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="%s" SessionIndex="%s">'
            '<saml:AuthnContext>'
            '<saml:AuthnContextClassRef>'
            'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            '</saml:AuthnContextClassRef>'
            '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '</saml:Assertion>'
            '</samlp:Response>') % (resp_rand_id, now, recipient,
                                    self.saml_issuer, sigtmpl,rand_id_assert, now,
                                    self.saml_issuer, username,
                                    login_req_id, recipient, later,
                                    now, later, audience,
                                    now, rand_id_assert)

    resp = '<!DOCTYPE samlp:Response [<!ATTLIST samlp:Response ID ID #IMPLIED>]>' + resp
    resp = self._signXML(resp)
    return resp
 

  def _signXML(self, xml):
    import libxml2
    import xmlsec
    dsigctx = None
    doc = None
    try:
      # initialization
      libxml2.initParser()
      libxml2.substituteEntitiesDefault(1)
      if xmlsec.init() < 0:
        raise SignatureError('xmlsec init failed')
      if xmlsec.checkVersion() != 1:
        raise SignatureError('incompatible xmlsec library version %s' %
                             str(xmlsec.checkVersion()))
      if xmlsec.cryptoAppInit(None) < 0:
        raise SignatureError('crypto initialization failed')
      if xmlsec.cryptoInit() < 0:
        raise SignatureError('xmlsec-crypto initialization failed')

      # load the input
      doc = libxml2.parseDoc(xml)
      if not doc or not doc.getRootElement():
        raise SignatureError('error parsing input xml')
      node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature,
                             xmlsec.DSigNs)
      if not node:
        raise SignatureError("couldn't find root node")

      dsigctx = xmlsec.DSigCtx()
         
      key = xmlsec.cryptoAppKeyLoad(self.key_file, xmlsec.KeyDataFormatPem,
                                    self.key_pwd, None, None)

      if not key:
        raise SignatureError('failed to load the private key %s' % self.key_file)
      dsigctx.signKey = key

      if key.setName(self.key_file) < 0:
        raise SignatureError('failed to set key name')

      if xmlsec.cryptoAppKeyCertLoad(key, self.cert_file, xmlsec.KeyDataFormatPem) < 0:
        print "Error: failed to load pem certificate \"%s\"" % self.cert_file
        return self.cleanup(doc, dsigctx)

      # sign
      if dsigctx.sign(node) < 0:
        raise SignatureError('signing failed')
      signed_xml = doc.serialize()

    finally:
      if dsigctx:
        dsigctx.destroy()
      if doc:
        doc.freeDoc()
      xmlsec.cryptoShutdown()
      xmlsec.shutdown()
      libxml2.cleanupParser()

    return signed_xml


  def cleanup(self,doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res

  def log(self,msg):
    print ('[%s] %s') % (datetime.datetime.now(), msg)

# Utility routintes to base64 encode/decode and inflate/deflate
# pg 16-17:
# http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
# from: http://stackoverflow.com/questions/1089662/
#                                    python-inflate-and-deflate-implementations

  def decode_base64_and_inflate(self,b64string):
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15)

  def deflate_and_base64_encode(self,string_val):
    zlibbed_str = zlib.compress(string_val)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


# -------
# Main
# -------------

def main():
  # Default listen port
  cherrypy.server.socket_port = 28080
  cherrypy.server.socket_host =  '0.0.0.0'
  debug_flag = False
  saml_issuer = "authn.py"
  key_file = None
  key_pwd = None
  crt_file = None
  protocol = 'http'

  def usage():
    print ('\nUsage: authn.py --debug  '
           '--port=<port>  '
           '--saml_issuer=<issuer>  '
        '--cert_file=<certificate_file>'
           '--use_ssl'
           '--key_file=<key_file> (--key_blank_pwd|--key_pwd=)\n')

  try:
    opts, args = getopt.getopt(sys.argv[1:], None,
                               ["debug", "use_ssl", "port=",
                                 "saml_issuer=", "cert_file=",
                                 "key_file=", "key_blank_pwd", "key_pwd="])
  except getopt.GetoptError:
    usage()
    sys.exit(1)

  cherrypy.config.update({'global':{'log.screen': False}})
  cherrypy.config.update({"global": {"tools.sessions.on": "True","tools.sessions.timeout": 30}})

  for opt, arg in opts:
    if opt == "--debug":
      debug_flag = True
      cherrypy.config.update({'global':{'log.screen': True}})
    if opt == "--saml_issuer":
      saml_issuer = arg
    if opt == "--port":
      port = int(arg)
      cherrypy.config.update({"global": {"server.socket_port": port}})
    if opt == "--key_file":
      key_file = arg
    if opt == "--cert_file":
      cert_file = arg
    if opt == "--key_pwd":
      key_pwd = arg
    if opt == "--key_blank_pwd":
      key_pwd = ''
    if opt == "--use_ssl":
      protocol = "https"
      cherrypy.config.update({"global": {
          "server.ssl_certificate": "ssl.crt",
          "server.ssl_private_key": "ssl.key",
          'checker.on': False,
          'tools.log_headers.on': False,
          'request.show_tracebacks': False,
          'request.show_mismatched_params': False,
          'log.screen': False}})

  try:
    import libxml2
    import xmlsec
  except ImportError:
    print('libxml2 and/or xmlsec missing.  Unable to continue')
    sys.exit(1)
  if not key_file:
    print('No private key specified to use for POST binding.')
    usage()
    sys.exit(1)
  elif key_pwd is None:
    key_pwd = getpass.getpass('Password for %s: ' % key_file)

  if (protocol == 'https'):
    cherrypy.config.update({"global": {
          "server.ssl_certificate": cert_file,
          "server.ssl_private_key": key_file}})
  cherrypy.quickstart(AuthN(cherrypy.server.socket_port, protocol, debug_flag,
                            saml_issuer, cert_file, key_file, key_pwd))

if __name__ == '__main__':
  main()

