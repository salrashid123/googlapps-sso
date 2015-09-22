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

Sample SAML ServiceProvider (SP) capable of processing *basic* POST profiles

It can work with the apps.py from
https://github.com/salrashid123/googlapps-sso
with some minor modifications:
 app.py is hardcoded to work with google's redirect
 https://github.com/salrashid123/googlapps-sso/blob/master/apps.py#L248 
   (i.,e AssertionConsumerServiceURL is hardcoded 'https://www.google.com/a/yourdomain.com/acs')
 to use saml_sp.py with apps.py:
 
 
   idp:  your identity provider's login URL
   acs_url: AssertionConsumerServiceURL to redirect back to the SP
 
  1. comment out lines 246,247,268 in apps.py and run apps.py from the commandline only (not as the docker image)
     that is, comment the following lines in apps.py
     #domain_as_acs = 'https://www.google.com/a/' + domain.lower() + '/acs'
     #if (acs_url.lower() != domain_as_acs):
       #self.log('Login Domain mismatched with AssertionConsumerServiceURL')
       #return 'Login domain and ACS domain mismatched ' + 'loginDomain : ' + domain + '  acs:' + acs_url

  2. edit /etc/hosts and add
    127.0.0.1  sso.yourdomain.com sp.mydomain.com
  3. run
        ./saml_sp.py --debug --use_ssl 
          --idp=https://sso.yourdomain.com:28080/login 
          --provider_name=authn.py 
          --acs_url=https://sp.mydomain.com:38080/secure 
          --cert_file=ssl.crt 
          --key_file=ssl.key  
          --key_blank_pwd
  4. Open up a new browser and go to:
       https://sp.mydomain.com:38080/secure
         this will check if a user is logged in or not
         if not saml_sp.py will redirect to the IdP (apps.py) at  https://sso.yourdomain.com:28080/login
  5. Login to your Idp with *any* username, password and domain
  6. IdP will redirect you to https://sp.mydomain.com:38080/secure
  7. sp.mydomain.com:38080/secure will read the SAML POST response
       a. decode the response and verify its digital signature (i.,e both apps.py and saml_sp.py should use the same certs
       b. extract the SAML Request ID and compare it to what was sent to the IdP in step 4 redirect
       c. compare the timestamp of the SAMLAssertion sent by the IdP (if its too old, the SP will reject it)
       d. extract the userID from the saml response
       e. confirm the user is logged into the SP
   
The SP does have a /logout URI but that only logs out of the SP and does nothing to logout of the IdP (apps.py).
TODO: modify apps.py, saml_sp.py to redirect and do uniform logout
   
./saml_sp.py 
   --debug 
   --use_ssl 
   --idp=https://sso.yourdomain.com:28080/login 
   --provider_name=authn.py 
   --acs_url=https://sp.mydomain.com:38080/secure 
   --cert_file=ssl.crt 
   --key_file=ssl.key  
   --key_blank_pwd

"""

class SignatureError(Exception):
  pass

class SP(object):

  def __init__(self, port, debug_flag, protocol, 
               idp,provider_name, acs_url, saml_issuer, 
               cert_file, key_file, key_pwd):
    self.debug_flag = debug_flag
    self.key_file = key_file
    self.key_pwd = key_pwd
    self.cert_file = cert_file
    self.protocol = protocol
    self.idp = idp 
    self.provider_name = provider_name
    self.acs_url = acs_url

    # neverending list of samlID's and date/time they were issued    
    self.samlIDs = {}
    
    self.log ('--------------------------------')
    self.log ('-----> Starting saml_sp.py <------')
    self.log ('--------------------------------')
    self.saml_issuer = saml_issuer

  #Main landing page
  def index(self):
    indexHTML = ('<html><title>Service Provider Landing Page</title>'
                 '<body><center>'
                 '<h3>Landing page for SPI sp.py</h3>'
                 '<p><a href="/secure">/secure</a><br/>'
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
           '<p><a href="/secure">/secure</a><br/>'
           '</p>'
           '</body></html>') % str(user)
    return ret
  logout.exposed = True

  def secure(self, SAMLResponse = None, RelayState = None): 
    
    # first check if the user session exists already
    # then check if the SAMLResponse was sent in thei srequest
    # if not, construct a SAMLRequest and 302 redirect to the IdP
    # if the SAMLRequest was sent in, verify its digital signature
    # then extract out the InResponseTo field (to make sure its something we sent into the IdP earlier)
    # extract out the NotOnOrAfter to make sure the assertion is still valid 
    # extract out the userID and consider it as a vali duser
    user = cherrypy.session.get('user')
      
    if (SAMLResponse != None):
      if (self._verifyXML(base64.b64decode(SAMLResponse))):        
        xmldoc = xml.dom.minidom.parseString(base64.b64decode(SAMLResponse))
        sissuer = xmldoc.getElementsByTagName('saml:Issuer')
        for node in sissuer:
          print node.firstChild.nodeValue
    
        sassert = xmldoc.getElementsByTagName('saml:Assertion')
        for node in sassert:
            if node.attributes.has_key('ID'):
              self.log("SAMLResponse  saml:Assertion/ID " +  node.attributes['ID'].value)                           
            subj = node.getElementsByTagName('saml:Subject')
            for s in subj:
              subj_conf = s.getElementsByTagName('saml:SubjectConfirmationData')
              for node in subj_conf:
                  if node.attributes.has_key('InResponseTo'):
                    response_to_id = node.attributes['InResponseTo'].value
                    self.log("SAMLResponse  saml:Assertion/saml:SubjectConfirmationData[InResponseTo]' " +  response_to_id)
                    try:
                      self.log("FOUND InResponseTo ID " + str(self.samlIDs[response_to_id]))
                    except KeyError:
                      self.log("---------------->>  Unable to find valid InResponseTo ID  <<-----------------")
                      return ('<html><body><center><li>Unable to match SAML InResponseTo ID field ' + response_to_id + '</li></center></body></html>')   
                      
                  if node.attributes.has_key('NotOnOrAfter'):
                    NotOnOrAfter = node.attributes['NotOnOrAfter'].value
                    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())      
                    self.log("SAMLResponse  saml:Assertion/saml:SubjectConfirmationData[NotOnOrAfter]' " +  NotOnOrAfter)
                    self.log("FOUND NotOnOrAfter ID " + NotOnOrAfter + '   now : '  + now)
                    if (datetime.datetime.strptime(NotOnOrAfter, '%Y-%m-%dT%H:%M:%SZ') <= datetime.datetime.utcnow()):
                      self.log('********* SAMLResponse expired ' + NotOnOrAfter  + ' > ' + time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())   )
                      return ('<html><body><center><li>SAMLAssertion already Expired ' + NotOnOrAfter + '</li></center></body></html>')   
              u = s.getElementsByTagName('saml:NameID')
              for node3 in u:
                user = node3.firstChild.nodeValue
                cherrypy.session['user'] = user                
                self.log("*********** LOGGED IN AS: " + user)
                                     
        return ('<html><body><center>'
                '<li>Logged in as: %s</li>'
                '<p><a href="/logout">/logout</a><br/>'
                '</p></center></body></html>') %str(user)                  
      else:
        self.log("---------------->>  Invalid SAMLResponse  <<---------------------")
        self.log(xml.dom.minidom.parseString(base64.b64decode(SAMLResponse)).toprettyxml())
        return('invalid SAMLResponse received')
    if user == None:
      self.log("Redirecting to IdP " + self.idp)
      req_rand_id = self.getrandom_samlID()
      now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())      
      self.samlIDs[req_rand_id] = time.gmtime()
      
      saml_resp = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
                     ' ID="%s" Version="2.0" IssueInstant="%s" '
                     ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
                     ' ProviderName="%s" IsPassive="false" AssertionConsumerServiceURL="%s">'
                   '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>'
                   '<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />'
                   '</samlp:AuthnRequest>') % (req_rand_id, now, self.provider_name,self.acs_url,self.saml_issuer)               
      
      self.log(saml_resp)         
      cherrypy.response.status = 302
      cherrypy.response.headers['location'] = (self.idp + 
                                               '?SAMLRequest=' + urllib.quote_plus(self.deflate_and_base64_encode(saml_resp))
                                               + '&RelayState=' + self.acs_url )
  secure.exposed = True

  def default(self, attr='abc'):
    cherrypy.response.status = 404
    return "Page not Found"
  default.exposed = True

  def getrandom_samlID(self):
    return random.choice('abcdefghijklmnopqrstuvwxyz') + hex(random.getrandbits(160))[2:-1]

  def _verifyXML(self, xml):
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

      # verify
      if dsigctx.verify(node) < 0:
        raise SignatureError('verification failed')
      if dsigctx.status == xmlsec.DSigStatusSucceeded:
          self.log("Signature is OK")
          is_valid = True
      else:
          self.log("*****************  Signature is INVALID ********************")
          is_valid = False

    finally:
      if dsigctx:
        dsigctx.destroy()
      if doc:
        doc.freeDoc()
      xmlsec.cryptoShutdown()
      xmlsec.shutdown()
      libxml2.cleanupParser()

    return is_valid


  def cleanup(self,doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res
  
  def log(self,msg):
    print ('[%s] %s') % (datetime.datetime.now(), msg)

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
  cherrypy.server.socket_port = 38080
  cherrypy.server.socket_host =  '0.0.0.0'
  debug_flag = False
  saml_issuer = "authn.py"
  key_file = None
  key_pwd = None
  crt_file = None
  protocol = 'http'
  idp = "https://sso.yourdomain.com:28080/login"
  acs_url = 'https://www.google.com/a/mydomain.com/acs'
  provider_name = 'authn.py'

  def usage():
    print ('\nUsage: sp.py --debug  '
           '--port=<port>  '
           '--saml_issuer=<issuer>  '
           '--idp=<idp>'
           '--provider_name='
           '--acs_url='
           '--cert_file=<certificate_file>'
           '--use_ssl'
           '--key_file=<key_file> (--key_blank_pwd|--key_pwd=)\n')

  try:
    opts, args = getopt.getopt(sys.argv[1:], None,
                               ["debug", "use_ssl", "port=",
                                 "idp=", "provider_name=",
                                 "acs_url=", "saml_issuer=", "cert_file=",
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
    if opt == "--idp":
      idp = arg
    if opt == "--provider_name":
      provider_name = arg
    if opt == "--acs_url":
      acs_url = arg
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
          'request.show_mismatched_params': False}})

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
  cherrypy.quickstart(SP(cherrypy.server.socket_port, protocol, debug_flag,
                            idp,provider_name, acs_url,
                            saml_issuer, cert_file, key_file, key_pwd))

if __name__ == '__main__':
  main()

