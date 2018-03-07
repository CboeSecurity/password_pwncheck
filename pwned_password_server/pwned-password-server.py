#!/usr/bin/python

# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:4443

from math import ceil,floor
from os import listdir
from os.path import isfile, join, getsize
from hashlib import sha1,pbkdf2_hmac
import hashlib
from binascii import hexlify
from re import sub

from urllib import unquote

import re
import sqlite3


from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import ssl
from urlparse import urlparse, parse_qs
from json import dumps

SSLCertFile='./localhost.cer'
SSLKeyFile='./localhost.key'
SSLKeyFilePassword='<password>'

ListenPort = 443
ListenInterface = '0.0.0.0'
BreachedPasswordPath = './db'
TokenDatabasePath = 'tokens.sqlite'
debug = False

fp = open(u'/var/log/pwnedpass-access.log','a')  
HashAlgorithmStrings = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

## SQLITE Schema
##

###########################################################
##  searchfile => binary search against an ordered file  ##
###########################################################
class SearchFile:
    def __init__(self,filepath):
        self.filepath = filepath
        self.fp = open(self.filepath,'r')

        first = self.fp.readline()
        self.linesize = len(first)
        self.nows_linesize = len(first.strip())
        self.filesize = getsize(self.filepath)
        self.filerows = self.filesize/self.linesize


    def find(self,string):
        if debug:
            print "   * searchfile: find: filepath=%s"%(self.filepath)
        string = string.strip()
        if len(string) != self.nows_linesize:
            return None
        startrow = self.filerows/2
        startjump = self.filerows/4
        ret = self._find(string,startrow,startjump)
        if ret == None:
            return ret
        return int(self._find(string,startrow,startjump))+1

    def _find(self,needle,currow,jumpsize,prevjumpsize=0):
        newjumpsize = ceil(float(jumpsize)/2)
        if jumpsize == 0 or newjumpsize == prevjumpsize:
            if debug:
                print "     + %d: No Match"%(currow)
            return None
        self.fp.seek(currow*self.linesize)
        curstring = self.fp.readline().strip()
        if curstring > needle:
            return self._find(needle,currow-jumpsize,newjumpsize,jumpsize)
        elif curstring < needle:
            return self._find(needle,min(self.filerows-1,currow+jumpsize),newjumpsize,jumpsize)
        else:
            if debug:
                print "    \- - %d: %s == %s (%d)"%(currow,curstring,needle,jumpsize)
            return currow

###########################################################
##  searchfiles => search against a directory of files   ##
###########################################################
class SearchFiles:
    def __init__(self,filepaths):
        self.search_files = {}
        if type(filepaths) == type(""):
            filepaths = [join(filepaths, f) for f in listdir(filepaths) if isfile(join(filepaths, f))]
        if type(filepaths) == type([]):
            for filepath in filepaths:
                self.search_files[filepath] = SearchFile(filepath)

    def find(self,needle):
        for filepath,pwnedfile in self.search_files.iteritems():
            # short circuit to prevent scanning a file with a known different sized hash string
            if len(needle) != pwnedfile.nows_linesize:
                return None
            ret = pwnedfile.find(needle)
            if ret != None:
                return (filepath, ret)
        return None


class TokenCheck:
    def __init__(self,dbpath):
        self.conn = sqlite3.connect(dbpath)
        self.checkstr = 'SELECT count(*) FROM tokens WHERE token=?'
        self.insertstr = "INSERT INTO tokens (user,token,ip) VALUES ( ?, ?, ? )"
        self.createstr = 'CREATE TABLE tokens ( user TEXT, token TEXT, ip TEXT, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);'
        self.indexstr = 'CREATE INDEX idx ON tokens(token);'

    def addToken(self,user,token,ip=None):
        c = self.conn.cursor()
        c.execute(self.insertstr,(user,token,ip,))
        self.conn.commit()

    def checkToken(self,user,token):
        c = self.conn.cursor()
        try:
            c.execute(self.checkstr,(token,))
        except sqlite3.OperationalError, e:
            if "no such table" in e.message:
                c.execute(self.createstr)
                c.execute(self.indexstr)
                self.conn.commit()
                if debug == True:
                    print "Committed new table into database"
                return self.checkToken(user,token)
        res =  c.fetchone()[0]
        if res == 1:
            return True
        else:
            return False

    ####################################################################
    ##  TokenizePassword => De-humanize a password to entropic values ##
    ####################################################################
    def tokenizePassword(self,password):
        # first -> all special characters (1+) => "!"
        first = sub('[\\\|\+=!@#$%^&*()\-_{\[\]}`~\'"]+','!',password)
        # second -> all numbers (1+) => "#"
        second = sub('[0-9]+','#',first)
        # uppercase the whole string
        third = second.upper()
        # shorten repeated characters
        fourth = sub(r'(.)\1+',r'\1',third)
        return fourth

    def hashToken(self,token):
        return hexlify(pbkdf2_hmac('sha256',token, sha1('CBoePassword').digest(), 100000))


class PasswordRequestHandler(SimpleHTTPRequestHandler):

    pwned = None
    tokendb = None

    def do_GET(self):
        if debug:
            print "Received Request"
        
        #fp.write((u"HEXREQUEST:%s:HEXREQUEST\n"%self.path.encode('hex')))   
        #fp.flush()
        #fp.write((u"REQUEST:%s:REQUEST\n"%self.path.encode('utf8')))
        parsed_path = urlparse(unicode(self.path))
        args = parse_qs(parsed_path.query)
        #if 'debug' in args:
        #    debug = True
        self.user = "-"
        self.retval = "-"
        self.code = -1
        
        if parsed_path.path == "/checkpwd":
            message = ''
            if u'debug' in args:
                message_parts = [
                    u'CLIENT VALUES:',
                    u'client_address=%s (%s)' % (self.client_address,
                                                self.address_string()),
                    u'command=%s' % self.command,
                    u'path=%s' % self.path,
                    u'real path=%s' % parsed_path.path,
                    u'query=%s' % parsed_path.query,
                    u'arguments (json)=%s' % dumps(args),
                    u'request_version=%s' % self.request_version,
                    u'',
                    u'SERVER VALUES:',
                    u'server_version=%s' % self.server_version,
                    u'sys_version=%s' % self.sys_version,
                    u'protocol_version=%s' % self.protocol_version,
                    u'',
                    u'HEADERS RECEIVED:',
                    ]
                for name, value in sorted(self.headers.items()):
                    message_parts.append('%s=%s' % (name, value.rstrip()))
                message_parts.append('')
                message += u'\r\n'.join(message_parts)
           
            if 'u' in args and 'p' in args:
                user = unquote(args['u'][0]) #.decode('utf8'); 
                self.user = user
                password = unquote(args['p'][0]) #    .decode('utf8')
                (isGood,code,reason) = self.verifyPasswordGood(user.encode('utf8'),password.encode('utf8'))
                message += u','.join(map(unicode,[isGood,code,reason]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message)
        else:
            self.send_response(301)
            self.send_header('Location', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ')
            self.end_headers()
        return

    def verifyPasswordGood(self,user,password):
        isPwned = False
        isUsed = False
        tooShort = False
        reason = []
        retval = False
   
        ### first test against haveibeenpwned and similar...
        for algstr in HashAlgorithmStrings:
            hashAlg = hashlib.new(algstr)
            hashAlg.update(password)
            testhash = hashAlg.hexdigest().upper()
        
            ret = self.pwned.find(testhash)
            if ret == None:
                if debug:
                    print " * %s: %s: * No Match"%(algstr, testhash)
            else:
                isPwned = True
                if debug:
                    print " *** %s: %s: - Breached! %s ***"%(algstr, testhash,ret)
                reason.append( "Password can be found in the breached password database" )
    
        ### now test for bad token usage
        token = self.tokendb.tokenizePassword(password)
        tokenhash = self.tokendb.hashToken(token) 
        if debug:
            print " \- * Password: %s"%(password)
            print " \- * Token: %s"%(token)

        if len(token) < 15:
            if debug:
                print " \- - Password is too short (%d, must be 15 character minimum)"%(len(token))
            tooShort = True
            reason.append( "Password is too short (%d, must be 15 character minimum)"%(len(token)) )

        if self.tokendb.checkToken(user,tokenhash):
            if debug:
                print " \- - Password is in token library"
            isUsed = True
            reason.append( "Password is too similar to a previously used password" )
        else:
            if debug:
                print " \- * Password is not in token library"
    
        if not isUsed and not isPwned and not tooShort:
            if debug:
                self.tokendb.addToken(user,tokenhash,self.client_address[0])
                print " \- + Password is a valid entry and is now reserved"
            reason.append( "Password is valid and now reserved" )
            retval = True
        else:
            if debug:
                print " \- - Password is invalid and unacceptable"
            retval = False
        
        self.code = int(isPwned)*100+int(isUsed)*10+int(tooShort)*1
        self.retval = retval
        return (retval,self.code,'\n'.join(reason))

    def log_message(self, format, *args):
        if not debug:
            args = (re.sub(r'p=.* HTTP',r'p=<redacted> HTTP',args[0]),args[1],args[2])
        print "%s\t%s\t%s\t%s\t%d\t%s" % (self.log_date_time_string(), self.client_address[0],self.user,self.retval,self.code,format%args)
        fp.write("%s,%s,%s,%s,%d,%s\n" % (self.log_date_time_string(), self.client_address[0],self.user,self.retval,self.code,format%args))
        fp.flush()

if __name__ == '__main__':
    # build up our SSL wrapper with our keying material
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.load_cert_chain(certfile=SSLCertFile, keyfile=SSLKeyFile, password=SSLKeyFilePassword)
    
    # Setup our database accesses
    PasswordRequestHandler.pwned = SearchFiles(BreachedPasswordPath)
    PasswordRequestHandler.tokendb = TokenCheck(TokenDatabasePath)
    
    # create the web server, glue in SSL
    httpd = HTTPServer((ListenInterface, ListenPort), PasswordRequestHandler) 
    httpd.socket = context.wrap_socket (httpd.socket, server_side=True)
    
    # Fire off the web server to start accepting requests
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print "Exiting Gracefully..."
        exit(0)
