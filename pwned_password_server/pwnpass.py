from platform import system
import argparse

from math import ceil,floor
from os import listdir
from os.path import isfile, join, getsize
from hashlib import sha1,pbkdf2_hmac
import hashlib
from binascii import hexlify
from re import sub

import re

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import NoSuchTableError
from sqlalchemy import Column, Integer, Text, DateTime 
from sqlalchemy.sql import func
Base = declarative_base()

import logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

#fp = open(u'/var/log/pwnedpass-access.log','a')  
HashAlgorithmStrings = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
CustomHashAlgorithmStrings = ['ntlm']

def ntlm(password):
    hashval = hashlib.new('md4', password.encode('utf-16le')).digest()
    return hexlify(hashval)


class PasswordTest:

    def __init__(self,cfg):
        self.cfg = cfg
        self.debug = cfg.debug
        self.reason = {0:""}
    def test(self,user,password,token):
        return (0,None) # first is the test 'code', 2nd is context for custom report
    def report(self,code,context=None):
        return self.reason.get(code,"")

class BreachedTokenTest(PasswordTest):

    def __init__(self,cfg):
        super().__init__(cfg)
        self.reason[200] = "Password is similar to a known breached password"
        isdebug = cfg.debug
        isdebug = False
        self.pwnedtokens = SearchFiles(cfg.breachtokendir,debug=isdebug)

    def makeHash(self,token):
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def printDatabase(files,parser = lambda x: x.split('|')[2]):
        for curfile in files:
            with open(curfile) as fp:
                password = parser(line)
                token = tokenizePassword(password)
                linehash = self.makeHash(token)
                print(linehash)

    def test(self,user,password,token):
        ret = 0
        testhash = self.makeHash(token)
        out =  self.pwnedtokens.find(testhash)
        if out:
        #if self.pwned.find(testhash):
            ret = 200
                
        if self.debug:
            if ret:
                print(" \- - Similar Breached Password found as %s: %s"%(testhash,ret))
            else:
                print(" \- * Password not found in Similar breach hashes: * No Match")
        return (ret,None)

class BreachedHashTest(PasswordTest):

    def __init__(self,cfg):
        super().__init__(cfg)
        self.reason[100] = "Password can be found in the breached password database"
        isdebug = cfg.debug
        isdebug = False
        self.pwned = SearchFiles(cfg.breachdir,debug=isdebug)

    def test(self,user,password,token):
        ret = 0
        for algstr in HashAlgorithmStrings:
            hashAlg = hashlib.new(algstr)
            hashAlg.update(password.encode('utf-8'))
            testhash = hashAlg.hexdigest().upper()
            out =  self.pwned.find(testhash)
            #if self.pwned.find(testhash):
            if out:
                ret = 100
                break
        if ret == 0:
            for algstr in CustomHashAlgorithmStrings:
                hashAlg = eval(algstr)
                testhash = hashAlg(password)
                out = self.pwned.find(testhash)
                print(str(testhash,'utf-8'))
                if self.pwned.find(testhash):
                    ret = 100
                    break


                
        if self.debug:
            if ret:
                print((" \- - Breached Password found as %s: %s: %s"%(algstr, testhash,ret)))
            else:
                print(" \- * Password not found in Breached hash: * No Match")
                #print((" * Password not found in Breached hash: %s: %s: * No Match"%(algstr, testhash)))
        return (ret,None)


class BlacklistRegexTest(PasswordTest):

    def __init__(self,cfg):
        super().__init__(cfg)
        self.reason[20] = 'Password matches blacklist terms'
        self.regexs = []
        if cfg.blacklistpath != None:
            fp = open(cfg.blacklistpath,'r')
            for line in fp:
                line = line.strip()
                insensitive = False
                if line[0:2] == "i:":
                    insensitive = True
                    line = line[2:]
                self.regexs.append((insensitive,line))

    def test(self,user,password,token):
        for line in self.regexs:
            (ignore,regex) = line
            regex = regex.replace('<user>',user)
            results = None
            if ignore == True:
                results = re.search(regex,password,re.IGNORECASE)
            else:
                results = re.search(regex,password)
            if results != None:
                if self.debug:
                    print(" \- - A blacklisted term was found")
                return (20,None)
        if self.debug:
            print(" \- * No blacklisted terms were found")
        return (0,None)

class PreviouslyUsedTest(PasswordTest):

    def __init__(self,cfg,tokendb):
        super().__init__(cfg)
        self.tokendb = tokendb
        self.reason[10] = "Password is too similar to a previously used password"

    def test(self,user,password,token):
        ### now test for bad token usage
        tokenhash = self.tokendb.hashToken(token) 
        if self.tokendb.checkToken(user,tokenhash):
            if self.debug:
                print(" \- - Password is in token library")
            return (10,None)
        else:
            if self.debug:
                print(" \- * Password is not in token library")
        return (0,None)

class TokenLengthTest(PasswordTest):

    def __init__(self,cfg):
        super().__init__(cfg)
        self.minlength = cfg.mintokenlength
        self.reason = "Password is too short (%d, must be %d character minimum)"

    def test(self, user, password, token):
        if len(token) < self.minlength:
            if self.debug:
                print(" \- - Password is too short (%d, must be %d character minimum)"%(len(token),self.minlength))
            return (1,len(token))
        if self.debug:
            print(" \- * Password length is acceptable (%d), must be %d character minimum)"%(len(token),self.minlength))
        return (0,0)

    def report(self,code,ctx):
        if code:
            return self.reason%(ctx,self.minlength)
        return ""

class PasswordLengthTest(PasswordTest):

    def __init__(self,cfg):
        super().__init__(cfg)
        self.minlength = 15
        self.reason = "Password is too short (%d, must be %d character minimum)"

    def test(self, user, password, token):
        if len(password) < self.minlength:
            if self.debug:
                print(" \- - Password is too short (%d, must be %d character minimum)"%(len(password),self.minlength))
            return (1,len(password))
        if self.debug:
            print(" \- * Password length is acceptable (%d), must be %d character minimum)"%(len(password),self.minlength))
        return (0,0)

    def report(self,code,ctx):
        if code:
            return self.reason%(ctx,self.minlength)
        return ""

###########################################################
##  searchfile => binary search against an ordered file  ##
###########################################################
class SearchFile:
    def __init__(self,filepath,debug=False):
        self.filepath = filepath
        self.fp = open(self.filepath,'r')

        first = self.fp.readline()
        self.linesize = len(first)
        self.nows_linesize = len(first.strip())
        self.filesize = getsize(self.filepath)
        self.filerows = self.filesize/self.linesize
        self.debug = debug


    def find(self,string):
        if self.debug:
            print(("   * searchfile: find: filepath=%s"%(self.filepath)))
        string = string.strip()
        if len(string) != self.nows_linesize:
            return None
        startrow = floor(self.filerows/2)
        startjump = int(self.filerows/4)
        ret = self._find(string,startrow,startjump)
        if ret == None:
            return ret
        return int(ret)+1
        #return int(self._find(string,startrow,startjump))+1

    def _find(self,needle,currow,jumpsize,prevjumpsize=-1):
        #print("currow: %s     jumpsize: %s"%(currow,jumpsize))
        newjumpsize = ceil(float(jumpsize)/2)
        if jumpsize == 0 or newjumpsize == prevjumpsize:
            if self.debug:
                #print("jumpsize: %s     newjumpsize: %s     prevjumpsize: %s"%(jumpsize,newjumpsize,prevjumpsize))
                print(("     + %d: No Match"%(currow)))
            return None
        self.fp.seek(currow*self.linesize)
        curstring = self.fp.readline().strip()
        #print('if "%s" is "%s"'%(curstring,needle))
        if curstring > needle:
            return self._find(needle,currow-jumpsize,newjumpsize,jumpsize)
        elif curstring < needle:
            return self._find(needle,min(self.filerows-1,currow+jumpsize),newjumpsize,jumpsize)
        else:
            if self.debug:
                print(("    \- - %d: %s == %s (%d)"%(currow,curstring,needle,jumpsize)))
            return currow

###########################################################
##  searchfiles => search against a directory of files   ##
###########################################################
class SearchFiles:
    def __init__(self,filepaths,debug=False):
        self.debug = debug
        self.search_files = {}
        if type(filepaths) == type(""):
            filepaths = [join(filepaths, f) for f in listdir(filepaths) if isfile(join(filepaths, f))]
        if type(filepaths) == type([]):
            for filepath in filepaths:
                self.search_files[filepath] = SearchFile(filepath,debug)
        if self.debug:
            print(" * Will Search the following:\n    %s"%("\n    ").join(filepaths))

    def find(self,needle):
        for filepath,pwnedfile in self.search_files.items():
            # short circuit to prevent scanning a file with a known different sized hash string
            if self.debug:
                print(" * len(testhash) = %d len(filehashes) = %d "%(len(needle),pwnedfile.nows_linesize))
                print(" * testhash: %s"%(needle))
            if len(needle) != pwnedfile.nows_linesize:
                return None
            ret = pwnedfile.find(needle)
            if ret != None:
                return (filepath, ret)
        return None

class Token(Base):
    __tablename__ = 'tokens'
    id = Column(Integer, primary_key=True)
    user = Column(Text,unique=False,nullable=False)
    token = Column(Text,unique=False,nullable=False)
    ip = Column(Text,unique=False,nullable=True)
    date = Column(DateTime(timezone=True), server_default=func.now())
    platform = Column(Text,unique=False,nullable=True)
    tags = Column(Text,unique=False,nullable=True)

class TokenCheck:

    def __init__(self,cfg,debug=False):
        dburl =  vars(cfg).get('dburl',None)
        if dburl == None:
            dburl = 'sqlite:///%s'%(cfg.dbpath)
        engine = create_engine(dburl, convert_unicode=True)
        self.dbsession = scoped_session(sessionmaker(autocommit=False,
                                                 autoflush=False,
                                                 bind=engine))
        Base.metadata.reflect(bind=engine)
        Base.query = self.dbsession.query_property()    
        Base.metadata.create_all(engine)
        self.debug = debug

    def addToken(self,user,token,ip=None,platform=None,tags=None):
        token = str(token,'utf-8')
        newtok = Token(user=user,token=token,ip=ip,platform=platform,tags=tags)
        self.dbsession.add(newtok)
        self.dbsession.commit()

    def checkToken(self,user,token):
        #c = self.conn.cursor()
        try:
            token = str(token,'utf-8')
            #print("token equals %s"%(strtoken))
            sql = self.dbsession.query(Token).filter(Token.token==token) 
            res = sql.first()
            #print("res equals %s"%(res))
        except NoSuchTableError as  e:
            print("Table does not exist!: %s"%e)
        if res:
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
        return hexlify(pbkdf2_hmac( 'sha256',
                                    token.encode('utf-8'), 
                                    sha1(   'CBoePassword'.encode('utf-8')).digest(),
                                            100000))


class PwnPass():

    pwned = None
    tokendb = None
    loghandle = None
    debug = False
    always_true = False
    regexs = []

    def __init__(self,cfg):
        self.tokendb = TokenCheck(cfg)
        self.Tests = [  BreachedHashTest(cfg),
                        BreachedTokenTest(cfg),
                        BlacklistRegexTest(cfg),
                        PreviouslyUsedTest(cfg,self.tokendb),
                        TokenLengthTest(cfg)]

    def verifyPasswordGood(self,user,password,ip=None,reserve=True,always_true=False):
        score = 0
        reasons = []
        token = self.tokendb.tokenizePassword(password)
        tokenhash = self.tokendb.hashToken(token) 

        for Test in self.Tests:
            (code,ctx) = Test.test(user,password,token)
            reasons.append(Test.report(code,ctx))
            score += code
        
        reasons = list(filter(lambda x: len(x),reasons))
        if score == 0:
            if reserve == True:
                self.tokendb.addToken(user,tokenhash,ip)
                reasons.append( "Password is valid and now reserved" )
                if self.debug:
                    print(" \- + Password is a valid entry and is now reserved")
            else:
                reasons.append( "Password is tested as valid" )
                if self.debug:
                    print(" \- + Password is tested as valid entry")
            retval = True
        else:
            if self.debug:
                print(" \- - Password is invalid and unacceptable")
            retval = False

        if always_true == True and retval == False:
            print(" \- - OVERRIDING invalid with Valid (yesman enabled)!!!")
            reasons.append( "Invalid Password Approved due to Yesman mode" )
            retval = True
        return (retval,score,'\n'.join(reasons))

def pwnargparse():
    args = argparse.ArgumentParser()
    args.add_argument('-b','--breachdir',help='Breached passwords hash directory path',default='./db')
    args.add_argument('-t','--breachtokendir',help='Breached passwords hash directory path',default='./db')
    args.add_argument('-d','--dbpath',help='Path to the sqlite file store for used passwords',default='tokens.sqlite')
    args.add_argument('-B','--blacklistpath',help='Path to a blacklist file of bad regex strings in passwords.  Lines starting with "i:" are case insensitively matched.  "<user>" will be replaced with the username',default=None)
    args.add_argument('-m','--mintokenlength',help='Minimum length of the Password once it is tokenized.  This is the genericized version of a password',default=15,type=int)
    args.add_argument('-D','--debug',help='Enter Debug mode (***DO NOT USE IN PRODUCTION!***)',action='store_true', default=False)
    args.add_argument('-Y','--yesman',help='Always return Valid... useful for preprod staging (***DO NOT USE IN PRODUCTION!***)', action='store_true')
    return args
