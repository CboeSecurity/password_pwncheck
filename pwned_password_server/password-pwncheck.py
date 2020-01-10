#!/usr/bin/python3

from werkzeug.serving import WSGIRequestHandler
from flask import Flask,request,send_from_directory,redirect,abort
from flask.logging import default_handler
from datetime import datetime
from platform import system
import logging
import time
import ssl
import os
import pwnpass
import threading
import re

app = Flask(__name__)
cfg = None 
pwn = None
logStore = threading.local()
logLock = threading.RLock()

def logmsg(request,type,message,args):
    is_dst = time.daylight and time.localtime().tm_isdst > 0
    tz =  - (time.altzone if is_dst else time.timezone) / 36
    if tz>=0:
        tz="+%04d"%tz
    else:
        tz="%05d"%tz
    datestr = '%d/%b/%Y %H:%M:%S'
    user = getattr(logStore,'user','')
    isValid = getattr(logStore,'isValid','')
    code = getattr(logStore,'code','')
    args = getLogDateTime(args)
    log = '%s %s,%s,%s,%s,%s,%s' % (datetime.now().strftime(datestr),tz,request.address_string(),user,isValid,code, message % args)
    with logLock:
        with open(cfg.logpath,'a') as fw:
            fw.write(log+os.linesep)
    return log

def getLogDateTime(args):
    if not cfg.debug:
        try:
            if len(args) == 3:
                args = (re.sub(r'p=.* HTTP',r'p=<redacted> HTTP',args[0]),args[1],args[2])
            elif len(args) == 2:
                args = (re.sub(r'p=.* HTTP',r'p=<redacted> HTTP',args[0]),args[1])
        except TypeError as e:
            print("arg0: %s"%type(args[0]))
            print("arg1: %s"%type(args[1]))
            if len(args) == 3:
                print("arg2: %s"%type(args[2]))
            print(args)
            raise e
#       args = (re.sub(r'p=.* HTTP',r'p=<redacted> HTTP',args[0]),args[1],args[2])
    return args

#"/" "GET" -> form.html
@app.route('/', methods = ['GET'])
def v1form():
    return open('%s/form.html'%(cfg.staticdir)).read()

@app.route('/checkpwd', methods = ['GET','POST'])
def v1CheckPassword():
    username = ''
    password = ''
    if request.method == 'GET':
        username = request.args.get('u','')
        password = request.args.get('p','')
        reserve = True
    elif request.method == 'POST':
        username = request.form.get('u','')
        password = request.form.get('p','')
        reserve = False
    (isGood,code,reason) = pwn.verifyPasswordGood(username,
                                              password,
                                              reserve=reserve,
                                              always_true=cfg.yesman)
    logStore.code = code
    logStore.isValid = isGood
    logStore.user = username

    message = u','.join(map(str,[isGood,code,reason]))
    return message

@app.route("/test", methods = [ "GET" ] )
def v1Test():
    return ""

@app.route("/styles.css")
@app.route("/script.js")
@app.route("/image.svg")
def StaticRequests():
    reqfile = request.path[1:]
    sp = os.path.join(app.root_path,cfg.staticdir) 
    mimetype=None
    if reqfile == 'image.svg':
        mimetype = 'image/svg+xml'
    return send_from_directory(sp,reqfile,mimetype=mimetype)

@app.route("/favicon.ico")
def NoSuchFile():
    abort(404)

#ELSE 301 to 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
@app.route('/<path:path>')
def catch_all(path):
    return redirect('https://www.youtube.com/watch?v=dQw4w9WgXcQ' ,code=301)

###########################################################
##################### MAIN ################################
###########################################################
if __name__ == "__main__":
    werkzeug_logger = logging.getLogger('werkzeug')
    WSGIRequestHandler.log = lambda self, type, message, *args: getattr(werkzeug_logger, type)(logmsg(self,type,message,args))

    args = pwnpass.pwnargparse()
    args.add_argument('-c','--sslcert',help='SSL Public Certificate for the HTTPS Web Server')
    args.add_argument('-k','--sslkey',help='SSL Private Key for the HTTPS Web Server')
    args.add_argument('--sslkeypass',help='Passphrase to decrypt the SSL Private Key', default=None)
    if system() == 'Windows':
        args.add_argument('-l','--logpath',help='Path to the logfile',default=None)
    else:
        args.add_argument('-l','--logpath',help='Path to the logfile',default='/var/log/pwnedpass-access.log')
    args.add_argument('-p','--port',help='TCP Port to for web server to listen on', default=443, type=int)
    args.add_argument('-i','--interface',help='TCP Bind interface for web server to listen on', default='0.0.0.0')
    args.add_argument('-s','--staticdir',help='Path to the static files supporting the web UI', default='static')

    cfg = args.parse_args()
    pwn = pwnpass.PwnPass(cfg)
    pwn.debug = cfg.debug

    ssl_context = 'adhoc'
    if cfg.sslcert and cfg.sslkey:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ssl_context.load_cert_chain(certfile=cfg.sslcert, keyfile=cfg.sslkey, password=cfg.sslkeypass)

    app.run(host=cfg.interface, port=cfg.port, ssl_context=ssl_context,debug=cfg.debug)
