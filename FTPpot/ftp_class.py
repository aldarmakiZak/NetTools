# code edited from twisted library github: https://github.com/twisted/teisted/blob/trunk/src/twisted/protocols/ftp.py and   https://github.com/lanjelot/twisted-honeypots/blob/master/python/ftppot.py
# add login and fake interactions
# add comments
# error handling
import time
from zope.interface import Interface, implements
from twisted.application import internet
from twisted.protocols import basic, policies
from twisted.internet import protocol, reactor, defer
from twisted.python import log
from re import match
import logging 


## FTP response codes  
WELCOME_MSG = b'220'
GOODBYE_MSG = b'221'
USER_OK_NEED_PASS = b'331'
UNKNOWN_COMMAND = b'500'
PLEASE_LOGIN = b'530'
LOGIN_WITH_USER_FIRST = b'503'
LOGIN_FAIL = b'503'
REQ_ACTN_NOT_TAKEN = b'550'

RESPONSE = {
    WELCOME_MSG: b'220 %s',
    GOODBYE_MSG: b'221 Goodbye.',
    USER_OK_NEED_PASS: b'331 Please specify the password.',
    PLEASE_LOGIN: b'530 Please login with USER and PASS.',
    UNKNOWN_COMMAND: b'500 Unknown command.',
    LOGIN_WITH_USER_FIRST: b'503 Login with USER first.',
    LOGIN_FAIL: b'503 Login incorrectddddddd.',
    REQ_ACTN_NOT_TAKEN: b'550 Requested action not taken: %s',
}


def add_logger(name, logfile):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(logfile)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

conn_logger = add_logger("Connection attempts", "ftp_connections.log")
interaction_log = add_logger("command", "ftp_interactions.log")
t0 = time.time()


class FTPcalss(basic.LineOnlyReceiver, policies.TimeoutMixin):
    
    UNAUTH, INAUTH = range(2)
    delimiter = b'\n'      
    discconnected = False

    def sendLine(self, msg):
        basic.LineOnlyReceiver.sendLine(self, msg+b'\r')


    def reply(self, key, *args):
        msg = RESPONSE[key] % args
        self.sendLine(msg)
    
    
    # new connections callback
    def connectionMade(self):
        # log connection 
        self.state = self.UNAUTH
        print("connection made")
        print(str(self.transport.getPeer()))
        self.reply(WELCOME_MSG, self.factory.welcomeMessage) # need welcome message


    # connection lost callback
    def connectionLost(self, reason):
        self.setTimeout(None)
        self.transport = None
   
   
    def timeoutConnection(self):
        self.transport.loseConnection()


    def lineReceived(self, line):
        #log the received command
        self.resetTimeout()
        
        def processSucceeded(result):
            if isinstance(result, tuple):
                self.reply(*result)
            elif result is not None:
                self.reply(result)
        
        deferr = defer.maybeDeferred(self.processCommand, line)
        deferr.addCallbacks(processSucceeded)

    # overwite default twisted ftp class functions to only send back responses without any modification 

    def processCommand(self, line):
        cmd, args = match(b'(\S+)\s*(.*)$', line.rstrip()).groups()
        cmd = cmd.upper()
        interaction_log.info(f" host from {str(self.transport.getPeer())} sent command {cmd}")
        if cmd == b'USER':
            if self.state != self.UNAUTH:
                return PLEASE_LOGIN  
            else:
                return self.ftp_USER(args)

        elif cmd == b'PASS':
            if self.state != self.INAUTH:
                return LOGIN_WITH_USER_FIRST
            else:
                return self.ftp_PASS(args)
    
        else:
                method = getattr(self, "ftp_" + cmd.decode("utf8"), None)
                if method is not None:
                    return method(line)
                else:
                    return PLEASE_LOGIN 


    def ftp_USER(self, username):
        self.username = username
        self.state = self.INAUTH
        return USER_OK_NEED_PASS # need password

    def ftp_PASS(self, password):
        conn_logger.info(f" Connection from {str(self.transport.getPeer())} with credintials\t {str(self.username)}:\t{str(password)}")
        self.state = self.UNAUTH
        del self.username
        return LOGIN_FAIL # login fail

    def ftp_QUIT(self, line):
        self.reply(GOODBYE_MSG)
        self.transport.loseConnection()
        self.discconnected = True
'''
    def ftp_STOR(self, path):
        self.sendLine(self,"125 226") 


    def ftp_DELE(self, path):
        self.sendLine(self,"250") 


    def ftp_RNFR(self, fromName):
        self.sendLine(self,"350") 


    def ftp_MKD(self, path):
        self.sendLine(self,"257") 


    def ftp_RNTO(self, toName):
        self.sendLine(self,"250") 


    def ftp_RMD(self, path):
        self.sendLine(self,"250") 
''' 




class potfactory(protocol.ServerFactory):
    protocol = FTPcalss
    welcomeMessage = b'vsFTPd 2.3.4'
    proto = 'ftp'


if __name__=='__main__':

    t = potfactory()
    reactor.listenTCP(2222,t)
    reactor.run()