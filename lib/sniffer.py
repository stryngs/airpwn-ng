from lib.injector import Injector
from Queue import Queue, Empty
from threading import Thread
from scapy.all import *

class Sniffer(object):
    """This is the highest level object in the library.

    It uses an instance of PacketHandler as the processing engine
    for packets received from scapy's sniff() function.
    """

    def __init__(self, packethandler, *positional_parameters, **keyword_parameters):
        if 'filter' in keyword_parameters:
            self.filter = keyword_parameters['filter']
        else:
            self.filter = None

        if 'm' in keyword_parameters:
            self.m = keyword_parameters['m']
        else:
            self.m = None

        if self.m is None:
            print "[ERROR] No monitor interface selected"
            exit()

        if self.filter is None:
            if "mon" not in self.m:
                print "[WARN] SNIFFER: Filter empty for non-monitor interface"

        self.packethandler = packethandler

    ### This should have the option to filter regardless of which NIC we use.
    def sniff(self, q):
        """Target function for Queue (multithreading).
        
        Usually we set a filter for GET requests on the dot11 tap interface.
        It can also be an empty string.
        """
        if 'mon' in self.m:
            sniff(iface = self.m, prn = lambda x: q.put(x), store = 0)
        else:
            sniff(iface = self.m, filter = self.filter, prn = lambda x: q.put(x), store = 0)


    def handler(self, q, m, pkt, args):
        """This function exists solely to reduce lines of code"""
        self.packethandler.process(m, pkt, args)
        q.task_done()


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.
        
        It uses the PacketHandler.process function.
        Call this function to begin actual sniffing + injection.
        
        If args.b is thrown, a two-way sniff is implemented
        Otherwise airpwn-ng will only look at packets headed outbound
        While airpwn-ng only hijacks inbound frames to begin with,
        -b is useful for grabbing any cookies inbound from a server
        
        Useful reminder:        
            to-DS is:    1L (open) / 65L (crypted)
            from-DS is:  2L (open) /66L (crypted)
        """
        ### Play with this later, switch to scapy 2.3.3 required this...
        #q = Queue()
        q = Queue.Queue()
        sniffer = Thread(target = self.sniff, args = (q,))
        sniffer.daemon = True
        sniffer.start()

        ## Deal with only BSSID filtering
        if args.bssid and not args.b:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    if pkt[Dot11].addr3 == args.bssid:
                        self.handler(q, self.m, pkt, args)
                    else:
                        pass
                except Empty:
                    #q.task_done()
                    pass

        ## Deal with only no speedpatch
        elif args.b and not args.bssid:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    if pkt[Dot11].FCfield == 1L:
                        self.handler(q, self.m, pkt, args)
                    else:
                        pass
                except Empty:
                    #q.task_done()
                    pass

        ## Deal with BSSID filtering and no speedpatch
        elif args.bssid and args.b:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    if pkt[Dot11].addr3 == args.bssid and pkt[Dot11].FCfield == 1L:
                        self.handler(q, self.m, pkt, args)
                    else:
                        pass
                except Empty:
                    #q.task_done()
                    pass

        ## Deal with anything else
        else:
            while True:
                try:
                    pkt = q.get(timeout = 1)
                    self.handler(q, self.m, pkt, args)
                except Empty:
                    #q.task_done()
                    pass
