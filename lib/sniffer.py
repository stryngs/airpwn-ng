# from Queue import Queue, Empty


try:
    from queue import Queue, Empty
except ImportError:
    # Python 2
    from Queue import Queue, Empty



from pyDot11 import *
from lib.visuals import Bcolors
from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff
from threading import Thread
import sys, time

class Sniffer(object):
    """This is the highest level object in the library.

    It uses an instance of PacketHandler as the processing engine
    for packets received from scapy's sniff() function.
    """

    def __init__(self, packethandler, args, *positional_parameters, **keyword_parameters):
        if 'm' in keyword_parameters:
            self.m = keyword_parameters['m']
        else:
            self.m = None

        if self.m is None:
            print ('[ERROR] No monitor interface selected')
            exit()

        self.packethandler = packethandler

        if args.wpa:
            self.shake = Handshake(args.wpa, args.essid, args.pcap)
            self.packethandler.injector.shake = self.shake


    def sniff(self, q):
        """Target function for Queue (multithreading)"""
        sniff(iface = self.m, prn = lambda x: q.put(x), store = 0)


    def handler(self, q, m, pkt, args):
        """This function exists solely to reduce lines of code

        This function has been changed a bit to have the processing,
        moved to within the try: for WPA and WEP
        If errors are seen where pyDot11 fails to process, and
        airpwn-ng starts to hang, move self.packethandler.process()
        out from under the try/except like it previously was
        """

        ### This might need a different structure for self.shake bridge
        ### Multiple vics might collide...
        ## WPA
        if args.wpa:

            ### dict tk and use tgtMAC as key, tk as value
            #tk = self.shake.tgtInfo.get(self.tgtMAC)

            ## eType tagalong via packerhandler.eType when rdy for tkip
            eType = self.shake.encDict.get(self.tgtMAC)

            ### tkip vs ccmp decision pt for now
            if eType == 'ccmp':
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[1]
            else:
                encKey = self.shake.tgtInfo.get(self.tgtMAC)[0]

            ## Decrypt
            try:
                self.packethandler.injector.shake.origPkt = pkt
                pkt,\
                self.packethandler.injector.shake.PN = wpaDecrypt(encKey,
                                                                  pkt,
                                                                  eType,
                                                                  False)
                #print pkt.summary()
            except:
                sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Decryption failed\n ' + Bcolors.ENDC)
                sys.stdout.flush()
                return

        ## WEP
        elif args.wep:

            ## Decrypt
            try:
                pkt, iVal = wepDecrypt(pkt, args.wep, False)
                #print pkt.summary()
            except:
                sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Decryption failed\n ' + Bcolors.ENDC)
                sys.stdout.flush()
                return

        ## Process and finish out the task
        self.packethandler.process(m, pkt, args)
        q.task_done()


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the PacketHandler.process function.
        Call this function to begin actual sniffing + injection.

        If args.b is thrown, a two-way sniff is implemented
        Otherwise airpwn-ng will only look at packets headed outbound
        While airpwn-ng only hijacks inbound frames to begin with,
        -b is useful for grabbing data inbound from a server

        Useful reminder:
            to-DS is:    1L (open) / 65L (crypted)
            from-DS is:  2L (open) /66L (crypted)
        """
        # print('stryngsDEBUG')
        q = Queue()
        sniffer = Thread(target = self.sniff, args = (q,))
        sniffer.daemon = True
        sniffer.start()

        ## Sniffing in Monitor Mode for Open wifi
        if args.mon == 'mon' and not args.wep and not args.wpa:

            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                #print 'BSSID filtering and Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        ### DEBUG
                        # if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1L and len(pkt) >= args.s:
                        if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1 and len(pkt) >= args.s:
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

            ## NO Speedpatch and NO BSSID filtering
            elif args.b and not args.bssid:
                #print 'NO Speedpatch and NO BSSID filtering\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        ### DEBUG
                        # if (pkt[Dot11].FCfield == 1L or pkt[Dot11].FCfield == 2L) and len(pkt) >= args.s:
                        if (pkt[Dot11].FCfield == 1 or pkt[Dot11].FCfield == 2) and len(pkt) >= args.s:
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                #print 'BSSID filtering and NO Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)
                        ### DEBUG
                        # if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1L and len(pkt) >= args.s) or\
                        #     (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 2L and len(pkt) >= args.s):
                        if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 1 and len(pkt) >= args.s) or\
                            (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 2 and len(pkt) >= args.s):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

            ## Speedpatch and NO BSSID filtering
            else:
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        ### DEBUG
                        # if pkt[Dot11].FCfield == 1L and len(pkt) >= args.s:
                        if pkt[Dot11].FCfield == 1 and len(pkt) >= args.s:
                            self.handler(q, self.m, pkt, args)
                    except Empty:
                        #q.task_done()
                        pass

        ## Sniffing in Monitor Mode for WEP
        elif args.mon == 'mon' and args.wep:
            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                #print 'BSSID filtering and Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        ### DEBUG
                        # if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L and len(pkt) >= args.s:
                        if pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= args.s:
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                #print 'BSSID filtering and NO Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        ### DEBUG
                        # if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L and len(pkt) >= args.s) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66L and len(pkt) >= args.s):
                        if (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= args.s) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66 and len(pkt) >= args.s):
                            self.handler(q, self.m, pkt, args)
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

        ## Sniffing in Monitor Mode for WPA
        elif args.mon == 'mon' and args.wpa:

            ## BSSID filtering and Speedpatch
            if args.bssid and not args.b:
                #print 'BSSID filtering and Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)

                        if pkt.haslayer(EAPOL):
                            self.shake.eapolGrab(pkt)

                        ### DEBUG
                        # elif pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L and len(pkt) >= args.s:
                        elif pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= args.s:
                            self.tgtMAC = False

                            ## MAC verification
                            if pkt.addr1 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr1
                            elif pkt.addr2 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr2

                            ## Pass the packet
                            if self.tgtMAC:
                                self.handler(q, self.m, pkt, args)
                            else:
                                pass
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

            ## BSSID filtering and NO Speedpatch
            elif args.bssid and args.b:
                #print 'BSSID filtering and NO Speedpatch\n'
                while True:
                    try:
                        pkt = q.get(timeout = 1)
                        if pkt.haslayer(EAPOL):
                            self.shake.eapolGrab(pkt)

                        ### DEBUG
                        # elif (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65L and len(pkt) >= args.s) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66L and len(pkt) >= args.s):
                        elif (pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65 and len(pkt) >= args.s) or (pkt[Dot11].addr2 == args.bssid and pkt[Dot11].FCfield == 66 and len(pkt) >= args.s):
                            self.tgtMAC = False

                            ## MAC verification
                            if pkt.addr1 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr1
                            elif pkt.addr2 in self.shake.availTgts:
                                self.tgtMAC = pkt.addr2

                            ## Pass the packet
                            if self.tgtMAC:
                                self.handler(q, self.m, pkt, args)
                            else:
                                pass
                        else:
                            pass
                    except Empty:
                        #q.task_done()
                        pass

        ## Sniffing in Tap Mode -- aka Encrypted WiFi
        ## No longer needed!
        ## Left for historical purposes
        #else:
            ### Tap mode
            #print 'Tap mode\n'
            #while True:
                #try:
                    #pkt = q.get(timeout = 1)
                    #self.handler(q, self.m, pkt, args)
                #except Empty:
                    ##q.task_done()
                    #pass
